import asyncio
import aiohttp
import base64
import os
import argparse
import logging
import dataclasses
import json
import re
from typing import List, Optional, Tuple, Dict, Set, Type
from tqdm import tqdm
from urllib.parse import urlparse, parse_qs, unquote
from functools import lru_cache
from abc import ABC, abstractmethod

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

def parse_args() -> argparse.Namespace:
    """解析命令行参数。"""
    parser = argparse.ArgumentParser(description='提取订阅节点并输出') # 描述已更新
    parser.add_argument('--input', default='sub/sub_all_url_check.txt', help='订阅文件路径')
    # 移除了 --output_prefix 和 --chunk_size 参数
    parser.add_argument('--output', default='output/all_nodes.txt', help='输出节点文件的路径') # 新增输出文件路径参数
    parser.add_argument(
        '--strict_dedup',
        action='store_true',
        default=True,
        help='启用严格去重模式（考虑 network 和 security_method 字段）'
    )
    return parser.parse_args()

def is_valid_url(url: str) -> bool:
    """检查给定的字符串是否是有效的 URL。"""
    try:
        result = urlparse(url)
        return all([result.scheme in ['http', 'https'], result.netloc])
    except ValueError:
        return False

def normalize_server(server: str) -> str:
    """规范化服务器地址（小写，移除无效字符）。"""
    return re.sub(r'[^a-zA-Z0-9.-:[\]]', '', server.lower())

def normalize_ipv6_url(url: str) -> str:
    """规范化 IPv6 URL，确保地址正确括在方括号中。"""
    try:
        parsed = urlparse(url)
        if ':' in parsed.netloc and not parsed.netloc.startswith('['):
            # 提取主机和端口
            netloc = parsed.netloc
            user_info = ''
            if '@' in netloc:
                user_info, netloc = netloc.split('@', 1)
            host, port = netloc, ''
            if ':' in netloc and not netloc.endswith(']'):
                host, port = netloc.rsplit(':', 1)
            if ':' in host and not host.startswith('['):
                host = f'[{host}]'
            new_netloc = f'{user_info}@{host}' if user_info else host
            if port:
                new_netloc += f':{port}'
            # 重构 URL
            return parsed._replace(netloc=new_netloc).geturl()
        return url
    except Exception:
        return url

def read_subscriptions(file_path: str) -> List[str]:
    """从文件中读取订阅 URL 列表。"""
    if not os.path.exists(file_path):
        logger.warning(f'未找到 {file_path} 文件，跳过生成步骤。')
        return []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return [url.strip() for url in f.readlines() if url.strip()]
    except Exception as e:
        logger.error(f'读取文件 {file_path} 失败: {e}')
        return []

# 修改后的写入函数，不再分片
def write_all_nodes(nodes: List[str], output_file_path: str) -> None:
    """将所有节点写入单个文件。"""
    if not nodes:
        logger.info("没有节点可写入。")
        return

    output_dir = os.path.dirname(output_file_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
        logger.info(f"已创建输出目录: {os.path.abspath(output_dir)}")

    try:
        with open(output_file_path, 'w', encoding='utf-8') as f:
            for node in nodes:
                f.write(f'{node}\n')
        logger.info(f'所有 {len(nodes)} 条节点信息已写入到：{os.path.abspath(output_file_path)}')
    except IOError as e:
        logger.error(f"写入文件 {output_file_path} 失败: {e}")

@dataclasses.dataclass(frozen=True)
class ParsedNodeInfo:
    """标准化解析后的节点信息，用于语义去重。"""
    protocol: str
    server: str
    port: int
    original_url: str = dataclasses.field(compare=False, hash=False)
    identifier: Optional[str] = None
    security_method: Optional[str] = None
    network: Optional[str] = None

class NodeParser(ABC):
    """抽象基类，定义节点解析接口。"""
    @abstractmethod
    def parse(self, node_url: str) -> Optional[ParsedNodeInfo]:
        pass

    @staticmethod
    @lru_cache(maxsize=1000)
    def decode_base64(encoded: str) -> Optional[str]:
        """缓存 Base64 解码结果以提升性能。"""
        try:
            return base64.b64decode(encoded + '==' * (-len(encoded) % 4)).decode('utf-8', errors='ignore')
        except Exception:
            return None

class SSNodeParser(NodeParser):
    def parse(self, node_url: str) -> Optional[ParsedNodeInfo]:
        try:
            node_url = normalize_ipv6_url(node_url)
            parsed = urlparse(node_url)
            if not parsed.scheme.startswith('ss'):
                return None

            user_info, netloc = '', parsed.netloc
            if '@' in parsed.netloc:
                user_info, netloc = parsed.netloc.split('@', 1)

            server, port = netloc.split(':') if ':' in netloc else (netloc, None)
            port = int(port) if port else 443
            server = normalize_server(server)

            method, password = None, None
            if user_info:
                decoded_user_info = self.decode_base64(user_info)
                if decoded_user_info and ':' in decoded_user_info:
                    method, password = decoded_user_info.split(':', 1)
                else:
                    password = user_info

            if not (server and port):
                return None

            return ParsedNodeInfo(
                protocol='ss',
                server=server,
                port=port,
                original_url=node_url,
                identifier=password,
                security_method=method
            )
        except Exception as e:
            logger.debug(f"解析 SS 节点 {node_url} 失败: {e}")
            return None

class SSRNodeParser(NodeParser):
    def parse(self, node_url: str) -> Optional[ParsedNodeInfo]:
        try:
            encoded_part = node_url[len('ssr://'):]
            decoded = self.decode_base64(encoded_part.replace('-', '+').replace('_', '/'))
            if not decoded:
                return None

            parts = decoded.split(':')
            if len(parts) < 6:
                return None

            server = normalize_server(parts[0])
            port = int(parts[1])
            method = parts[3]
            password = parts[5].split('/')[0]

            if not (server and port):
                return None

            return ParsedNodeInfo(
                protocol='ssr',
                server=server,
                port=port,
                original_url=node_url,
                identifier=password,
                security_method=method
            )
        except Exception as e:
            logger.debug(f"解析 SSR 节点 {node_url} 失败: {e}")
            return None

class VMessNodeParser(NodeParser):
    @lru_cache(maxsize=1000)
    def _parse_json(self, encoded_json: str) -> Optional[Dict]:
        """缓存 JSON 解析结果以提升性能。"""
        try:
            decoded_json = self.decode_base64(encoded_json)
            return json.loads(decoded_json) if decoded_json else None
        except Exception:
            return None

    def parse(self, node_url: str) -> Optional[ParsedNodeInfo]:
        try:
            encoded_json = node_url[len('vmess://'):]
            node_data = self._parse_json(encoded_json)
            if not node_data:
                return None

            server = normalize_server(node_data.get('add', ''))
            port = int(node_data.get('port', 0))
            uuid = node_data.get('id')
            security = node_data.get('scy') or node_data.get('security')
            network = node_data.get('net')

            if not (server and port and uuid):
                return None

            return ParsedNodeInfo(
                protocol='vmess',
                server=server,
                port=port,
                original_url=node_url,
                identifier=uuid,
                security_method=security,
                network=network
            )
        except Exception as e:
            logger.debug(f"解析 VMess 节点 {node_url} 失败: {e}")
            return None

class VlessTrojanNodeParser(NodeParser):
    def parse(self, node_url: str) -> Optional[ParsedNodeInfo]:
        try:
            node_url = normalize_ipv6_url(node_url)
            parsed = urlparse(node_url)
            protocol = parsed.scheme
            if protocol not in ['vless', 'trojan']:
                return None

            server = normalize_server(parsed.hostname or '')
            port = parsed.port or 443
            identifier = unquote(parsed.username or '')

            query_params = parse_qs(parsed.query)
            security = query_params.get('security', [None])[0]
            network = query_params.get('type', [None])[0]

            if not (server and port and identifier):
                return None

            return ParsedNodeInfo(
                protocol=protocol,
                server=server,
                port=port,
                original_url=node_url,
                identifier=identifier,
                security_method=security,
                network=network
            )
        except ValueError as e:
            logger.debug(f"解析 Vless/Trojan 节点 {node_url} 失败 (无效 URL): {e}")
            return None
        except Exception as e:
            logger.debug(f"解析 Vless/Trojan 节点 {node_url} 失败: {e}")
            return None

class HysteriaNodeParser(NodeParser):
    def parse(self, node_url: str) -> Optional[ParsedNodeInfo]:
        try:
            node_url = normalize_ipv6_url(node_url)
            parsed = urlparse(node_url)
            protocol = parsed.scheme
            if protocol not in ['hysteria', 'hy', 'hy2']:
                return None

            server = normalize_server(parsed.hostname or '')
            port = parsed.port
            if port is None:
                host_port = parsed.netloc.split('?')[0]
                server, port_str = host_port.split(':') if ':' in host_port else (host_port, '443')
                server = normalize_server(server)
                port = int(port_str)

            query_params = parse_qs(parsed.query)
            auth = query_params.get('auth', [None])[0]
            password = query_params.get('password', [None])[0]
            identifier = auth or password

            if not (server and port):
                return None

            return ParsedNodeInfo(
                protocol=protocol,
                server=server,
                port=port,
                original_url=node_url,
                identifier=identifier
            )
        except Exception as e:
            logger.debug(f"解析 Hysteria 节点 {node_url} 失败: {e}")
            return None

def get_parsers() -> List[Type[NodeParser]]:
    """返回所有支持的节点解析器。"""
    return [
        SSNodeParser,
        SSRNodeParser,
        VMessNodeParser,
        VlessTrojanNodeParser,
        HysteriaNodeParser
    ]

def extract_nodes(text: str, strict_dedup: bool = True) -> Tuple[List[str], Dict[str, int]]:
    """
    从文本中提取有效节点，并进行语义去重。
    返回去重后的节点列表和统计信息。
    """
    valid_node_prefixes = ['ss://', 'ssr://', 'vmess://', 'vless://', 'trojan://', 'hysteria://', 'hy://', 'hy2://']
    
    try:
        decoded_text = base64.b64decode(text + '==' * (-len(text) % 4)).decode('utf-8', errors='ignore')
        lines = decoded_text.split('\n')
    except Exception:
        lines = text.split('\n')

    parsed_nodes: List[ParsedNodeInfo] = []
    stats = {'total': 0, 'failed': 0, 'by_protocol': {}}
    
    parsers = [parser() for parser in get_parsers()]
    for line in lines:
        line = line.strip()
        if not any(line.startswith(prefix) for prefix in valid_node_prefixes):
            continue

        stats['total'] += 1
        parsed_node = None
        for parser in parsers:
            parsed_node = parser.parse(line)
            if parsed_node:
                parsed_nodes.append(parsed_node)
                stats['by_protocol'][parsed_node.protocol] = stats['by_protocol'].get(parsed_node.protocol, 0) + 1
                break
        if not parsed_node:
            stats['failed'] += 1

    deduplicated_nodes: List[ParsedNodeInfo] = []
    seen_keys: Set[Tuple] = set()

    for node in parsed_nodes:
        key_tuple = (
            node.protocol,
            node.server,
            node.port,
            node.identifier or '',
            node.security_method or '' if strict_dedup else '',
            node.network or '' if strict_dedup else ''
        )
        normalized_key = tuple(str(x).lower() for x in key_tuple)
        if normalized_key not in seen_keys:
            seen_keys.add(normalized_key)
            deduplicated_nodes.append(node)

    final_nodes = [node.original_url for node in deduplicated_nodes]
    stats['unique'] = len(final_nodes)
    
    return final_nodes, stats

async def fetch_url(url: str, session: aiohttp.ClientSession, timeout: int = 10) -> Optional[str]:
    """异步获取单个 URL 的内容。"""
    try:
        async with session.get(url, timeout=timeout) as response:
            if response.status == 200:
                return await response.text()
            else:
                logger.error(f'获取 {url} 失败: 状态码 {response.status}')
                return None
    except Exception as e:
        logger.error(f'获取 {url} 失败: {e}')
        return None

async def fetch_all_urls(urls: List[str], max_concurrent: int = 10) -> List[Optional[str]]:
    """异步并发获取所有 URL 的内容。"""
    results = []
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def sem_fetch(url: str, session: aiohttp.ClientSession) -> Optional[str]:
        async with semaphore:
            return await fetch_url(url, session)
            
    async with aiohttp.ClientSession() as session:
        tasks = [sem_fetch(url, session) for url in urls]
        for coro in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc='处理订阅 URL', leave=False):
            result = await coro
            results.append(result)
    return results

def main():
    """主函数，执行订阅节点提取和输出的整个流程。""" # 描述已更新
    args = parse_args()
    
    subscriptions = read_subscriptions(args.input)
    if not subscriptions:
        return
        
    valid_urls = [url for url in subscriptions if is_valid_url(url)]
    if not valid_urls:
        logger.info("未找到有效的订阅 URL。")
        return

    contents = asyncio.run(fetch_all_urls(valid_urls))
    
    all_nodes = []
    total_stats = {'total': 0, 'failed': 0, 'unique': 0, 'by_protocol': {}}
    
    for content in contents:
        if content:
            nodes, stats = extract_nodes(content, args.strict_dedup)
            all_nodes.extend(nodes)
            total_stats['total'] += stats['total']
            total_stats['failed'] += stats['failed']
            total_stats['unique'] += stats['unique']
            for protocol, count in stats['by_protocol'].items():
                total_stats['by_protocol'][protocol] = total_stats['by_protocol'].get(protocol, 0) + count
    
    all_nodes = list(set(all_nodes)) # 最终字符串级别去重
    total_stats['unique'] = len(all_nodes)

    logger.info("\n=== 节点处理统计 ===")
    logger.info(f"总节点数: {total_stats['total']}")
    logger.info(f"解析失败数: {total_stats['failed']}")
    logger.info(f"去重后节点数: {total_stats['unique']}")
    logger.info("按协议分布:")
    for protocol, count in total_stats['by_protocol'].items():
        logger.info(f"  {protocol}: {count}")

    # 调用修改后的写入函数
    write_all_nodes(all_nodes, args.output)
    output_directory = os.path.dirname(args.output) or "." # 获取输出文件所在的目录
    logger.info(f"\n所有生成的节点文件已保存到目录: {os.path.abspath(output_directory)}")


if __name__ == '__main__':
    main()
