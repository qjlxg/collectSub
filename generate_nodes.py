import asyncio
import aiohttp
import base64
import os
import argparse
import logging
import json
from typing import List, Optional, Dict
from tqdm import tqdm
from urllib.parse import urlparse, parse_qs, urlencode
import re

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def parse_args() -> argparse.Namespace:
    """解析命令行参数。"""
    parser = argparse.ArgumentParser(description='提取订阅节点并分批输出')
    parser.add_argument('--input', default='sub/sub_all_url_check.txt', help='订阅文件路径')
    parser.add_argument('--output_prefix', default='output/all_nodes', help='输出节点文件的前缀')
    parser.add_argument('--chunk_size', type=int, default=500, help='每个输出文件的节点数量')
    return parser.parse_args()

def is_valid_url(url: str) -> bool:
    """检查给定的字符串是否是有效的 URL。"""
    try:
        result = urlparse(url)
        return all([result.scheme in ['http', 'https'], result.netloc])
    except ValueError:
        return False

def normalize_node(node: str) -> Dict:
    """规范化节点信息，提取关键字段用于去重"""
    try:
        # 支持的协议类型
        valid_node_prefixes = ['ss://', 'ssr://', 'vmess://', 'vless://', 'trojan://', 'hysteria://', 'hy://', 'hy2://']
        protocol = next((prefix for prefix in valid_node_prefixes if node.startswith(prefix)), None)
        
        if not protocol:
            return {}

        # 提取协议和内容
        content = node[len(protocol):]
        
        if protocol in ['ss://', 'ssr://']:
            # Shadowsocks/ShadowsocksR
            try:
                # 处理 Base64 编码
                if '@' in content:
                    auth, server_info = content.split('@', 1)
                    decoded_auth = base64.b64decode(auth + '==' * (-len(auth) % 4)).decode('utf-8', errors='ignore')
                    method, password = decoded_auth.split(':', 1)
                    server, rest = server_info.split(':', 1)
                    port = rest.split('#')[0].split('?')[0]
                    return {
                        'protocol': protocol,
                        'server': server.lower(),
                        'port': port,
                        'method': method,
                        'password': password
                    }
            except Exception:
                return {'raw': node}
                
        elif protocol == 'vmess://':
            # VMess
            try:
                decoded = base64.b64decode(content + '==' * (-len(content) % 4)).decode('utf-8')
                vmess_data = json.loads(decoded)
                return {
                    'protocol': protocol,
                    'server': vmess_data.get('add', '').lower(),
                    'port': str(vmess_data.get('port', '')),
                    'id': vmess_data.get('id', ''),
                    'type': vmess_data.get('net', '')
                }
            except Exception:
                return {'raw': node}
                
        elif protocol in ['vless://', 'trojan://']:
            # VLESS/Trojan
            try:
                user_id, rest = content.split('@', 1)
                server, rest = rest.split(':', 1)
                port = rest.split('?')[0].split('#')[0]
                params = parse_qs(urlparse(node).query)
                return {
                    'protocol': protocol,
                    'server': server.lower(),
                    'port': port,
                    'user_id': user_id,
                    'type': params.get('type', [''])[0]
                }
            except Exception:
                return {'raw': node}
                
        elif protocol in ['hysteria://', 'hy://', 'hy2://']:
            # Hysteria
            try:
                server, rest = content.split(':', 1)
                port = rest.split('?')[0].split('#')[0]
                params = parse_qs(urlparse(node).query)
                return {
                    'protocol': protocol,
                    'server': server.lower(),
                    'port': port,
                    'auth': params.get('auth', [''])[0]
                }
            except Exception:
                return {'raw': node}
                
        return {'raw': node}
    except Exception:
        return {'raw': node}

def node_to_key(node_dict: Dict) -> str:
    """将规范化后的节点信息转换为用于去重的键"""
    if 'raw' in node_dict:
        return node_dict['raw']
    
    # 根据协议类型生成唯一键
    if node_dict['protocol'] in ['ss://', 'ssr://']:
        return f"{node_dict['protocol']}{node_dict['server']}:{node_dict['port']}:{node_dict['method']}:{node_dict['password']}"
    elif node_dict['protocol'] == 'vmess://':
        return f"{node_dict['protocol']}{node_dict['server']}:{node_dict['port']}:{node_dict['id']}:{node_dict['type']}"
    elif node_dict['protocol'] in ['vless://', 'trojan://']:
        return f"{node_dict['protocol']}{node_dict['server']}:{node_dict['port']}:{node_dict['user_id']}:{node_dict['type']}"
    elif node_dict['protocol'] in ['hysteria://', 'hy://', 'hy2://']:
        return f"{node_dict['protocol']}{node_dict['server']}:{node_dict['port']}:{node_dict['auth']}"
    return node_dict.get('raw', '')

def read_subscriptions(file_path: str) -> List[str]:
    """从文件中读取订阅 URL 列表。"""
    if not os.path.exists(file_path):
        print(f'未找到 {file_path} 文件，跳过生成步骤。')
        return []
    with open(file_path, 'r', encoding='utf-8') as f:
        return [url.strip() for url in f.readlines() if url.strip()]

def write_nodes_in_chunks(nodes: List[str], output_prefix: str, chunk_size: int) -> None:
    """
    将节点列表分批写入多个文件。
    每批次的节点数量由 chunk_size 决定。
    """
    if not nodes:
        print("没有节点可写入。")
        return

    output_dir = os.path.dirname(output_prefix)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"已创建输出目录: {os.path.abspath(output_dir)}")

    total_chunks = (len(nodes) + chunk_size - 1) // chunk_size
    print(f"总共有 {len(nodes)} 个节点，将分 {total_chunks} 个文件输出 (每文件 {chunk_size} 个节点)。")

    for i in range(total_chunks):
        start_index = i * chunk_size
        end_index = min((i + 1) * chunk_size, len(nodes))
        chunk = nodes[start_index:end_index]
        file_name = f"{output_prefix}_{i+1:03d}.txt"
        
        try:
            with open(file_name, 'w', encoding='utf-8') as f:
                for node in chunk:
                    f.write(f'{node}\n')
            print(f'节点信息已写入到：{os.path.abspath(file_name)} (包含 {len(chunk)} 条节点)')
        except IOError as e:
            logger.error(f"写入文件 {file_name} 失败: {e}")
            print(f"写入文件 {file_name} 失败，请检查目录权限或路径。")

def extract_nodes(text: str) -> List[str]:
    """
    从给定的文本中提取有效节点。
    尝试进行 base64 解码，如果失败则直接处理。
    """
    valid_node_prefixes = ['ss://', 'ssr://', 'vmess://', 'vless://', 'trojan://', 'hysteria://', 'hy://', 'hy2://']
    nodes = []
    try:
        decoded_text = base64.b64decode(text + '==' * (-len(text) % 4)).decode('utf-8', errors='ignore')
        lines = decoded_text.split('\n')
    except Exception:
        lines = text.split('\n')
        
    for line in lines:
        line = line.strip()
        for prefix in valid_node_prefixes:
            if line.startswith(prefix) and len(line) > len(prefix) + 10:
                nodes.append(line)
                break
    
    # 去重：先规范化节点，再基于关键字段去重
    normalized_nodes = [normalize_node(node) for node in nodes]
    seen_keys = set()
    unique_nodes = []
    
    for node, norm_node in zip(nodes, normalized_nodes):
        key = node_to_key(norm_node)
        if key not in seen_keys:
            seen_keys.add(key)
            unique_nodes.append(node)
    
    print(f"原始节点数: {len(nodes)}, 去重后节点数: {len(unique_nodes)}")
    return unique_nodes

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
        for coro in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc='处理订阅 URL'):
            result = await coro
            results.append(result)
    return results

def main():
    """主函数，执行订阅节点提取和分批输出的整个流程。"""
    args = parse_args()
    
    subscriptions = read_subscriptions(args.input)
    if not subscriptions:
        return
        
    valid_urls = [url for url in subscriptions if is_valid_url(url)]
    if not valid_urls:
        print("未找到有效的订阅 URL。")
        return

    contents = asyncio.run(fetch_all_urls(valid_urls))
    
    all_nodes = []
    for content in contents:
        if content:
            nodes = extract_nodes(content)
            all_nodes.extend(nodes)
    
    all_nodes = list(set(all_nodes))  # 额外一层字符串级别的去重
    print(f"成功提取到 {len(all_nodes)} 个不重复的节点。")

    write_nodes_in_chunks(all_nodes, args.output_prefix, args.chunk_size)
    output_directory = os.path.dirname(args.output_prefix) if os.path.dirname(args.output_prefix) else "."
    print(f"\n所有生成的节点文件已保存到目录: {os.path.abspath(output_directory)}")

if __name__ == '__main__':
    main()
