import asyncio
import aiohttp
import base64
import os
import argparse
import logging
import dataclasses # 新增：用于创建数据类
import json # 新增：用于解析 VMess 节点的 JSON 数据
from typing import List, Optional, Tuple, Dict, Any
from tqdm import tqdm
from urllib.parse import urlparse, parse_qs, unquote # unquote 可能会用于解码 URL 组件

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def parse_args() -> argparse.Namespace:
    """解析命令行参数。"""
    parser = argparse.ArgumentParser(description='提取订阅节点并分批输出')
    # 更改默认输出前缀，使其指向一个名为 'output' 的子目录
    parser.add_argument('--input', default='sub/sub_all_url_check.txt', help='订阅文件路径')
    parser.add_argument('--output_prefix', default='output/all_nodes', help='输出节点文件的前缀 (例如: output/all_nodes_001.txt, output/all_nodes_002.txt)')
    parser.add_argument('--chunk_size', type=int, default=300, help='每个输出文件的节点数量')
    return parser.parse_args()

def is_valid_url(url: str) -> bool:
    """检查给定的字符串是否是有效的 URL。"""
    try:
        result = urlparse(url)
        return all([result.scheme in ['http', 'https'], result.netloc])
    except ValueError:
        return False

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
    文件命名格式为 output_prefix_XXX.txt (例如: all_nodes_001.txt)。
    """
    if not nodes:
        print("没有节点可写入。")
        return

    # 提取输出文件所在的目录路径
    output_dir = os.path.dirname(output_prefix)
    # 如果指定了目录（即 output_prefix 包含了路径信息），且该目录不存在，则创建它
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"已创建输出目录: {os.path.abspath(output_dir)}") # 打印创建的目录的绝对路径

    total_chunks = (len(nodes) + chunk_size - 1) // chunk_size
    print(f"总共有 {len(nodes)} 个节点，将分 {total_chunks} 个文件输出 (每文件 {chunk_size} 个节点)。")

    for i in range(total_chunks):
        start_index = i * chunk_size
        end_index = min((i + 1) * chunk_size, len(nodes))
        chunk = nodes[start_index:end_index]

        # 构造完整的文件名，包括前缀和序号
        file_name = f"{output_prefix}_{i+1:03d}.txt"
        
        try:
            with open(file_name, 'w', encoding='utf-8') as f:
                for node in chunk:
                    f.write(f'{node}\n')
            print(f'节点信息已写入到：{os.path.abspath(file_name)} (包含 {len(chunk)} 条节点)')
        except IOError as e:
            logger.error(f"写入文件 {file_name} 失败: {e}")
            print(f"写入文件 {file_name} 失败，请检查目录权限或路径。")

# --- 新增和修改的代码部分，用于更智能的去重 ---

@dataclasses.dataclass(frozen=True) # 使用 frozen=True 使其可哈希，用于集合去重
class ParsedNodeInfo:
    """
    标准化解析后的节点信息，用于语义去重。
    只有参与比较和哈希的字段才会被用于去重。
    """
    protocol: str
    server: str
    port: int
    # 主要标识符，可能是 UUID (vmess/vless/trojan) 或密码 (ss)
    identifier: Optional[str] = None
    # 加密方法 (SS/SSR) 或安全类型 (Vmess/Vless)
    security_method: Optional[str] = None
    # 对于 Vmess/Vless, 网络类型 (tcp, ws, grpc等)
    network: Optional[str] = None
    # 原始的完整 URL，不参与去重比较，但去重后需要返回它
    original_url: str = dataclasses.field(compare=False, hash=False)

def _parse_ss_node(node_url: str) -> Optional[ParsedNodeInfo]:
    """解析 SS 协议的节点 URL。"""
    try:
        parsed = urlparse(node_url)
        if not parsed.scheme.startswith('ss'):
            return None

        user_info, netloc_part = '', parsed.netloc
        if '@' in parsed.netloc:
            user_info, netloc_part = parsed.netloc.split('@', 1)

        server_port_parts = netloc_part.split(':')
        server = server_port_parts[0]
        port = int(server_port_parts[1]) if len(server_port_parts) > 1 else None
        
        method = None
        password = None
        if user_info:
            if ':' in user_info:
                method, password = user_info.split(':', 1)
            else: # 某些旧客户端可能只有 base64(password)
                password = user_info
        
        if not (server and port):
            return None

        return ParsedNodeInfo(
            protocol='ss',
            server=server,
            port=port,
            identifier=password, # 使用密码作为标识符
            security_method=method, # 使用加密方法
            original_url=node_url
        )
    except Exception as e:
        logger.debug(f"解析 SS 节点 {node_url} 失败: {e}")
        return None

def _parse_ssr_node(node_url: str) -> Optional[ParsedNodeInfo]:
    """解析 SSR 协议的节点 URL。"""
    try:
        # SSR 格式复杂，通常需要对 base64 部分进行解码。
        # base64 编码的 SSR 链接可能包含 '-' 和 '_'，需要替换回 '+' 和 '/'
        encoded_part = node_url[len('ssr://'):]
        decoded_str = base64.b64decode(encoded_part.replace('-', '+').replace('_', '/')).decode('utf-8', errors='ignore')

        # SSR 内部格式大致为 server:port:protocol:method:obfsparam:password/?obfs=...&protocol=...#remark
        parts = decoded_str.split(':')
        if len(parts) < 6: # 至少需要包含 server, port, protocol, method, obfsparam, password
            return None

        server = parts[0]
        port = int(parts[1])
        # protocol = parts[2] # SSR 自身的协议类型，如 origin, verify_sha1
        method = parts[3]
        password = parts[5].split('/')[0] # 密码通常在 /? 或 # 之前

        if not (server and port):
            return None

        return ParsedNodeInfo(
            protocol='ssr',
            server=server,
            port=port,
            identifier=password,
            security_method=method,
            original_url=node_url
        )
    except Exception as e:
        logger.debug(f"解析 SSR 节点 {node_url} 失败: {e}")
        return None

def _parse_vmess_node(node_url: str) -> Optional[ParsedNodeInfo]:
    """解析 VMess 协议的节点 URL。"""
    try:
        # VMess 格式: vmess://base64(json)
        encoded_json = node_url[len('vmess://'):]
        decoded_json_str = base64.b64decode(encoded_json).decode('utf-8')
        node_data = json.loads(decoded_json_str)

        server = node_data.get('add')
        port = int(node_data.get('port'))
        uuid = node_data.get('id')
        security = node_data.get('scy') or node_data.get('security') # 'scy' 是常见的别名
        network = node_data.get('net')

        if not (server and port and uuid):
            return None

        return ParsedNodeInfo(
            protocol='vmess',
            server=server,
            port=port,
            identifier=uuid, # UUID 作为标识符
            security_method=security,
            network=network,
            original_url=node_url
        )
    except Exception as e:
        logger.debug(f"解析 VMess 节点 {node_url} 失败: {e}")
        return None

def _parse_vless_trojan_node(node_url: str) -> Optional[ParsedNodeInfo]:
    """解析 VLESS 或 Trojan 协议的节点 URL。"""
    try:
        parsed = urlparse(node_url)
        protocol = parsed.scheme # vless 或 trojan

        server = parsed.hostname
        port = parsed.port
        identifier = parsed.username # 对于 Trojan 是密码，对于 VLESS 是 UUID

        query_params = parse_qs(parsed.query)
        security = query_params.get('security', [None])[0] # TLS 安全类型 (tls, reality, none)
        network = query_params.get('type', [None])[0] # 网络类型 (tcp, ws, grpc)

        if not (server and port and identifier):
            return None

        return ParsedNodeInfo(
            protocol=protocol,
            server=server,
            port=port,
            identifier=identifier,
            security_method=security,
            network=network,
            original_url=node_url
        )
    except Exception as e:
        logger.debug(f"解析 {protocol} 节点 {node_url} 失败: {e}")
        return None

def _parse_hysteria_node(node_url: str) -> Optional[ParsedNodeInfo]:
    """解析 Hysteria/Hy2 协议的节点 URL。"""
    try:
        parsed = urlparse(node_url)
        protocol = parsed.scheme

        server = parsed.hostname
        port_str = parsed.port # 直接获取端口，可能是 None
        
        if port_str is None: # 如果 URL 中没有明确指定端口
            # 尝试从 netloc 部分解析 'host:port'
            host_port_part = parsed.netloc.split('?')[0] # 移除查询参数
            if ':' in host_port_part:
                server, port_str = host_port_part.split(':', 1)
                port = int(port_str)
            else: # 只有主机名，没有端口，使用默认值
                port = 443 
        else: # 端口已明确指定
            port = int(port_str)

        query_params = parse_qs(parsed.query)
        auth_str = query_params.get('auth', [None])[0] # Hysteria V1 认证字符串
        password = query_params.get('password', [None])[0] # Hysteria V2 密码

        identifier = auth_str or password # 哪个存在就用哪个作为标识符

        if not (server and port):
            return None
        
        return ParsedNodeInfo(
            protocol=protocol,
            server=server,
            port=port,
            identifier=identifier, # 使用认证字符串或密码作为标识符
            original_url=node_url
        )
    except Exception as e:
        logger.debug(f"解析 {protocol} 节点 {node_url} 失败: {e}")
        return None


def extract_nodes(text: str) -> List[str]:
    """
    从给定的文本中提取有效节点，并进行语义去重。
    """
    # 定义所有支持的节点协议前缀
    valid_node_prefixes = ['ss://', 'ssr://', 'vmess://', 'vless://', 'trojan://', 'hysteria://', 'hy://', 'hy2://']
    
    try:
        # 尝试 base64 解码整个订阅内容
        decoded_text = base64.b64decode(text).decode('utf-8', errors='ignore')
        lines = decoded_text.split('\n')
    except Exception:
        # 如果解码失败（可能不是 base64 编码），则直接按行分割文本
        lines = text.split('\n')
    
    parsed_nodes: List[ParsedNodeInfo] = [] # 用于存储所有解析后的节点信息
    
    for line in lines:
        line = line.strip()
        parsed_node = None
        
        # 根据节点 URL 的前缀，调用相应的解析函数
        if line.startswith('ss://'):
            parsed_node = _parse_ss_node(line)
        elif line.startswith('ssr://'):
            parsed_node = _parse_ssr_node(line)
        elif line.startswith('vmess://'):
            parsed_node = _parse_vmess_node(line)
        elif line.startswith('vless://') or line.startswith('trojan://'):
            parsed_node = _parse_vless_trojan_node(line)
        elif line.startswith('hysteria://') or line.startswith('hy://') or line.startswith('hy2://'):
            parsed_node = _parse_hysteria_node(line)
        
        if parsed_node:
            parsed_nodes.append(parsed_node)
            
    # --- 语义去重逻辑 ---
    deduplicated_parsed_nodes = [] # 存储去重后的 ParsedNodeInfo 对象
    seen_keys = set() # 存储用于判断重复的关键信息元组

    for node in parsed_nodes:
        # 构建用于去重的关键信息元组。
        # 关键字段包括：协议、服务器、端口、主要标识符、安全/加密方法、网络类型。
        key_tuple = (
            node.protocol,
            node.server,
            node.port,
            node.identifier,
            node.security_method,
            node.network
        )
        # 将元组中的所有 None 值转换为一个固定的可哈希值（例如空字符串），
        # 并且将所有字符串转换为小写，以实现更鲁棒的去重（忽略大小写和 None 差异）
        normalized_key_tuple = tuple(str(x).lower() if x is not None else '' for x in key_tuple)

        if normalized_key_tuple not in seen_keys:
            seen_keys.add(normalized_key_tuple)
            deduplicated_parsed_nodes.append(node) # 保留第一个遇到的节点对象

    # 从去重后的 ParsedNodeInfo 对象中提取它们的原始 URL 字符串
    final_nodes_urls = [node.original_url for node in deduplicated_parsed_nodes]

    return final_nodes_urls

# --- 现有代码保持不变 ---

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
    semaphore = asyncio.Semaphore(max_concurrent) # 控制并发数量
    
    async def sem_fetch(url: str, session: aiohttp.ClientSession) -> Optional[str]:
        async with semaphore:
            return await fetch_url(url, session)
            
    async with aiohttp.ClientSession() as session:
        tasks = [sem_fetch(url, session) for url in urls]
        # 使用 tqdm 显示进度条
        for coro in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc='处理订阅 URL'):
            result = await coro
            results.append(result)
    return results

def main():
    """主函数，执行订阅节点提取和分批输出的整个流程。"""
    args = parse_args()
    
    # 1. 读取订阅 URL
    subscriptions = read_subscriptions(args.input)
    if not subscriptions:
        return
        
    # 2. 过滤有效 URL 并并发获取内容
    valid_urls = [url for url in subscriptions if is_valid_url(url)]
    if not valid_urls:
        print("未找到有效的订阅 URL。")
        return

    contents = asyncio.run(fetch_all_urls(valid_urls))
    
    # 3. 提取所有节点并进行全局语义去重 (已在 extract_nodes 内部完成)
    all_nodes = []
    for content in contents:
        if content:
            # extract_nodes 现在会返回语义去重后的节点列表
            nodes = extract_nodes(content)
            all_nodes.extend(nodes)
    
    # 确保最终列表没有因为不同订阅源的细微差异而重复的节点（尽管 extract_nodes 已经做了很强的去重）
    # 这一步是额外的保障，但由于 extract_nodes 已经执行了语义去重，这里的去重效果会比较小。
    # 我们可以通过创建一个临时的 set 来快速检查是否有意外的完全重复的原始 URL。
    all_nodes = list(set(all_nodes)) # 再次执行基于字符串的最终去重，确保万无一失
    print(f"成功提取到并去重后得到 {len(all_nodes)} 个不重复的节点。")

    # 4. 将节点分批写入文件
    write_nodes_in_chunks(all_nodes, args.output_prefix, args.chunk_size)

    # 打印最终文件存储位置的提示
    output_directory = os.path.dirname(args.output_prefix) if os.path.dirname(args.output_prefix) else "."
    print(f"\n所有生成的节点文件已保存到目录: {os.path.abspath(output_directory)}")

if __name__ == '__main__':
    main()
