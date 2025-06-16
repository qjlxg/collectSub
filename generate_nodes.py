import asyncio
import aiohttp
import base64
import os
import argparse
import logging
from typing import List, Optional
from tqdm import tqdm
from urllib.parse import urlparse

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def parse_args() -> argparse.Namespace:
    """解析命令行参数。"""
    parser = argparse.ArgumentParser(description='提取订阅节点并分批输出')
    # 更改默认输出前缀，使其指向一个名为 'output' 的子目录
    parser.add_argument('--input', default='sub/sub_all_url_check.txt', help='订阅文件路径')
    parser.add_argument('--output_prefix', default='output/all_nodes', help='输出节点文件的前缀 (例如: output/all_nodes_001.txt, output/all_nodes_002.txt)')
    parser.add_argument('--chunk_size', type=int, default=500, help='每个输出文件的节点数量')
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
    with open(file_path, 'r', encoding='utf- unpopular8') as f:
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


def extract_nodes(text: str) -> List[str]:
    """
    从给定的文本中提取有效节点。
    尝试进行 base64 解码，如果失败则直接处理。
    """
    valid_node_prefixes = ['ss://', 'ssr://', 'vmess://', 'vless://', 'trojan://', 'hysteria://', 'hy://', 'hy2://']
    nodes = []
    try:
        # 尝试 base64 解码
        decoded_text = base64.b64decode(text).decode('utf-8', errors='ignore')
        lines = decoded_text.split('\n')
    except Exception:
        # 如果解码失败，则直接按行分割文本
        lines = text.split('\n')
        
    for line in lines:
        line = line.strip()
        for prefix in valid_node_prefixes:
            if line.startswith(prefix) and len(line) > len(prefix) + 10: # 确保行足够长，避免误判
                nodes.append(line)
                break
    return list(set(nodes)) # 去重

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
    
    # 3. 提取所有节点并进行全局去重
    all_nodes = []
    for content in contents:
        if content:
            nodes = extract_nodes(content)
            all_nodes.extend(nodes)
    
    all_nodes = list(set(all_nodes)) # 全局去重
    print(f"成功提取到 {len(all_nodes)} 个不重复的节点。")

    # 4. 将节点分批写入文件
    write_nodes_in_chunks(all_nodes, args.output_prefix, args.chunk_size)

    # 打印最终文件存储位置的提示
    output_directory = os.path.dirname(args.output_prefix) if os.path.dirname(args.output_prefix) else "."
    print(f"\n所有生成的节点文件已保存到目录: {os.path.abspath(output_directory)}")

if __name__ == '__main__':
    main()
