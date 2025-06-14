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
    parser = argparse.ArgumentParser(description='提取订阅节点')
    parser.add_argument('--input', default='sub/sub_all_url_check.txt', help='订阅文件路径')
    parser.add_argument('--output', default='all_nodes.txt', help='输出节点文件路径')
    return parser.parse_args()

def is_valid_url(url: str) -> bool:
    try:
        result = urlparse(url)
        return all([result.scheme in ['http', 'https'], result.netloc])
    except ValueError:
        return False

def read_subscriptions(file_path: str) -> List[str]:
    if not os.path.exists(file_path):
        print(f'未找到 {file_path} 文件，跳过生成步骤。')
        return []
    with open(file_path, 'r', encoding='utf-8') as f:
        return [url.strip() for url in f.readlines() if url.strip()]

def write_nodes(nodes: List[str], file_path: str) -> None:
    with open(file_path, 'w', encoding='utf-8') as f:
        for node in nodes:
            f.write(f'{node}\n')
    print(f'节点信息已更新到：{file_path}')

def extract_nodes(text: str) -> List[str]:
    valid_node_prefixes = ['ss://', 'ssr://', 'vmess://', 'vless://', 'trojan://', 'hysteria://', 'hy://', 'hy2://']
    nodes = []
    try:
        decoded_text = base64.b64decode(text).decode('utf-8', errors='ignore')
        lines = decoded_text.split('\n')
    except:
        lines = text.split('\n')
    
    for line in lines:
        line = line.strip()
        for prefix in valid_node_prefixes:
            if line.startswith(prefix) and len(line) > len(prefix) + 10:
                nodes.append(line)
                break
    return list(set(nodes))  # 去重

async def fetch_url(url: str, session: aiohttp.ClientSession, timeout: int = 10) -> Optional[str]:
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
    args = parse_args()
    subscriptions = read_subscriptions(args.input)
    if not subscriptions:
        return
    
    valid_urls = [url for url in subscriptions if is_valid_url(url)]
    contents = asyncio.run(fetch_all_urls(valid_urls))
    
    all_nodes = []
    for content in contents:
        if content:
            nodes = extract_nodes(content)
            all_nodes.extend(nodes)
    
    all_nodes = list(set(all_nodes))  # 全局去重
    write_nodes(all_nodes, args.output)

if __name__ == '__main__':
    main()
