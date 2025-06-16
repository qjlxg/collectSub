import asyncio
import aiohttp
import re
import yaml
import os
import base64
from urllib.parse import quote
from tqdm import tqdm
from loguru import logger
import json # 引入 json 模块用于处理 Clash YAML 结构

# 全局配置
RE_URL = r"https?://[-A-Za-z0-9+&@#/%?=~_|!:,.;]+[-A-Za-z0-9+&@#/%=~_|]"
CHECK_NODE_URL_STR = "https://{}/sub?target={}&url={}&insert=false&config=config%2FACL4SSR.ini"
CHECK_URL_LIST = ['api.dler.io', 'sub.xeton.dev', 'sub.id9.cc', 'sub.maoxiongnet.com']
MIN_GB_AVAILABLE = 5 # 最小可用流量，单位 GB

# -------------------------------
# 配置文件操作
# -------------------------------
def load_yaml_config(path_yaml):
    """读取 YAML 配置文件，如文件不存在则返回默认结构"""
    if os.path.exists(path_yaml):
        with open(path_yaml, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
    else:
        config = {
            "机场订阅": [],
            "clash订阅": [],
            "v2订阅": [],
            "开心玩耍": [],
            "tgchannel": []
        }
    return config

def save_yaml_config(config, path_yaml):
    """保存配置到 YAML 文件"""
    with open(path_yaml, 'w', encoding='utf-8') as f:
        yaml.dump(config, f, allow_unicode=True)

def get_config_channels(config_file='config.yaml'):
    """
    从配置文件中获取 Telegram 频道链接，
    将类似 https://t.me/univstar 转换为 https://t.me/s/univstar 格式
    """
    config = load_yaml_config(config_file)
    tgchannels = config.get('tgchannel', [])
    new_list = []
    for url in tgchannels:
        parts = url.strip().split('/')
        if parts:
            channel_id = parts[-1]
            new_list.append(f'https://t.me/s/{channel_id}')
    return new_list

# -------------------------------
# 异步 HTTP 请求辅助函数
# -------------------------------
async def fetch_content(url, session, method='GET', headers=None, timeout=15):
    """获取指定 URL 的文本内容"""
    try:
        async with session.request(method, url, headers=headers, timeout=timeout) as response:
            if response.status == 200:
                text = await response.text()
                return text, response.headers # 返回内容和响应头
            else:
                logger.warning(f"URL {url} 返回状态 {response.status}")
                return None, None
    except Exception as e:
        logger.error(f"请求 {url} 异常: {e}")
        return None, None

# -------------------------------
# 频道抓取及订阅检查
# -------------------------------
async def get_channel_urls(channel_url, session):
    """从 Telegram 频道页面抓取所有订阅链接，并过滤无关链接"""
    content, _ = await fetch_content(channel_url, session)
    if content:
        all_urls = re.findall(RE_URL, content)
        filtered = [u for u in all_urls if "//t.me/" not in u and "cdn-telegram.org" not in u]
        logger.info(f"从 {channel_url} 提取 {len(filtered)} 个链接")
        return filtered
    else:
        logger.warning(f"无法获取 {channel_url} 的内容")
        return []

async def check_single_subscription(url, session):
    """
    检查单个订阅链接的有效性并分类：
      - 判断响应头中的 subscription-userinfo 用于机场订阅，并检查可用流量
      - 判断内容中是否包含 'proxies:' 判定 clash 订阅
      - 尝试 base64 解码判断 v2 订阅（识别 ss://、ssr://、vmess://、trojan://）
    返回一个字典：{"url": ..., "type": ..., "info": ..., "content": ...}
    """
    headers = {'User-Agent': 'ClashforWindows/0.18.1'}
    content, response_headers = await fetch_content(url, session, headers=headers, timeout=10)

    if content is None: # 如果无法获取内容，直接返回 None
        return None

    result = {"url": url, "type": None, "info": None, "content": content}

    # 判断机场订阅（检查流量信息）
    if response_headers:
        sub_info = response_headers.get('subscription-userinfo')
        if sub_info:
            nums = re.findall(r'\d+', sub_info)
            if len(nums) >= 3:
                try:
                    upload, download, total = map(int, nums[:3])
                    unused = (total - upload - download) / (1024 ** 3)
                    if unused >= MIN_GB_AVAILABLE: # 过滤少于5GB的机场订阅
                        result["type"] = "机场订阅"
                        result["info"] = f"可用流量: {round(unused, 2)} GB"
                        return result
                    else:
                        logger.info(f"机场订阅 {url} 可用流量不足 {MIN_GB_AVAILABLE} GB，已排除。")
                        return None # 排除流量不足的机场
                except ValueError:
                    logger.warning(f"解析订阅信息 {sub_info} 失败 for {url}")

    # 判断 clash 订阅
    if "proxies:" in content:
        try:
            # 尝试解析为 YAML，进一步确认是 Clash 配置
            yaml.safe_load(content)
            result["type"] = "clash订阅"
            return result
        except yaml.YAMLError:
            logger.warning(f"链接 {url} 包含 'proxies:' 但不是有效的 YAML 配置，视为未知订阅。")

    # 判断 v2 订阅，通过 base64 解码检测
    try:
        sample = content[:min(len(content), 2048)] # 适当增加解码长度，以应对较长的单行编码
        decoded_content = base64.b64decode(sample).decode('utf-8', errors='ignore')
        if any(proto in decoded_content for proto in ['ss://', 'ssr://', 'vmess://', 'trojan://']):
            result["type"] = "v2订阅"
            # 对于V2订阅，将解码后的内容存入 content
            try:
                result["content"] = base64.b64decode(content).decode('utf-8', errors='ignore')
            except Exception as e:
                logger.warning(f"V2订阅 {url} 的完整内容解码失败: {e}")
            return result
    except (base64.binascii.Error, UnicodeDecodeError):
        pass # 不是有效的base64编码

    # 剩下的是未知类型，但如果能获取到内容，也算有效
    result["type"] = "未知订阅"
    return result

# -------------------------------
# 节点有效性检测（根据多个检测入口）
# -------------------------------
async def check_node_validity(url, target, session):
    """
    通过遍历多个检测入口检查订阅节点有效性，
    如果任一检测返回状态 200，则认为该节点有效。
    """
    encoded_url = quote(url, safe='')
    for check_base in CHECK_URL_LIST:
        check_url = CHECK_NODE_URL_STR.format(check_base, target, encoded_url)
        try:
            async with session.get(check_url, timeout=15) as resp:
                if resp.status == 200:
                    return url
        except Exception:
            continue
    return None

def write_url_list(url_list, file_path):
    """将 URL 列表写入文本文件"""
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(url_list))
    logger.info(f"已保存 {len(url_list)} 个链接到 {file_path}")

# -------------------------------
# 节点解码与合并
# -------------------------------
def decode_and_extract_nodes(sub_type, content):
    """
    根据订阅类型解码内容并提取节点。
    返回一个包含代理链接的列表。
    """
    nodes = []
    if not content:
        return nodes

    try:
        if sub_type in ["机场订阅", "v2订阅", "未知订阅"]: # 这些通常是 base64 编码的 V2Ray/SSR/SS 链接
            # 尝试直接解码，因为 check_single_subscription 已经对 V2 订阅做了初步解码
            # 但这里要确保是完整解码，且处理非 base64 的原始链接
            try:
                decoded_text = base64.b64decode(content).decode('utf-8', errors='ignore')
            except (base64.binascii.Error, UnicodeDecodeError):
                decoded_text = content # 如果不是base64编码，就直接用原始内容

            # 匹配所有常见的代理链接格式
            # 增加对 trojan:// 的匹配
            proxy_patterns = r"(ss://[^\\n]+|ssr://[^\\n]+|vmess://[^\\n]+|trojan://[^\\n]+)"
            nodes.extend(re.findall(proxy_patterns, decoded_text))

        elif sub_type == "clash订阅":
            try:
                clash_config = yaml.safe_load(content)
                if clash_config and 'proxies' in clash_config:
                    for proxy in clash_config['proxies']:
                        # Clash 代理配置通常是字典，需要根据协议类型构造链接
                        # 这里只是一个简单的示例，实际可能需要更复杂的逻辑来构建标准代理链接
                        # 或者直接使用 Clash config 的代理名称 (proxy['name'])
                        # 为了简化并确保能输出可用的链接，这里假设 proxy 字典中包含足够信息构建链接
                        # 实际可能需要根据不同的协议 (ss, vmess, trojan) 构造对应的链接格式
                        # 简单的做法是：如果 Clash 配置中也直接包含了标准链接，则提取
                        # 考虑到 Clash 配置通常是节点详情，而不是可直接订阅的单行链接
                        # 我们直接提取 Clash 原始的 proxies 字典并转换为 JSON 字符串，方便查看
                        # 或者，如果目标是生成一个大的 V2Ray/SSR/SS 订阅文件，则需要进行格式转换
                        # 目前脚本目标是合并所有“节点”，我们将 Clash 的每个代理项作为一个“节点”
                        # 考虑到方便后续使用，这里可以简单地将 Clash proxy item 转换为 JSON 字符串
                        nodes.append(json.dumps(proxy, ensure_ascii=False))
            except yaml.YAMLError as e:
                logger.warning(f"无法解析 Clash 订阅内容为 YAML: {e}")

    except Exception as e:
        logger.error(f"解码和提取节点失败 ({sub_type}): {e}")
    return nodes

# -------------------------------
# 主函数入口
# -------------------------------
async def main():
    config_path = 'config.yaml'
    config = load_yaml_config(config_path)

    async with aiohttp.ClientSession() as session:
        # 获取所有 Telegram 频道中的 URL
        tg_channels = get_config_channels(config_path)
        all_urls_from_channels = []
        for channel in tg_channels:
            urls = await get_channel_urls(channel, session)
            all_urls_from_channels.extend(urls)
        today_urls = list(set(all_urls_from_channels)) # 去重
        logger.info(f"从 Telegram 频道共获得 {len(today_urls)} 个去重链接")

        # 异步检查所有订阅链接的有效性并分类
        tasks = [check_single_subscription(url, session) for url in today_urls]
        sub_results = []
        for coro in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="订阅筛选"):
            res = await coro
            if res:
                sub_results.append(res)
        logger.info(f"完成订阅筛选，共 {len(sub_results)} 个有效结果。")

        # 根据检查结果按类型分类并更新配置
        subs = []  # 机场订阅
        clash = [] # Clash 订阅
        v2 = []    # V2ray/SSR/SS 订阅
        play = []  # 开心玩耍（含流量信息）
        all_decoded_nodes = set() # 用于存储所有去重后的解码节点

        for res in sub_results:
            if res["type"] == "机场订阅":
                subs.append(res["url"])
                if res["info"]:
                    play.append(f'{res["info"]} {res["url"]}')
            elif res["type"] == "clash订阅":
                clash.append(res["url"])
            elif res["type"] == "v2订阅":
                v2.append(res["url"])

            # 尝试解码并提取节点，加入到总的节点集合中
            nodes = decode_and_extract_nodes(res["type"], res["content"])
            all_decoded_nodes.update(nodes)

        print("\n--- 订阅分类结果 ---")
        print(f"机场订阅数量 (可用流量 >= {MIN_GB_AVAILABLE}GB): {len(subs)}")
        print(f"Clash 订阅数量: {len(clash)}")
        print(f"V2ray/SSR/SS 订阅数量: {len(v2)}")
        print(f"开心玩耍 (含流量信息) 数量: {len(play)}")

        # 合并并更新配置（与原有数据合并）
        config["机场订阅"] = sorted(list(set(config.get("机场订阅", []) + subs)))
        config["clash订阅"] = sorted(list(set(config.get("clash订阅", []) + clash)))
        config["v2订阅"] = sorted(list(set(config.get("v2订阅", []) + v2)))
        config["开心玩耍"] = sorted(list(set(config.get("开心玩耍", []) + play)))
        save_yaml_config(config, config_path)
        logger.info("配置文件已更新。")

        # 写入订阅存储文件（包含流量信息和机场订阅链接）
        sub_store_file = config_path.replace('.yaml', '_sub_store.txt')
        content_to_write = "-- play_list --\n\n" + "\n".join(play) + "\n\n-- sub_list --\n\n" + "\n".join(subs)
        with open(sub_store_file, 'w', encoding='utf-8') as f:
            f.write(content_to_write)
        logger.info(f"订阅存储文件已保存至 {sub_store_file}")

        # 写入所有解码后的节点
        all_nodes_file = config_path.replace('.yaml', '_all_merged_nodes.txt')
        write_url_list(sorted(list(all_decoded_nodes)), all_nodes_file)
        logger.info(f"所有解码并合并后的节点已保存至 {all_nodes_file}，共 {len(all_decoded_nodes)} 个节点。")

        # 批量检测各类订阅的节点有效性并写入文件（保持原有逻辑，因为这里的“节点”是订阅链接本身）
        subscription_targets = {
            "机场订阅": {"urls": subs, "target": "loon", "file_suffix": "_loon.txt"},
            "clash订阅": {"urls": clash, "target": "clash", "file_suffix": "_clash.txt"},
            "v2订阅": {"urls": v2, "target": "v2ray", "file_suffix": "_v2.txt"}
        }

        for sub_type, data in subscription_targets.items():
            if data["urls"]:
                logger.info(f"开始检测 '{sub_type}' 类型的订阅链接有效性...")
                tasks = [check_node_validity(url, data["target"], session) for url in data["urls"]]
                valid_urls_for_type = []
                for coro in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc=f"{sub_type} 链接检测"):
                    res = await coro
                    if res:
                        valid_urls_for_type.append(res)
                valid_file = config_path.replace('.yaml', data["file_suffix"])
                write_url_list(valid_urls_for_type, valid_file)
            else:
                logger.info(f"没有 '{sub_type}' 类型的链接需要检测。")


if __name__ == '__main__':
    asyncio.run(main())
