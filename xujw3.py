import base64
import re
import json
import logging
from urllib.parse import urlparse, parse_qs, quote, unquote

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- 辅助函数 ---

def is_base64(s):
    """检查字符串是否为有效的 Base64 编码"""
    return re.match(r'^[A-Za-z0-9+/=]+$', s) is not None

def decode_base64_if_encoded(data):
    """尝试解码 Base64 编码的数据"""
    try:
        decoded_data = base64.b64decode(data).decode('utf-8')
        return decoded_data
    except Exception:
        return data # 如果解码失败，返回原始数据

def parse_clash_url(url):
    """解析 Clash URL 并返回字典"""
    parsed_url = urlparse(url)
    proxy_type = parsed_url.scheme
    params = dict(parse_qs(parsed_url.query))
    # 将列表值转换为单个值
    for key, value in params.items():
        if isinstance(value, list) and len(value) == 1:
            params[key] = value[0]
    
    # 路径部分可能包含用户信息或路径
    path_parts = parsed_url.path.strip('/').split('/')
    
    # Fragment 部分通常是节点名称
    name = unquote(parsed_url.fragment) if parsed_url.fragment else f"{proxy_type}节点"

    return {
        "type": proxy_type,
        "server": parsed_url.hostname,
        "port": parsed_url.port,
        "name": name,
        "params": params,
        "path_parts": path_parts,
        "username": parsed_url.username,
        "password": parsed_url.password
    }

def convert_clash_proxy_to_url(proxy_dict):
    """
    将 Clash JSON 代理配置转换为标准 URL 格式。
    如果无法转换，返回 None。
    """
    ptype = proxy_dict.get('type')
    name = quote(proxy_dict.get('name', 'ClashNode')) # 编码节点名称

    try:
        if ptype == 'ss':
            server = proxy_dict.get('server')
            port = proxy_dict.get('port')
            password = proxy_dict.get('password')
            cipher = proxy_dict.get('cipher')
            if all([server, port, password, cipher]):
                # SS 链接格式: ss://method:password@server:port#name
                encoded_info = base64.b64encode(f"{cipher}:{password}".encode()).decode()
                return f"ss://{encoded_info}@{server}:{port}#{name}"

        elif ptype == 'vmess':
            server = proxy_dict.get('server')
            port = proxy_dict.get('port')
            uuid = proxy_dict.get('uuid')
            alterId = proxy_dict.get('alterId', 0)
            security = proxy_dict.get('security', 'auto')
            network = proxy_dict.get('network', 'tcp')
            
            vmess_config = {
                "v": "2",
                "ps": unquote(name), # VMess 链接中的名称不编码
                "add": server,
                "port": port,
                "id": uuid,
                "aid": alterId,
                "net": network,
                "type": "none", # 伪装类型
                "host": "",
                "path": "",
                "tls": "",
                "sni": "",
                "alpn": ""
            }

            # 处理 TLS
            if proxy_dict.get('tls'):
                vmess_config['tls'] = "tls"
                vmess_config['sni'] = proxy_dict.get('sni', '')
                if 'alpn' in proxy_dict:
                    vmess_config['alpn'] = ",".join(proxy_dict['alpn'])

            # 处理各种网络类型 (ws, http, grpc, h2, quic, tcp)
            if network == 'ws':
                vmess_config['type'] = "ws"
                ws_opts = proxy_dict.get('ws-opts', {})
                vmess_config['path'] = ws_opts.get('path', '')
                vmess_config['host'] = ws_opts.get('headers', {}).get('Host', '')
            elif network == 'grpc':
                vmess_config['type'] = "grpc"
                grpc_opts = proxy_dict.get('grpc-opts', {})
                vmess_config['serviceName'] = grpc_opts.get('serviceName', '')
            elif network == 'h2': # 对应 Clash 的 h2
                vmess_config['type'] = "http" # Vmess 链接中的 http 对应 Clash 的 h2
                h2_opts = proxy_dict.get('h2-opts', {})
                vmess_config['path'] = h2_opts.get('path', '')
                vmess_config['host'] = h2_opts.get('host', [])[0] if h2_opts.get('host') else ''
            # 其他网络类型可以根据需要添加

            return "vmess://" + base64.b64encode(json.dumps(vmess_config, ensure_ascii=False).encode()).decode()

        elif ptype == 'trojan':
            server = proxy_dict.get('server')
            port = proxy_dict.get('port')
            password = proxy_dict.get('password')
            
            if all([server, port, password]):
                trojan_url = f"trojan://{password}@{server}:{port}#{name}"
                
                params = []
                if proxy_dict.get('sni'):
                    params.append(f"sni={quote(proxy_dict['sni'])}")
                if proxy_dict.get('skip-cert-verify'):
                    params.append("allowInsecure=1") # Trojan 标准中通常是 allowInsecure
                if 'alpn' in proxy_dict and proxy_dict['alpn']:
                    params.append(f"alpn={','.join(proxy_dict['alpn'])}")
                
                if params:
                    trojan_url += "?" + "&".join(params)
                
                return trojan_url

        elif ptype == 'vless':
            server = proxy_dict.get('server')
            port = proxy_dict.get('port')
            uuid = proxy_dict.get('uuid')
            
            if all([server, port, uuid]):
                vless_url = f"vless://{uuid}@{server}:{port}#{name}"
                
                params = []
                # 处理 TLS
                if proxy_dict.get('tls'):
                    params.append("security=tls")
                    if proxy_dict.get('sni'):
                        params.append(f"sni={quote(proxy_dict['sni'])}")
                    if 'alpn' in proxy_dict and proxy_dict['alpn']:
                        params.append(f"alpn={','.join(proxy_dict['alpn'])}")
                    if proxy_dict.get('skip-cert-verify'):
                        params.append("allowInsecure=1")

                # 处理传输协议
                network = proxy_dict.get('network', 'tcp')
                params.append(f"type={network}")

                if network == 'ws':
                    ws_opts = proxy_dict.get('ws-opts', {})
                    if ws_opts.get('path'):
                        params.append(f"path={quote(ws_opts['path'])}")
                    if ws_opts.get('headers', {}).get('Host'):
                        params.append(f"host={quote(ws_opts['headers']['Host'])}")
                elif network == 'grpc':
                    grpc_opts = proxy_dict.get('grpc-opts', {})
                    if grpc_opts.get('serviceName'):
                        params.append(f"serviceName={quote(grpc_opts['serviceName'])}")
                    if grpc_opts.get('mode'):
                        params.append(f"mode={quote(grpc_opts['mode'])}")
                elif network == 'h2': # Clash 的 h2
                    h2_opts = proxy_dict.get('h2-opts', {})
                    if h2_opts.get('path'):
                        params.append(f"path={quote(h2_opts['path'])}")
                    if h2_opts.get('host'):
                        params.append(f"host={quote(','.join(h2_opts['host']))}") # h2 的 host 可能是列表

                # 其他 VLESS 参数可以根据需要添加
                
                if params:
                    vless_url += "?" + "&".join(params)
                
                return vless_url
        
        # --- 新增的 Hysteria, Hysteria2, TUIC 协议处理 ---
        # 对于这些协议，由于没有官方统一的 URL 格式，我们不尝试转换为 URL，而是返回 None
        # 让调用者保留其原始 JSON 格式。
        elif ptype in ['hysteria', 'hysteria2', 'tuic']:
            logger.info(f"Clash 代理类型 '{ptype}' 没有标准 URL 格式，将保留其原始 JSON 配置。")
            return None # 返回 None，表示无法转换为标准 URL

        logger.warning(f"不支持的 Clash 代理类型: {ptype}")
        return None
    except Exception as e:
        logger.error(f"转换 Clash 代理 '{proxy_dict.get('name', '未知节点')}' 失败: {e}")
        return None

# --- 主要处理逻辑 ---

def decode_and_extract_nodes(content):
    """
    解码内容并提取所有代理节点。
    支持直接链接、Base64 编码的链接和 Clash JSON 配置。
    """
    nodes = []
    sub_type = "未知"

    if not content:
        return nodes, sub_type

    # 1. 尝试识别 Clash JSON 配置
    try:
        json_content = json.loads(content)
        if isinstance(json_content, dict) and 'proxies' in json_content:
            sub_type = "clash订阅"
            logger.info("检测到 Clash JSON 订阅。")
            for proxy in json_content['proxies']:
                node_link = convert_clash_proxy_to_url(proxy)
                if node_link:
                    nodes.append(node_link)
                else:
                    # 如果无法转换为标准链接，将其原始 JSON 格式添加到列表中
                    # 这样客户端（特别是Clash）可以直接使用这些JSON
                    try:
                        nodes.append(json.dumps(proxy, ensure_ascii=False))
                        logger.info(f"添加了无法转换为标准链接的 Clash 代理 (JSON 格式): {proxy.get('name', '未知节点')}")
                    except Exception as e:
                        logger.warning(f"无法将 Clash 代理转换为 JSON 字符串: {proxy.get('name', '未知节点')}, 错误: {e}")
            return nodes, sub_type
    except json.JSONDecodeError:
        pass # 不是 JSON，继续尝试 Base64 或纯文本

    # 2. 尝试 Base64 解码
    decoded_content = decode_base64_if_encoded(content)
    if decoded_content != content:
        sub_type = "Base64编码订阅"
        logger.info("检测到 Base64 编码订阅。")
    else:
        sub_type = "纯文本链接"
        logger.info("检测到纯文本链接。")

    # 3. 从解码后的内容中提取链接
    # 定义代理链接的正则表达式模式
    proxy_patterns = {
        'vmess': r'vmess://[a-zA-Z0-9+/=]+',
        'ss': r'ss://[a-zA-Z0-9%@:./?#=&+-]+',
        'trojan': r'trojan://[a-zA-Z0-9%@:./?#=&+-]+',
        'vless': r'vless://[a-zA-Z0-9%@:./?#=&+-]+',
        'ssr': r'ssr://[a-zA-Z0-9%@:./?#=&+-]+',
        'hysteria': r'hysteria://[a-zA-Z0-9%@:./?#=&+-]+',
        'hysteria2': r'hysteria2://[a-zA-Z0-9%@:./?#=&+-]+',
        'tuic': r'tuic://[a-zA-Z0-9%@:./?#=&+-]+',
        # 可能需要添加对裸机IP的识别，但通常订阅会包含协议头
    }

    for proto, pattern in proxy_patterns.items():
        found_links = re.findall(pattern, decoded_content)
        if found_links:
            nodes.extend(found_links)
            logger.info(f"提取到 {len(found_links)} 条 {proto} 链接。")

    # 移除重复项
    nodes = list(dict.fromkeys(nodes))
    return nodes, sub_type

def main():
    # 模拟一个 Clash 订阅内容，包含 vmess, ss, trojan 和 hysteria
    # 注意：实际使用时，content 应该从文件或网络获取
    clash_sub_content_example = """
{
  "port": 7890,
  "socks-port": 7891,
  "allow-lan": true,
  "mode": "rule",
  "log-level": "info",
  "external-controller": "0.0.0.0:9090",
  "proxies": [
    {
      "name": "香港-VMess-WS",
      "type": "vmess",
      "server": "example.com",
      "port": 443,
      "uuid": "your-uuid-vmess",
      "alterId": 0,
      "cipher": "auto",
      "network": "ws",
      "tls": true,
      "servername": "example.com",
      "ws-opts": {
        "path": "/ws",
        "headers": {
          "Host": "example.com"
        }
      }
    },
    {
      "name": "新加坡-SS-AES256",
      "type": "ss",
      "server": "1.2.3.4",
      "port": 8443,
      "password": "your-password-ss",
      "cipher": "aes-256-gcm"
    },
    {
      "name": "日本-Trojan",
      "type": "trojan",
      "server": "trojan.example.com",
      "port": 443,
      "password": "your-password-trojan",
      "sni": "trojan.example.com",
      "skip-cert-verify": true
    },
    {
      "name": "美国-Hysteria",
      "type": "hysteria",
      "server": "hysteria.example.com",
      "port": 443,
      "auth-str": "your-auth-str",
      "alpn": ["h3", "quic"],
      "up": 100,
      "down": 500,
      "obfs": "none"
    },
    {
      "name": "英国-Hysteria2",
      "type": "hysteria2",
      "server": "hysteria2.example.com",
      "port": 443,
      "password": "your-password-hysteria2",
      "obfs": "salamander",
      "obfs-password": "salamander-pwd"
    },
    {
      "name": "德国-TUIC",
      "type": "tuic",
      "server": "tuic.example.com",
      "port": 443,
      "uuid": "your-uuid-tuic",
      "password": "your-password-tuic",
      "congestion-controller": "bbr",
      "udp-relay-mode": "native",
      "tls": true,
      "sni": "tuic.example.com",
      "alpn": ["h3"]
    },
    {
      "name": "加拿大-VLESS-WS-TLS",
      "type": "vless",
      "server": "vless.example.com",
      "port": 443,
      "uuid": "your-uuid-vless",
      "network": "ws",
      "tls": true,
      "ws-opts": {
        "path": "/vless",
        "headers": {
          "Host": "vless.example.com"
        }
      },
      "servername": "vless.example.com"
    }
  ]
}
    """

    # 这是一个包含 base64 编码的 vmess 链接的示例
    base64_example = base64.b64encode("vmess://eyJhZGQiOiJleGFtcGxlLmNvbSIsInaidCI6NDQzLCJhaWQiOjAsImhvc3QiOiIiLCJpZCI6IjAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMCIsIm5ldCI6InRjcCIsInBhdGgiOiIiLCJwcyI6Itq0y6y2u+OChOWkn+S7u+WPsOmqjCIsInNlY3VyaXR5IjoiYXV0byIsInNraXAtY2VydC12ZXJpZnkiOmZhbHNlLCJ0bHMiOiIiLCJ0eXBlIjoibm9uZSIsInYiOiIyIn0=".encode()).decode()

    # 这是一个混合的纯文本订阅示例
    mixed_text_example = """
vmess://eyJhZGQiOiJleGFtcGxlLmNvbSIsICJwb3J0Ijo0NDMsICJhaWQiOjAsICJpZCI6IjAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMCIsICJuZXQiOiJ3cyIsICJwYXRoIjoiL3dzIiwgInBzIjoi5paw5a2QIl0sICJ0bHMiOiJ0bHMiLCAidHlwZSI6IndzIiwgInYiOiIyIn0=
ss://YWVzLTI1Ni1nY206cGFzc3dvcmRAdGVzdC5jb206ODg4OCNzaGFkb3djb2Nz
trojan://password@trojan.example.com:443#Trojan-Test
hysteria://hy.example.com:443?auth=yourpass#Hysteria-Direct
tuic://tuic.example.com:443?uuid=your-uuid&password=your-password#TUIC-Direct
    """

    # 你可以选择使用哪个内容进行测试
    # content_to_process = clash_sub_content_example
    # content_to_process = base64_example
    content_to_process = mixed_text_example

    # 解码并提取节点
    extracted_nodes, sub_type = decode_and_extract_nodes(content_to_process)

    # 将所有节点写入文件
    output_filename = "_all_merged_nodes.txt"
    with open(output_filename, 'w', encoding='utf-8') as f:
        for node in extracted_nodes:
            f.write(node + '\n')

    logger.info(f"所有节点已提取并保存到 '{output_filename}'，订阅类型为: {sub_type}")
    logger.info(f"共提取了 {len(extracted_nodes)} 个节点。")

    print(f"\n查看 '{output_filename}' 文件以获取提取的节点。")
    print("注意：Hysteria, Hysteria2, TUIC 节点在 Clash 订阅中将以原始 JSON 格式存在，以便 Clash 客户端识别。")

if __name__ == '__main__':
    main()
