#!/usr/bin/env python3
"""
GhostBits 扫描器集成工具

功能：
1. Nuclei 模板转换 - 将现有模板的 payload 做 Ghost Bits 编码
2. Payload 字典生成 - 将 fuzz 字典批量编码
3. Xray POC 转换 - 将 xray POC 中的 payload 编码
4. Burp 插件配置生成

用法：
    # 转换 nuclei 模板
    python3 integrations.py nuclei -i template.yaml -o encoded_template.yaml

    # 批量转换目录下所有模板
    python3 integrations.py nuclei -d templates/ -o encoded_templates/

    # 生成编码后的 fuzz 字典
    python3 integrations.py wordlist -i sqli.txt -o sqli_ghostbits.txt

    # 生成多种编码变体的字典
    python3 integrations.py wordlist -i payloads.txt --variants -o output_dir/
"""

import sys
import os
import re
import argparse
import shutil

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from engine import GhostBitsEngine, OutputFormatter, OUTPUT_FORMATS, CHARSET_STRATEGIES


# ============================================================
# Nuclei 模板转换
# ============================================================

class NucleiConverter:
    """Nuclei YAML 模板 Ghost Bits 编码转换器"""

    # 需要编码的 YAML 字段路径
    PAYLOAD_FIELDS = [
        "payloads",
        "raw",
        "path",
        "body",
        "data",
    ]

    # payload 中需要编码的攻击特征
    ATTACK_INDICATORS = re.compile(
        r"(?i)(\.\./|union\s+select|<script|;.*cat\s|@type|"
        r"Runtime|exec\(|ProcessBuilder|ldap://|rmi://|"
        r"\$\{jndi|<!ENTITY|file://|%2e%2e)"
    )

    def __init__(self, engine: GhostBitsEngine, format: str = "percent"):
        self.engine = engine
        self.format = format
        self.formatter = OUTPUT_FORMATS.get(format, OutputFormatter.percent_encode)

    def convert_file(self, input_path: str, output_path: str) -> bool:
        """转换单个 nuclei 模板文件"""
        try:
            with open(input_path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception as e:
            print(f"  [!] Cannot read {input_path}: {e}", file=sys.stderr)
            return False

        # 在 YAML 中查找并编码 payload
        converted = self._process_yaml(content)

        # 添加 Ghost Bits 标记注释
        header = (
            "# [GhostBits] This template has been encoded with Ghost Bits\n"
            f"# [GhostBits] Charset: {self.engine.strategy.name}, Format: {self.format}\n"
            "# [GhostBits] Original payloads are encoded to bypass WAF signature detection\n"
        )

        if converted != content:
            output_content = header + converted
        else:
            output_content = content  # 没有变化就不加标记

        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(output_content)

        return converted != content

    def convert_directory(self, input_dir: str, output_dir: str) -> tuple[int, int]:
        """批量转换目录下的所有 YAML 模板"""
        converted = 0
        total = 0

        for root, dirs, files in os.walk(input_dir):
            for filename in files:
                if not filename.endswith((".yaml", ".yml")):
                    continue

                total += 1
                input_path = os.path.join(root, filename)
                rel_path = os.path.relpath(input_path, input_dir)
                output_path = os.path.join(output_dir, rel_path)

                if self.convert_file(input_path, output_path):
                    converted += 1
                    print(f"  [+] {rel_path}")

        return converted, total

    def _process_yaml(self, content: str) -> str:
        """处理 YAML 内容，编码其中的 payload"""
        lines = content.split("\n")
        result = []
        in_raw_block = False
        in_payloads_block = False

        for line in lines:
            stripped = line.strip()

            # 检测 raw 请求块
            if stripped.startswith("- |") or stripped == "- |+":
                in_raw_block = True
                result.append(line)
                continue

            if in_raw_block:
                if stripped and not line.startswith(" " * 8) and not line.startswith("\t\t"):
                    in_raw_block = False
                else:
                    # 在 raw 块中编码攻击载荷
                    line = self._encode_line_payload(line)
                    result.append(line)
                    continue

            # 检测 payloads 块
            if stripped.startswith("payloads:"):
                in_payloads_block = True
                result.append(line)
                continue

            if in_payloads_block:
                if stripped.startswith("- "):
                    # payload 列表项
                    value = stripped[2:].strip().strip('"').strip("'")
                    if self.ATTACK_INDICATORS.search(value):
                        encoded = self._encode_payload(value)
                        indent = len(line) - len(line.lstrip())
                        result.append(f"{' ' * indent}- \"{encoded}\"")
                        continue
                elif not stripped.startswith("#") and stripped and not line.startswith(" "):
                    in_payloads_block = False

            # 检测 path/body/data 字段中的 payload
            for field in ["path:", "body:", "data:"]:
                if stripped.startswith(field):
                    value_part = stripped[len(field):].strip().strip('"').strip("'")
                    if value_part and self.ATTACK_INDICATORS.search(value_part):
                        encoded = self._encode_payload(value_part)
                        indent = len(line) - len(line.lstrip())
                        result.append(f"{' ' * indent}{field} \"{encoded}\"")
                        continue

            result.append(line)

        return "\n".join(result)

    def _encode_line_payload(self, line: str) -> str:
        """编码 raw 请求行中的攻击载荷"""
        # 只编码 URL path 和参数中的攻击部分
        # GET /path?param=value HTTP/1.1
        match = re.match(r"(\s*)(GET|POST|PUT|DELETE|PATCH)\s+(\S+)\s+(HTTP/\S+)", line)
        if match:
            indent, method, url, version = match.groups()
            parsed = urllib.parse.urlparse(url)

            # 编码 path
            if self.ATTACK_INDICATORS.search(parsed.path):
                new_path = self._encode_payload(parsed.path)
            else:
                new_path = parsed.path

            # 编码 query
            if parsed.query and self.ATTACK_INDICATORS.search(parsed.query):
                new_query = self._encode_query(parsed.query)
            else:
                new_query = parsed.query

            new_url = new_path
            if new_query:
                new_url += "?" + new_query

            return f"{indent}{method} {new_url} {version}"

        # 检查是否是请求体中的攻击载荷
        if self.ATTACK_INDICATORS.search(line):
            stripped = line.strip()
            indent = len(line) - len(line.lstrip())
            encoded = self._encode_payload(stripped)
            return " " * indent + encoded

        return line

    def _encode_payload(self, payload: str) -> str:
        """编码单个 payload 字符串"""
        # 确定豁免字符
        exempt = "/?&=#{}[]():,. "
        encoded = self.engine.encode(payload, exempt=exempt)
        return self.formatter(encoded)

    def _encode_query(self, query: str) -> str:
        """编码查询字符串"""
        import urllib.parse
        params = urllib.parse.parse_qs(query, keep_blank_values=True)
        parts = []
        for key, values in params.items():
            for value in values:
                if self.ATTACK_INDICATORS.search(value):
                    encoded = self.engine.encode(value, exempt="")
                    formatted = self.formatter(encoded)
                    parts.append(f"{key}={formatted}")
                else:
                    parts.append(f"{key}={value}")
        return "&".join(parts)


# ============================================================
# Payload 字典生成
# ============================================================

class WordlistGenerator:
    """Fuzz 字典 Ghost Bits 编码生成器"""

    def __init__(self, engine: GhostBitsEngine):
        self.engine = engine

    def convert_file(self, input_path: str, output_path: str,
                     format: str = "percent", exempt: str = "") -> int:
        """转换单个字典文件"""
        formatter = OUTPUT_FORMATS.get(format, OutputFormatter.percent_encode)
        count = 0

        with open(input_path, "r", encoding="utf-8", errors="replace") as fin:
            with open(output_path, "w", encoding="utf-8") as fout:
                for line in fin:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    encoded = self.engine.encode(line, exempt=exempt)
                    formatted = formatter(encoded)
                    fout.write(formatted + "\n")
                    count += 1

        return count

    def generate_variants(self, input_path: str, output_dir: str) -> dict:
        """生成多种编码变体的字典"""
        os.makedirs(output_dir, exist_ok=True)
        base_name = os.path.splitext(os.path.basename(input_path))[0]
        results = {}

        variants = [
            ("gb2312", "percent", "gb2312_percent"),
            ("gb2312", "unicode", "gb2312_unicode"),
            ("cjk", "percent", "cjk_percent"),
            ("latin", "percent", "latin_percent"),
            ("latin", "unicode", "latin_unicode"),
            ("private", "percent", "private_percent"),
            ("random", "mixed", "random_mixed"),
        ]

        for charset, fmt, suffix in variants:
            engine = GhostBitsEngine(charset=charset)
            formatter = OUTPUT_FORMATS[fmt]
            output_path = os.path.join(output_dir, f"{base_name}_{suffix}.txt")

            count = 0
            with open(input_path, "r", encoding="utf-8", errors="replace") as fin:
                with open(output_path, "w", encoding="utf-8") as fout:
                    for line in fin:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        encoded = engine.encode(line, exempt="")
                        formatted = formatter(encoded)
                        fout.write(formatted + "\n")
                        count += 1

            results[suffix] = {"path": output_path, "count": count}
            print(f"  [+] {output_path} ({count} payloads)")

        return results


# ============================================================
# CLI
# ============================================================

def cmd_nuclei(args):
    """Nuclei 模板转换"""
    engine = GhostBitsEngine(charset=args.charset, seed=args.seed)
    converter = NucleiConverter(engine, format=args.format)

    if args.directory:
        output_dir = args.output or (args.directory.rstrip("/") + "_ghostbits")
        print(f"Converting templates: {args.directory} → {output_dir}")
        converted, total = converter.convert_directory(args.directory, output_dir)
        print(f"\nDone: {converted}/{total} templates encoded")
    elif args.input:
        output_path = args.output or args.input.replace(".yaml", "_ghostbits.yaml")
        if converter.convert_file(args.input, output_path):
            print(f"[+] Encoded: {output_path}")
        else:
            print(f"[*] No attack patterns found, copied as-is: {output_path}")
    else:
        print("[ERROR] 需要指定 -i/--input 或 -d/--directory", file=sys.stderr)
        sys.exit(1)


def cmd_wordlist(args):
    """字典生成"""
    if not args.input:
        print("[ERROR] 需要指定 -i/--input", file=sys.stderr)
        sys.exit(1)

    engine = GhostBitsEngine(charset=args.charset, seed=args.seed)
    generator = WordlistGenerator(engine)

    if args.variants:
        output_dir = args.output or "ghostbits_wordlists"
        print(f"Generating variants: {args.input} → {output_dir}/")
        generator.generate_variants(args.input, output_dir)
    else:
        output_path = args.output or args.input.replace(".txt", "_ghostbits.txt")
        count = generator.convert_file(
            args.input, output_path,
            format=args.format,
            exempt=args.exempt or "",
        )
        print(f"[+] {count} payloads encoded → {output_path}")


def main():
    parser = argparse.ArgumentParser(
        prog="ghostbits-integrations",
        description="GhostBits 扫描器集成工具 — 模板转换 & 字典生成",
    )

    subparsers = parser.add_subparsers(dest="command")

    # nuclei
    nuc = subparsers.add_parser("nuclei", help="转换 Nuclei 模板")
    nuc.add_argument("-i", "--input", help="输入模板文件")
    nuc.add_argument("-d", "--directory", help="输入模板目录")
    nuc.add_argument("-o", "--output", help="输出路径")
    nuc.add_argument("-c", "--charset", default="gb2312",
                     choices=list(CHARSET_STRATEGIES.keys()))
    nuc.add_argument("-f", "--format", default="percent",
                     choices=list(OUTPUT_FORMATS.keys()))
    nuc.add_argument("--seed", type=int)

    # wordlist
    wl = subparsers.add_parser("wordlist", help="生成编码后的 fuzz 字典")
    wl.add_argument("-i", "--input", required=True, help="输入字典文件")
    wl.add_argument("-o", "--output", help="输出路径")
    wl.add_argument("-c", "--charset", default="gb2312",
                    choices=list(CHARSET_STRATEGIES.keys()))
    wl.add_argument("-f", "--format", default="percent",
                    choices=list(OUTPUT_FORMATS.keys()))
    wl.add_argument("-e", "--exempt", help="豁免字符")
    wl.add_argument("--variants", action="store_true",
                    help="生成多种编码变体")
    wl.add_argument("--seed", type=int)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    commands = {
        "nuclei": cmd_nuclei,
        "wordlist": cmd_wordlist,
    }

    commands[args.command](args)


if __name__ == "__main__":
    main()
