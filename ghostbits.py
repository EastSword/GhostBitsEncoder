#!/usr/bin/env python3
"""
GhostBits Encoder — 东方隐侠安全团队

基于 Black Hat Asia 2026 Ghost Bits 编码绕过技术的专业级 payload 生成与检测工具。

Usage:
    python3 ghostbits.py encode -p "payload"
    python3 ghostbits.py encode --preset spring-traversal
    python3 ghostbits.py decode -p "encoded_string"
    python3 ghostbits.py detect -i file.log
    python3 ghostbits.py rules --format snort
    python3 ghostbits.py presets --list
"""

import sys
import os
import argparse
import json

# 确保模块可导入
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine import GhostBitsEngine, OutputFormatter, OUTPUT_FORMATS, CHARSET_STRATEGIES
from presets import get_preset, list_presets, list_tags, PRESETS
from detector import GhostBitsDetector, generate_ioc_patterns
from rules import RuleGenerator


# ============================================================
# CLI 命令实现
# ============================================================

def cmd_encode(args):
    """编码命令"""
    # 确定 payload 来源
    if args.preset:
        preset = get_preset(args.preset)
        payload = preset.payload
        charset = args.charset or preset.charset
        fmt = args.format or preset.format
        exempt = args.exempt if args.exempt is not None else preset.exempt
        repeat = args.repeat or preset.repeat
        tail = args.tail or preset.tail

        if not args.quiet:
            print(f"[*] Preset: {preset.name}", file=sys.stderr)
            print(f"[*] Target: {preset.target}", file=sys.stderr)
            if preset.cve:
                print(f"[*] CVE: {preset.cve}", file=sys.stderr)
            print(f"[*] Notes: {preset.notes}", file=sys.stderr)
            print(file=sys.stderr)
    elif args.payload is not None:
        payload = args.payload
        charset = args.charset or "gb2312"
        fmt = args.format or "raw"
        exempt = args.exempt or ""
        repeat = args.repeat or 1
        tail = args.tail or ""
    elif args.batch:
        # 批量模式
        return cmd_encode_batch(args)
    elif not sys.stdin.isatty():
        # 管道输入
        payload = sys.stdin.read().strip()
        charset = args.charset or "gb2312"
        fmt = args.format or "raw"
        exempt = args.exempt or ""
        repeat = args.repeat or 1
        tail = args.tail or ""
    else:
        print("[ERROR] 需要指定 -p/--payload、--preset 或通过管道输入", file=sys.stderr)
        sys.exit(1)

    # 编码
    engine = GhostBitsEngine(charset=charset, seed=args.seed)
    encoded = engine.encode(
        payload=payload,
        exempt=exempt,
        repeat=repeat,
        tail=tail,
    )

    # 格式化输出
    formatter = OUTPUT_FORMATS.get(fmt, OutputFormatter.raw)
    output = formatter(encoded)

    # 输出
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        if not args.quiet:
            print(f"[+] Output written to: {args.output}", file=sys.stderr)
    else:
        print(output)

    # 显示解码验证
    if args.verify and not args.quiet:
        decoded = engine.decode(encoded)
        print(f"\n[*] Decode verification: {decoded}", file=sys.stderr)


def cmd_encode_batch(args):
    """批量编码"""
    charset = args.charset or "gb2312"
    fmt = args.format or "raw"
    exempt = args.exempt or ""

    engine = GhostBitsEngine(charset=charset, seed=args.seed)
    formatter = OUTPUT_FORMATS.get(fmt, OutputFormatter.raw)

    input_file = args.batch
    results = []

    try:
        with open(input_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                encoded = engine.encode(payload=line, exempt=exempt)
                output = formatter(encoded)
                results.append(output)
    except FileNotFoundError:
        print(f"[ERROR] File not found: {input_file}", file=sys.stderr)
        sys.exit(1)

    # 输出
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write("\n".join(results))
        print(f"[+] {len(results)} payloads encoded → {args.output}", file=sys.stderr)
    else:
        for r in results:
            print(r)


def cmd_decode(args):
    """解码命令"""
    if args.payload is not None:
        text = args.payload
    elif args.input:
        with open(args.input, "r", encoding="utf-8") as f:
            text = f.read()
    elif not sys.stdin.isatty():
        text = sys.stdin.read()
    else:
        print("[ERROR] 需要指定 -p/--payload、-i/--input 或通过管道输入", file=sys.stderr)
        sys.exit(1)

    # 处理 %uXXXX 和 \uXXXX 格式的输入
    import re
    text = re.sub(r"%u([0-9A-Fa-f]{4})", lambda m: chr(int(m.group(1), 16)), text)
    text = re.sub(r"\\u([0-9A-Fa-f]{4})", lambda m: chr(int(m.group(1), 16)), text)

    engine = GhostBitsEngine()
    decoded = engine.decode(text, raw=getattr(args, 'raw', False))

    if args.json:
        analysis = engine.analyze(text)
        print(json.dumps(analysis, ensure_ascii=False, indent=2))
    else:
        print(decoded)


def cmd_detect(args):
    """检测命令"""
    detector = GhostBitsDetector(threshold=args.threshold)

    if args.scan:
        # 扫描文件
        fmt = "json" if args.json else "text"
        findings = detector.scan_file(args.scan, format=fmt)
        if findings is None:
            # 文件错误
            sys.exit(2)
        if args.json:
            pass  # scan_file 已输出 JSON
        elif not findings:
            pass  # scan_file 已输出 OK 消息
        sys.exit(0 if not findings else 1)

    elif args.input:
        with open(args.input, "r", encoding="utf-8") as f:
            text = f.read()
    elif args.payload is not None:
        text = args.payload
    elif not sys.stdin.isatty():
        text = sys.stdin.read()
    else:
        print("[ERROR] 需要指定 --scan、-i/--input、-p/--payload 或管道输入", file=sys.stderr)
        sys.exit(1)

    result = detector.detect_string(text)

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        status = "⚠️  GHOST BITS DETECTED" if result["is_ghost_bits"] else "✓ Clean"
        print(f"Status: {status}")
        print(f"Confidence: {result['confidence']:.0%}")
        if result["is_ghost_bits"]:
            print(f"Decoded payload: {result['decoded_payload'][:200]}")
            if result["encoded_formats_found"]:
                print(f"Encoding formats: {', '.join(result['encoded_formats_found'])}")

    sys.exit(1 if result["is_ghost_bits"] else 0)


def cmd_rules(args):
    """规则生成命令"""
    generator = RuleGenerator()

    output = generator.generate_all(format=args.format)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"[+] Rules written to: {args.output}", file=sys.stderr)
    else:
        print(output)


def cmd_presets(args):
    """预设管理命令"""
    if args.tag:
        presets = list_presets(tag=args.tag)
    else:
        presets = list_presets()

    if args.json:
        data = []
        for p in presets:
            data.append({
                "id": p.id,
                "name": p.name,
                "description": p.description,
                "target": p.target,
                "cve": p.cve,
                "tags": p.tags,
            })
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        if args.tags_only:
            tags = list_tags()
            print("Available tags:")
            for t in tags:
                count = len(list_presets(tag=t))
                print(f"  {t} ({count})")
            return

        print(f"\n{'ID':<22} {'Name':<28} {'CVE':<18} {'Tags'}")
        print(f"{'─'*22} {'─'*28} {'─'*18} {'─'*30}")
        for p in presets:
            cve = p.cve or "—"
            tags = ", ".join(p.tags[:3])
            print(f"{p.id:<22} {p.name:<28} {cve:<18} {tags}")

        print(f"\nTotal: {len(presets)} presets")
        if not args.tag:
            print("Filter by tag: --tag <tag>  |  List tags: --tags")


def cmd_ioc(args):
    """IOC 模式输出"""
    patterns = generate_ioc_patterns()

    if args.json:
        print(json.dumps(patterns, ensure_ascii=False, indent=2))
    else:
        print("Ghost Bits IOC Patterns")
        print("=" * 50)
        for name, pattern in patterns["patterns"].items():
            print(f"\n[{pattern['severity'].upper()}] {name}")
            print(f"  Description: {pattern['description']}")
            print(f"  Regex: {pattern['regex']}")
        print("\nHeuristics:")
        for h in patterns["heuristics"]:
            print(f"  • {h}")


# ============================================================
# CLI 入口
# ============================================================

def build_parser() -> argparse.ArgumentParser:
    """构建命令行参数解析器"""
    parser = argparse.ArgumentParser(
        prog="ghostbits",
        description="GhostBits Encoder — Ghost Bits payload 生成与检测工具 (东方隐侠)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              %(prog)s encode -p "1 or 1=1" -c gb2312 -f percent
              %(prog)s encode --preset spring-traversal
              %(prog)s encode --preset fastjson-rce --verify
              %(prog)s decode -p "%%u4F31%%u5020%%u6F6F%%u7272"
              %(prog)s detect --scan access.log
              %(prog)s rules --format snort -o ghost_bits.rules
              %(prog)s presets --list
              echo "SELECT 1" | %(prog)s encode -f unicode
        """),
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- encode ---
    enc = subparsers.add_parser("encode", help="编码 payload 为 Ghost Bits 形式")
    enc.add_argument("-p", "--payload", help="原始 payload")
    enc.add_argument("--preset", help="使用漏洞预设")
    enc.add_argument("--batch", help="批量编码文件（每行一个 payload）")
    enc.add_argument("-c", "--charset", choices=list(CHARSET_STRATEGIES.keys()),
                     help="伪装字符集")
    enc.add_argument("-f", "--format", choices=list(OUTPUT_FORMATS.keys()),
                     help="输出格式")
    enc.add_argument("-e", "--exempt", help="豁免字符（不编码）")
    enc.add_argument("-r", "--repeat", type=int, help="payload 重复次数")
    enc.add_argument("-t", "--tail", help="追加明文尾部")
    enc.add_argument("--seed", type=int, help="随机种子（可复现结果）")
    enc.add_argument("-o", "--output", help="输出文件路径")
    enc.add_argument("-q", "--quiet", action="store_true", help="静默模式")
    enc.add_argument("--verify", action="store_true", help="显示解码验证")

    # --- decode ---
    dec = subparsers.add_parser("decode", help="解码 Ghost Bits 还原实际 payload")
    dec.add_argument("-p", "--payload", help="编码后的字符串")
    dec.add_argument("-i", "--input", help="输入文件")
    dec.add_argument("--raw", action="store_true", help="原始字节输出（不转义控制字符）")
    dec.add_argument("--json", action="store_true", help="JSON 格式输出（含分析详情）")

    # --- detect ---
    det = subparsers.add_parser("detect", help="检测流量中的 Ghost Bits 特征")
    det.add_argument("-p", "--payload", help="待检测字符串")
    det.add_argument("-i", "--input", help="待检测文件")
    det.add_argument("--scan", help="扫描日志文件")
    det.add_argument("--threshold", type=float, default=0.3,
                     help="检测阈值 (默认: 0.3)")
    det.add_argument("--json", action="store_true", help="JSON 格式输出")

    # --- rules ---
    rul = subparsers.add_parser("rules", help="生成安全设备检测规则")
    rul.add_argument("--format", choices=["snort", "modsecurity", "regex", "yara", "all"],
                     default="all", help="规则格式")
    rul.add_argument("-o", "--output", help="输出文件路径")

    # --- presets ---
    pre = subparsers.add_parser("presets", help="查看漏洞预设列表")
    pre.add_argument("--list", action="store_true", default=True, help="列出所有预设")
    pre.add_argument("--tag", help="按标签过滤")
    pre.add_argument("--tags", dest="tags_only", action="store_true", help="列出所有标签")
    pre.add_argument("--json", action="store_true", help="JSON 格式输出")

    # --- ioc ---
    ioc = subparsers.add_parser("ioc", help="输出 IOC 检测模式")
    ioc.add_argument("--json", action="store_true", help="JSON 格式输出")

    return parser


import textwrap


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    commands = {
        "encode": cmd_encode,
        "decode": cmd_decode,
        "detect": cmd_detect,
        "rules": cmd_rules,
        "presets": cmd_presets,
        "ioc": cmd_ioc,
    }

    cmd_func = commands.get(args.command)
    if cmd_func:
        cmd_func(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
