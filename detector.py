#!/usr/bin/env python3
"""
Ghost Bits 检测与分析模块

用于蓝队防御：
- 检测流量中的 Ghost Bits 编码特征
- 解码还原实际攻击载荷
- 批量扫描日志文件
- 输出结构化检测报告
"""

import re
import sys
import json
from typing import TextIO, Optional
from engine import GhostBitsEngine


class GhostBitsDetector:
    """Ghost Bits 流量检测器"""

    # %uXXXX 格式的 Unicode 编码模式
    PERCENT_U_PATTERN = re.compile(r"%u([0-9A-Fa-f]{4})")
    # \uXXXX 格式的 Unicode 转义
    UNICODE_ESCAPE_PATTERN = re.compile(r"\\u([0-9A-Fa-f]{4})")
    # HTML 数字实体
    HTML_ENTITY_PATTERN = re.compile(r"&#(\d+);")
    # 高密度非 ASCII 字符（原始 Unicode）
    HIGH_UNICODE_PATTERN = re.compile(r"[\u0100-\uFFFF]")

    def __init__(self, threshold: float = 0.3):
        """
        Args:
            threshold: Ghost Bits 判定阈值（可疑字符占比）
        """
        self.engine = GhostBitsEngine()
        self.threshold = threshold

    def detect_string(self, text: str) -> dict:
        """
        检测单个字符串是否包含 Ghost Bits 编码

        Returns:
            检测结果字典
        """
        # 先尝试解码各种编码格式
        decoded_variants = self._decode_all_formats(text)

        results = []
        for variant_name, variant_text in decoded_variants.items():
            analysis = self.engine.analyze(variant_text)
            if analysis["suspicious_chars"] > 0:
                results.append({
                    "format": variant_name,
                    "analysis": analysis,
                })

        # 直接分析原始文本中的高 Unicode 字符
        raw_analysis = self.engine.analyze(text)

        is_ghost_bits = (
            raw_analysis["is_ghost_bits"]
            or any(r["analysis"]["is_ghost_bits"] for r in results)
        )

        best_decode = raw_analysis["decoded_payload"]
        best_confidence = raw_analysis["confidence"]
        for r in results:
            if r["analysis"]["confidence"] > best_confidence:
                best_confidence = r["analysis"]["confidence"]
                best_decode = r["analysis"]["decoded_payload"]

        return {
            "input": text[:200] + ("..." if len(text) > 200 else ""),
            "is_ghost_bits": is_ghost_bits,
            "confidence": best_confidence,
            "decoded_payload": best_decode,
            "raw_analysis": raw_analysis,
            "encoded_formats_found": [r["format"] for r in results],
            "details": results,
        }

    def scan_file(
        self,
        filepath: str,
        output: Optional[TextIO] = None,
        format: str = "text",
    ) -> list[dict]:
        """
        扫描文件中的 Ghost Bits 特征

        Args:
            filepath: 文件路径
            output: 输出流
            format: 输出格式 (text/json)

        Returns:
            检测到的可疑行列表
        """
        if output is None:
            output = sys.stdout

        findings = []

        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    # 快速预筛选：跳过纯 ASCII 行
                    if self._quick_check(line):
                        result = self.detect_string(line)
                        if result["is_ghost_bits"]:
                            finding = {
                                "line_number": line_num,
                                "confidence": result["confidence"],
                                "decoded_payload": result["decoded_payload"],
                                "original": line[:500],
                            }
                            findings.append(finding)
        except FileNotFoundError:
            print(f"[ERROR] File not found: {filepath}", file=sys.stderr)
        except PermissionError:
            print(f"[ERROR] Permission denied: {filepath}", file=sys.stderr)

        # 输出结果
        if format == "json":
            json.dump(findings, output, ensure_ascii=False, indent=2)
        else:
            if findings:
                output.write(f"\n{'='*60}\n")
                output.write(f"Ghost Bits Scan: {filepath}\n")
                output.write(f"Findings: {len(findings)} suspicious lines\n")
                output.write(f"{'='*60}\n\n")
                for f in findings:
                    output.write(f"[Line {f['line_number']}] "
                                f"Confidence: {f['confidence']:.0%}\n")
                    output.write(f"  Decoded: {f['decoded_payload'][:100]}\n")
                    output.write(f"  Original: {f['original'][:100]}\n\n")
            else:
                output.write(f"[OK] No Ghost Bits detected in {filepath}\n")

        return findings

    def _quick_check(self, text: str) -> bool:
        """快速预筛选：检查是否值得深入分析"""
        # 包含 %uXXXX 编码
        if self.PERCENT_U_PATTERN.search(text):
            return True
        # 包含 \uXXXX 转义
        if self.UNICODE_ESCAPE_PATTERN.search(text):
            return True
        # 包含高 Unicode 字符
        if self.HIGH_UNICODE_PATTERN.search(text):
            return True
        # 包含 HTML 数字实体
        if self.HTML_ENTITY_PATTERN.search(text):
            return True
        return False

    def _decode_all_formats(self, text: str) -> dict[str, str]:
        """尝试解码所有已知的编码格式"""
        variants = {}

        # %uXXXX → Unicode 字符
        if self.PERCENT_U_PATTERN.search(text):
            decoded = self.PERCENT_U_PATTERN.sub(
                lambda m: chr(int(m.group(1), 16)), text
            )
            variants["percent_u"] = decoded

        # \uXXXX → Unicode 字符
        if self.UNICODE_ESCAPE_PATTERN.search(text):
            decoded = self.UNICODE_ESCAPE_PATTERN.sub(
                lambda m: chr(int(m.group(1), 16)), text
            )
            variants["unicode_escape"] = decoded

        # HTML 数字实体 → Unicode 字符
        if self.HTML_ENTITY_PATTERN.search(text):
            decoded = self.HTML_ENTITY_PATTERN.sub(
                lambda m: chr(int(m.group(1))), text
            )
            variants["html_entity"] = decoded

        return variants


def generate_ioc_patterns() -> dict:
    """
    生成 Ghost Bits 的 IOC（Indicators of Compromise）模式

    Returns:
        包含各种检测模式的字典
    """
    return {
        "description": "Ghost Bits encoding bypass indicators",
        "patterns": {
            "percent_u_high_density": {
                "regex": r"(%u[0-9A-Fa-f]{4}){3,}",
                "description": "连续 3 个以上 %uXXXX 编码（高位非零）",
                "severity": "high",
            },
            "unicode_escape_in_url": {
                "regex": r"(\\u[0-9A-Fa-f]{4}){3,}",
                "description": "URL 参数中出现连续 \\uXXXX 转义",
                "severity": "high",
            },
            "cjk_in_url_path": {
                "regex": r"[\u4E00-\u9FFF]{2,}.*(/|\\|\.\.)",
                "description": "URL 路径中出现 CJK 字符与路径操作符混合",
                "severity": "medium",
            },
            "mixed_encoding_anomaly": {
                "regex": r"(%u[0-9A-Fa-f]{4}.*%[0-9A-Fa-f]{2})|(%[0-9A-Fa-f]{2}.*%u[0-9A-Fa-f]{4})",
                "description": "同一请求中混合使用 %uXXXX 和 %XX 编码",
                "severity": "medium",
            },
            "high_byte_ascii_low_byte": {
                "regex": r"%u[0-9A-Fa-f]{2}(2[0-9]|3[0-9A-Fa-f]|4[0-9A-Fa-f]|5[0-9A-Fa-f]|6[0-9A-Fa-f]|7[0-9A-Ea-e])",
                "description": "%uXXYY 中 YY 对应可打印 ASCII 但 XX 非零",
                "severity": "high",
            },
        },
        "heuristics": [
            "请求中 Unicode 字符密度异常高（>30%）",
            "URL 路径包含 CJK/拉丁扩展字符但目标是英文系统",
            "同一参数中混合使用多种编码方式",
            "POST body 中出现大量非 BMP 字符但 Content-Type 声明为 ASCII 兼容",
        ],
    }
