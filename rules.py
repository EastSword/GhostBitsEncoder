#!/usr/bin/env python3
"""
Ghost Bits 防御规则生成模块

生成各种安全设备的检测规则：
- Snort/Suricata IDS 规则
- ModSecurity WAF 规则
- 正则表达式检测模式
- YARA 规则
"""

import textwrap
from datetime import datetime


class RuleGenerator:
    """安全规则生成器"""

    def __init__(self):
        self.timestamp = datetime.now().strftime("%Y-%m-%d")
        self.sid_base = 9000001  # 自定义规则 SID 起始值

    def generate_snort(self) -> str:
        """生成 Snort/Suricata 规则"""
        rules = []

        # 规则 1: 检测 %uXXXX 高密度编码
        rules.append(
            f'alert http $EXTERNAL_NET any -> $HOME_NET any '
            f'(msg:"GHOST-BITS Possible Ghost Bits encoding - high density percent-u"; '
            f'flow:to_server,established; '
            f'content:"%u"; '
            f'pcre:"/((%u[0-9A-Fa-f]{{4}}){{4,}})/"; '
            f'classtype:web-application-attack; '
            f'sid:{self.sid_base}; rev:1; '
            f'metadata:created_at {self.timestamp}, '
            f'reference url github.com/EastSword/GhostBitsEncoder;)'
        )

        # 规则 2: CJK 字符出现在 URL 路径中（非正常场景）
        rules.append(
            f'alert http $EXTERNAL_NET any -> $HOME_NET any '
            f'(msg:"GHOST-BITS CJK characters in URL path with traversal indicators"; '
            f'flow:to_server,established; '
            f'http_uri; '
            f'pcre:"/[\\x{{4e00}}-\\x{{9fff}}].*(\\.\\.|%2e%2e|%252e)/i"; '
            f'classtype:web-application-attack; '
            f'sid:{self.sid_base + 1}; rev:1; '
            f'metadata:created_at {self.timestamp};)'
        )

        # 规则 3: 混合编码异常
        rules.append(
            f'alert http $EXTERNAL_NET any -> $HOME_NET any '
            f'(msg:"GHOST-BITS Mixed encoding anomaly in HTTP request"; '
            f'flow:to_server,established; '
            f'content:"%u"; '
            f'content:".."; distance:0; '
            f'classtype:web-application-attack; '
            f'sid:{self.sid_base + 2}; rev:1; '
            f'metadata:created_at {self.timestamp};)'
        )

        # 规则 4: Unicode 转义在 JSON body 中的异常使用
        rules.append(
            f'alert http $EXTERNAL_NET any -> $HOME_NET any '
            f'(msg:"GHOST-BITS Suspicious unicode escapes in JSON body"; '
            f'flow:to_server,established; '
            f'http_client_body; '
            f'content:"@type"; '
            f'pcre:"/\\\\u[0-9a-f]{{4}}.*@type/i"; '
            f'classtype:web-application-attack; '
            f'sid:{self.sid_base + 3}; rev:1; '
            f'metadata:created_at {self.timestamp};)'
        )

        # 规则 5: SMTP 走私特征
        rules.append(
            f'alert tcp $EXTERNAL_NET any -> $HOME_NET 25 '
            f'(msg:"GHOST-BITS Possible SMTP smuggling via Ghost Bits"; '
            f'flow:to_server,established; '
            f'pcre:"/[\\x{{0100}}-\\x{{ffff}}].*\\r\\n/"; '
            f'classtype:protocol-command-decode; '
            f'sid:{self.sid_base + 4}; rev:1; '
            f'metadata:created_at {self.timestamp};)'
        )

        header = textwrap.dedent(f"""\
            # ============================================================
            # Ghost Bits Detection Rules for Snort/Suricata
            # Generated: {self.timestamp}
            # Reference: Black Hat Asia 2026 - Cast Attack: Ghost Bits
            # Author: 东方隐侠安全团队
            # ============================================================
            #
            # 部署说明：
            # 1. 将规则添加到 local.rules 或自定义规则文件
            # 2. 建议先以 alert 模式运行观察误报率
            # 3. 确认无误报后可改为 drop 模式
            # 4. 配合 Unicode 归一化预处理器使用效果更佳
            #
            # ============================================================

        """)

        return header + "\n\n".join(rules) + "\n"

    def generate_modsecurity(self) -> str:
        """生成 ModSecurity WAF 规则"""
        return textwrap.dedent(f"""\
            # ============================================================
            # Ghost Bits Detection Rules for ModSecurity
            # Generated: {self.timestamp}
            # Reference: Black Hat Asia 2026 - Cast Attack: Ghost Bits
            # Author: 东方隐侠安全团队
            # ============================================================

            # 规则 1: 检测 %uXXXX 高密度编码
            SecRule REQUEST_URI|ARGS|REQUEST_BODY "(%u[0-9A-Fa-f]{{4}}){{3,}}" \\
                "id:9100001,\\
                phase:2,\\
                t:none,\\
                block,\\
                msg:'Ghost Bits: High density percent-u encoding detected',\\
                logdata:'Matched Data: %{{MATCHED_VAR}} found within %{{MATCHED_VAR_NAME}}',\\
                severity:'CRITICAL',\\
                tag:'attack-encoding',\\
                tag:'ghost-bits'"

            # 规则 2: Unicode 归一化后重新检测
            # 先对请求做 Unicode 解码，再匹配攻击签名
            SecRule REQUEST_URI|ARGS "@rx %u([0-9A-Fa-f]{{4}})" \\
                "id:9100002,\\
                phase:1,\\
                t:none,t:urlDecodeUni,\\
                pass,\\
                nolog,\\
                setvar:tx.ghost_bits_detected=1,\\
                tag:'ghost-bits-preprocess'"

            # 规则 3: 如果检测到 Ghost Bits 编码，对归一化后的内容做 SQL 注入检测
            SecRule TX:ghost_bits_detected "@eq 1" \\
                "id:9100003,\\
                phase:2,\\
                t:none,\\
                chain"
                SecRule ARGS "@rx (?i)(union|select|insert|update|delete|drop|exec|xp_)" \\
                    "t:urlDecodeUni,t:lowercase,\\
                    block,\\
                    msg:'Ghost Bits: SQL injection detected after Unicode normalization',\\
                    severity:'CRITICAL',\\
                    tag:'attack-sqli',\\
                    tag:'ghost-bits'"

            # 规则 4: Ghost Bits + 路径穿越
            SecRule TX:ghost_bits_detected "@eq 1" \\
                "id:9100004,\\
                phase:2,\\
                t:none,\\
                chain"
                SecRule REQUEST_URI "@rx (\\.\\.|/etc/|/proc/|WEB-INF)" \\
                    "t:urlDecodeUni,\\
                    block,\\
                    msg:'Ghost Bits: Path traversal detected after Unicode normalization',\\
                    severity:'CRITICAL',\\
                    tag:'attack-lfi',\\
                    tag:'ghost-bits'"

            # 规则 5: 请求中 CJK 字符异常密度
            SecRule REQUEST_URI|ARGS "@rx [\\x{{4e00}}-\\x{{9fff}}]{{5,}}" \\
                "id:9100005,\\
                phase:2,\\
                t:none,\\
                block,\\
                msg:'Ghost Bits: Abnormal CJK character density in request',\\
                severity:'WARNING',\\
                tag:'anomaly',\\
                tag:'ghost-bits'"
        """)

    def generate_regex(self) -> str:
        """生成正则表达式检测模式"""
        return textwrap.dedent(f"""\
            # ============================================================
            # Ghost Bits Detection Regex Patterns
            # Generated: {self.timestamp}
            # 适用于：日志分析、SIEM 规则、自定义检测脚本
            # ============================================================

            # --- 高置信度模式 ---

            # 1. 连续 %uXXXX 编码（高位非零，低位为可打印 ASCII）
            # 匹配：%u4F31%u5020%u6F6F%u7272
            GHOST_PERCENT_U = (%u[1-9A-Fa-f][0-9A-Fa-f](2[0-9]|3[0-9A-Fa-f]|4[0-9A-Fa-f]|5[0-9A-Fa-f]|6[0-9A-Fa-f]|7[0-9A-Ea-e])){{3,}}

            # 2. 连续 \\uXXXX 转义（同上逻辑）
            GHOST_UNICODE_ESCAPE = (\\\\u[1-9A-Fa-f][0-9A-Fa-f](2[0-9]|3[0-9A-Fa-f]|4[0-9A-Fa-f]|5[0-9A-Fa-f]|6[0-9A-Fa-f]|7[0-9A-Ea-e])){{3,}}

            # --- 中置信度模式 ---

            # 3. URL 路径中出现 CJK 字符
            CJK_IN_PATH = /[^?#]*[\\u4E00-\\u9FFF]{{2,}}[^?#]*/

            # 4. 混合编码：%uXXXX 和 %XX 同时出现
            MIXED_ENCODING = (%u[0-9A-Fa-f]{{4}}.*%[0-9A-Fa-f]{{2}})|(%[0-9A-Fa-f]{{2}}.*%u[0-9A-Fa-f]{{4}})

            # --- 辅助模式 ---

            # 5. 高 Unicode 字符密度异常（用于统计分析）
            # 如果一个 URL 参数中超过 50% 是 U+0100 以上字符，标记为可疑
            HIGH_UNICODE_DENSITY = [\\u0100-\\uFFFF]

            # --- 使用建议 ---
            # - 模式 1、2 可直接用于告警
            # - 模式 3、4 建议配合上下文判断（目标系统是否为中文站点）
            # - 模式 5 用于统计，设置阈值后告警
            # - 所有模式建议先在 alert 模式运行 7 天评估误报率
        """)

    def generate_yara(self) -> str:
        """生成 YARA 规则"""
        return textwrap.dedent(f"""\
            /*
             * Ghost Bits Detection YARA Rules
             * Generated: {self.timestamp}
             * Reference: Black Hat Asia 2026 - Cast Attack: Ghost Bits
             * Author: 东方隐侠安全团队
             *
             * 用途：扫描 HTTP 请求日志、pcap 提取内容、Web 日志文件
             */

            rule GhostBits_PercentU_Encoding {{
                meta:
                    description = "Detects Ghost Bits encoding using %uXXXX format"
                    author = "东方隐侠安全团队"
                    date = "{self.timestamp}"
                    severity = "high"
                    reference = "https://i.blackhat.com/Asia-26/Presentations/Asia-26-Bai-Cast-Attack-Ghost-Bits-4.23.pdf"

                strings:
                    // 连续 %uXXXX 编码，高位非零
                    $percent_u_seq = /(%u[1-9A-Fa-f][0-9A-Fa-f][2-7][0-9A-Fa-f]){{4,}}/

                    // 常见 Ghost Bits 攻击关键字的编码形式
                    $ghost_select = /(%u[0-9A-Fa-f]{{2}}(53|65|6C|45|43|54)){{6}}/ nocase
                    $ghost_union = /(%u[0-9A-Fa-f]{{2}}(55|4E|49|4F|4E)){{5}}/ nocase

                condition:
                    any of them
            }}

            rule GhostBits_UnicodeEscape_In_JSON {{
                meta:
                    description = "Detects Ghost Bits in JSON payloads using \\\\uXXXX escapes"
                    author = "东方隐侠安全团队"
                    date = "{self.timestamp}"
                    severity = "high"

                strings:
                    $json_start = "{{"
                    $at_type = "@type"
                    $unicode_seq = /(\\\\u[1-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f]{{2}}){{4,}}/

                condition:
                    $json_start and $at_type and $unicode_seq
            }}

            rule GhostBits_PathTraversal {{
                meta:
                    description = "Detects Ghost Bits encoded path traversal attempts"
                    author = "东方隐侠安全团队"
                    date = "{self.timestamp}"
                    severity = "critical"

                strings:
                    // %u 编码的 ".." 序列
                    $dotdot_percent = /(%u[0-9A-Fa-f]{{2}}2[Ee]){{2}}/
                    // 路径分隔符
                    $slash = "/"
                    // 敏感路径目标
                    $etc_passwd = "etc/passwd"
                    $web_inf = "WEB-INF"
                    $web_xml = "web.xml"

                condition:
                    $dotdot_percent and $slash and any of ($etc_passwd, $web_inf, $web_xml)
            }}
        """)

    def generate_all(self, format: str = "all") -> str:
        """生成所有格式的规则"""
        generators = {
            "snort": self.generate_snort,
            "modsecurity": self.generate_modsecurity,
            "regex": self.generate_regex,
            "yara": self.generate_yara,
        }

        if format == "all":
            sections = []
            for name, gen in generators.items():
                sections.append(f"\n{'#' * 70}\n# {name.upper()}\n{'#' * 70}\n")
                sections.append(gen())
            return "\n".join(sections)
        elif format in generators:
            return generators[format]()
        else:
            raise ValueError(
                f"Unknown format: {format}. Available: {list(generators.keys())}"
            )
