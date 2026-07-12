# 模块一：数据包捕获与预处理

---

## 一、模块定位

```
                         ┌──────────────┐
                         │   网络流量     │
                         │  (网卡/PCAP)  │
                         └──────┬───────┘
                                │
                   ┌────────────▼────────────┐
                   │    模块一：数据包捕获     │
                   │    与预处理（本模块）      │
                   │                          │
                   │  capture.py ──┬─ 在线抓包  │
                   │               └─ 离线PCAP  │
                   │  packet_parser.py          │
                   │      ↓ 协议解析            │
                   │  TrafficRecord 结构化输出   │
                   └────────────┬──────────────┘
                                │
            ┌───────────────────┼───────────────────┐
            ▼                   ▼                   ▼
      ┌──────────┐      ┌────────────┐      ┌──────────┐
      │ 模块二    │      │ 模块三      │      │ 模块四    │
      │ 特征匹配  │      │ 异常检测    │      │ GUI/日志  │
      └──────────┘      └────────────┘      └──────────┘
```

模块一是 NIDS 系统的数据入口，其工作流程如下：

```
 在线模式:  网卡 ──→ BPF过滤 ──→ sniff() ──→ parse_packet() ──→ TrafficRecord ──→ 回调 / MessageBus
 离线模式:  PCAP文件 ──→ rdpcap() ──→ parse_packet() ──→ TrafficRecord ──→ 回调 / MessageBus
 模拟数据:  create_fake_*_record() ──→ TrafficRecord（纯内存构造，无需网卡/scapy）
```

---

## 二、文件架构

```
module1_capture/
├── README.md              ← 本文档
├── __init__.py            ← 统一导出接口
├── capture.py             ← 抓包引擎（有状态，管理生命周期）
├── packet_parser.py       ← 协议解析（无状态纯函数）
├── demo_module1.py        ← 一站式功能演示脚本（模拟数据 + PCAP离线解析）
└── demo_live_capture.py   ← 在线抓包演示脚本（需管理员权限 + Npcap）

外部依赖（模块一运行时必需）：
  common/
  ├── __init__.py           ← 公共模块统一导出
  ├── config.py             ← 配置常量、PRIVATE_IP_RANGES
  ├── data_structures.py    ← TrafficRecord / Alert 等核心数据模型
  ├── engine.py             ← ICaptureEngine 抽象接口
  ├── message_bus.py        ← 发布-订阅消息总线
  └── utils.py              ← 日志、配置管理器、IP工具

测试：
  tests/test_module1.py     ← 32 项自动化单元测试
```

---

## 三、数据流全景

### 3.1 完整的数据包处理管线

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        parse_packet() 解析管线                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  原始 scapy 包                                                          │
│       │                                                                 │
│       ▼                                                                 │
│  ┌─────────┐    有IP层?                                                  │
│  │ 检查 IP  ├─── 否 ──→ 返回 None（ARP等非IP包跳过）                       │
│  └────┬────┘                                                            │
│       │ 是                                                              │
│       ▼                                                                 │
│  ┌──────────┐                                                           │
│  │ 初始化    │  new TrafficRecord()                                      │
│  │ Traffic   │                                                          │
│  │ Record    │                                                          │
│  └────┬─────┘                                                           │
│       │                                                                 │
│       ▼                                                                 │
│  ┌──────────────┐                                                       │
│  │ 解析以太网层  │  _parse_ethernet()  →  src.mac, dst.mac                │
│  └──────┬───────┘                                                       │
│         ▼                                                               │
│  ┌──────────────┐                                                       │
│  │ 解析IP层      │  _parse_ip()  →  src.ip, dst.ip, 协议类型(TCP/UDP/ICMP)│
│  └──────┬───────┘                                                       │
│         ▼                                                               │
│  ┌──────────────┐                                                       │
│  │ 解析传输层    │  _parse_transport()                                    │
│  │              │  → TCP: src.port, dst.port, flags(如0x018=PSH+ACK)    │
│  │              │  → UDP: src.port, dst.port                             │
│  │              │  → ICMP: 仅标记协议类型                                 │
│  └──────┬───────┘                                                       │
│         ▼                                                               │
│  ┌──────────────┐                                                       │
│  │ 提取载荷      │  _parse_payload()  →  payload(文本), payload_raw(字节)  │
│  └──────┬───────┘  （最大64KB，超长截断）                                  │
│         ▼                                                               │
│  ┌──────────────────────┐                                                │
│  │ 检测应用层协议        │  _detect_application_protocol()                  │
│  │                      │                                                │
│  │  检查载荷内容 ──┬── HTTP?  ──→ _parse_http(): 提取方法/URI/Host/Body   │
│  │                │                                                      │
│  │                ├── 端口53? ──→ _parse_dns():  提取查询域名/类型        │
│  │                │                                                      │
│  │                ├── TLS标记?──→ _detect_tls(): 提取版本号              │
│  │                │                                                      │
│  │                └── 22/21/25 端口 ──→ SSH/FTP/SMTP 端口标记             │
│  └──────────────────────┘                                                │
│         ▼                                                               │
│  ┌──────────────┐                                                       │
│  │ 生成流ID      │  五元组: "src.ip:port-dst.ip:port-TCP/UDP"             │
│  └──────┬───────┘                                                       │
│         ▼                                                               │
│  ┌──────────────┐                                                       │
│  │ 返回           │  TrafficRecord 实例（含全部解析结果）                    │
│  └──────────────┘                                                       │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.2 数据输出路径

```
parse_packet() 返回 TrafficRecord
       │
       ▼
CaptureEngine._handle_packet()
       │
       ├──→ 更新统计信息（包数、字节数、流数、协议分布）
       │
       └──→ _dispatch(record)
                │
                ├──→ 遍历所有注册的回调函数（set_on_traffic_callback 注册）
                │       回调函数可任意多个，按注册顺序执行
                │
                └──→ MessageBus.publish("traffic_record", record)
                        （use_message_bus=True 时自动发布）
                               │
                               ├──→ 模块二订阅者收到 → 特征匹配检测
                               └──→ 模块三订阅者收到 → 异常行为检测
```

---

## 四、代码详解

### 4.1 `capture.py` — 抓包引擎

```
CaptureEngine(ICaptureEngine)
│
├── 状态字段
│   ├── _running: bool          ← 引擎是否正在运行
│   ├── _sniff_thread: Thread   ← 抓包工作线程（在线模式）
│   └── _stop_sniff: Event      ← 停止信号，通知线程退出
│
├── 统计字段
│   ├── _packet_count: int      ← 已捕获包总数
│   ├── _byte_total: int        ← 总字节数
│   ├── _tcp_flows: set()       ← TCP 流集合（去重）
│   ├── _udp_flows: set()       ← UDP 流集合（去重）
│   ├── _protocol_count: dict   ← {协议名: 数量} 分布
│   └── _error_count: int       ← 处理异常数
│
├── 回调系统
│   └── _on_traffic_callbacks: []  ← 回调函数列表，支持多个
│
└── 消息总线
    └── _use_message_bus: bool  ← 是否自动发布到 MessageBus
```

**核心方法详解：**

#### `start()` — 启动捕获

```python
def start(self, interface=None, filter_expr="", offline_pcap=None, ...) -> bool:
```

**工作流程：**

```
start() 被调用
    │
    ├── 检查 _running，已在运行则返回 False
    │
    ├── offline_pcap 不为 None?
    │    ├── 是 → 检查文件是否存在
    │    │         ├── 不存在 → 返回 False
    │    │         └── 存在 → 同步解析：rdpcap → _handle_packet 逐个处理
    │    │                   完成后 _running 自动置 False
    │    │                   返回 True
    │    └── 否 → 进入在线模式
    │
    ├── 在线模式:
    │    ├── 尝试 import scapy → 失败则返回 False
    │    ├── interface 为 None? → 调用 _auto_select_interface()
    │    │                              └── 找不到网卡 → 返回 False
    │    ├── 设置 _running = True
    │    ├── 创建后台线程运行 _sniff_worker()
    │    │    └── sniff(iface=interface, filter=filter_expr,
    │    │              prn=_handle_packet, store=False)
    │    │        每抓到一包 → _handle_packet() → parse_packet() → _dispatch()
    │    └── 返回 True
    │
    └── 注意：在线模式下 start() 立即返回，抓包在后台线程持续进行
```

**两种模式对比：**

| 特性 | 在线模式 | 离线模式 |
|------|---------|---------|
| 数据源 | 物理网卡 | PCAP 文件 |
| 所需权限 | 管理员/root | 普通用户 |
| 必需驱动 | Npcap(Windows) / LibPcap(Linux) | 无 |
| 运行方式 | 异步（后台线程） | 同步（阻塞直到读完） |
| 停止方式 | `stop()` 设置 Event 通知线程退出 | 自动停止 |
| 适用场景 | 真实环境监控 | 开发调试、重现历史流量 |

#### `stop()` — 停止捕获

```python
def stop(self):
    if not self._running:
        return                    # 未运行则直接返回，不抛异常
    self._stop_sniff.set()        # 设置停止标志
    self._running = False
    if self._sniff_thread and self._sniff_thread.is_alive():
        self._sniff_thread.join(timeout=3.0)  # 等线程最多3秒
```

#### `_handle_packet()` — 单包处理核心

```python
def _handle_packet(self, packet):
    # 1. 检查停止标志
    if self._stop_sniff.is_set():
        return

    # 2. 解析：将 scapy 包转为 TrafficRecord
    record = parse_packet(packet)
    if record is None:
        return                    # 非 IP 包跳过

    # 3. 更新统计
    self._packet_count += 1
    self._byte_total += len(packet)
    self._protocol_count[proto] += 1
    # TCP/UDP 流去重

    # 4. 分发
    self._dispatch(record)
```

#### `_auto_select_interface()` — 自动选网卡

```
get_working_ifaces()
    │
    ├── 遍历可用网卡
    │    ├── 优先选有 IP、非回环、非 lo 的网卡
    │    └── 兜底：返回第一个
    │
    └── 异常/无网卡 → 返回 None
```

### 4.2 `packet_parser.py` — 协议解析

**设计原则**：全部是纯函数，无状态，输入 scapy 包输出 `TrafficRecord`，解析失败不抛异常。

#### `parse_packet()` — 主入口

```python
def parse_packet(packet) -> Optional[TrafficRecord]:
```

```
输入: scapy 包对象（来自 sniff() 或 rdpcap()）
输出: TrafficRecord 实例，或 None（非 IP 包/解析失败）

关键逻辑:
  1. 先检查 packet.haslayer("IP") 或 haslayer("IPv6")
     └─ 都没有 → 返回 None（跳过 ARP、PPPoE 等）
  2. 逐层解析
  3. 最后生成流 ID
```

#### HTTP 解析详解

```python
def _parse_http(record: TrafficRecord):
    # 1. 取第一行判断是请求还是响应
    #    请求: "GET /index.php?id=1 HTTP/1.1"
    #    响应: "HTTP/1.1 200 OK"

    # 2. 解析请求行 → method, uri（自动 URL 解码）, protocol_detail

    # 3. 逐行解析请求头
    #    "Host: example.com"  → http_host
    #    "User-Agent: xxx"    → http_user_agent
    #    "Referer: xxx"       → http_referer（URL 解码）
    #    其他头部 → http_headers 字典

    # 4. 空行之后取请求体 → http_body
```

**关键技巧：URL 解码**

```python
from urllib.parse import unquote

# 原始 URI: "/search%3Fq%3Dtest%2Bvalue"
# 解码后:  "/search?q=test+value"
record.http_uri = unquote(parts[1])
```

#### DNS 解析详解

```python
def _parse_dns(record: TrafficRecord):
    # 直接从原始字节 payload_raw 中解析

    # DNS 头部 12 字节: ID(2) + flags(2) + qdcount(2) + ...
    qdcount = (raw[4] << 8) | raw[5]  # 查询数量

    # 从第 13 字节开始解析域名
    # 域名编码: 3www7example3com0 → www.example.com
    offset = 12
    while offset < len(raw):
        length = raw[offset]
        if length == 0: break          # 结束符
        if length & 0xC0:              # 压缩指针
            offset += 2; break
        part = raw[offset+1:offset+1+length]
        domain_parts.append(part.decode("ascii"))
        offset += length + 1

    record.dns_query = ".".join(domain_parts)
```

#### `create_fake_http_record()` — 测试辅助函数

```python
def create_fake_http_record(method="GET", uri="/index.php?id=1",
                            host="example.com", body="", ...) -> TrafficRecord:
    """纯内存构造 TrafficRecord，不涉及任何网络操作"""
    # 1. 构造 HTTP 协议字符串
    payload_str = f"{method} {uri} HTTP/1.1\r\nHost: {host}\r\n...\r\n{body}"

    # 2. new TrafficRecord() 并填充字段
    record = TrafficRecord()
    record.src = IPEndpoint(ip=src_ip, port=src_port)
    record.dst = IPEndpoint(ip=dst_ip, port=dst_port)
    record.protocol = ProtocolType.TCP
    record.payload = payload_str
    record.payload_raw = payload_str.encode("utf-8")
    record.http_method = method
    record.http_uri = uri
    record.http_host = host
    record.flags = 0x18  # PSH + ACK

    # 3. 生成流 ID
    record.flow_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-TCP"

    return record
```

**为什么这个函数重要？** 模块二/三/四在开发阶段不需要真实的网络流量，用这个函数就能生成任意 HTTP 请求供测试——包括含 SQL 注入、XSS 等攻击特征的请求。

### 4.3 常见协议的特征码速查

| 协议 | 端口 | 载荷特征 | 解析依据 |
|------|------|---------|---------|
| HTTP 请求 | 任意 | 以 `GET/POST/PUT...` 开头 | `payload.split()[0] in HTTP_METHODS` |
| HTTP 响应 | 任意 | 以 `HTTP/` 开头 | `payload.startswith("HTTP/")` |
| DNS | 53 | DNS 头部格式 | 原始字节逐字节解析域名 |
| TLS | 443(常见) | 首字节 `0x16`(Handshake) | `raw[0] == 0x16` |
| SSH | 22 | 端口标记 | `dst.port == 22` |
| FTP | 21 | 端口标记 | `dst.port == 21` |

---

## 五、测试方法

### 方式一：运行演示脚本（推荐先看效果）

**离线演示（无需权限/Pcap）：**
```bash
cd web_attack_detection_system
python module1_capture/demo_module1.py
```

```
demo_module1.py 执行流程：

┌──────────────────────────────────────────────────────────────────┐
│ 第1部分: 模拟数据                                                │
│  ├── create_fake_http_record()  → 打印完整字段（GET/POST各一个）   │
│  ├── create_fake_dns_record()   → 打印完整字段                     │
│  └── 模拟含 SQL注入的恶意请求 → 展示 URI 中的攻击特征                │
│  特点: 无需网卡/scapy/权限，纯内存构造                              │
├──────────────────────────────────────────────────────────────────┤
│ 第2部分: PCAP 生成 + 离线解析                                     │
│  ├── scapy 构造 7 个包（HTTP GET/HTTP 200/HTTP POST含注入/        │
│  │           SYN扫描x3/DNS查询）                                   │
│  ├── wrpcap() 保存为 data/test/demo_test.pcap                    │
│  └── CaptureEngine 离线解析 → 逐个打印 TrafficRecord 完整字段      │
│  特点: PCAP文件可用 Wireshark 打开对比                             │
├──────────────────────────────────────────────────────────────────┤
│ 第3部分: MessageBus 数据流                                        │
│  ├── 注册 2 个订阅者分别展示不同维度的处理                          │
│  ├── 发布 3 条消息 → 观察订阅者输出                                │
│  └── 查看总线统计（消息数、订阅者数、事件类型）                      │
├──────────────────────────────────────────────────────────────────┤
│ 第4部分: 原始 scapy 包解析                                        │
│  ├── 用 MockScapyPacket + MockIP/TCP/Raw 模拟完整 scapy 包       │
│  ├── 验证 HTTP query 参数自动解析（?debug=true&cmd=whoami）       │
│  ├── 验证 all_http_text 合并文本                                  │
│  └── 验证非 IP 包返回 None                                        │
├──────────────────────────────────────────────────────────────────┤
│ 第5部分: 批量性能测试                                             │
│  ├── 构造 1000 个 HTTP 模拟包                                     │
│  └── parse_packets() 批量解析 → 统计耗时/速率                     │
│  预期: 1000包 < 0.5秒（实测约 0.008秒）                           │
└──────────────────────────────────────────────────────────────────┘
```

```bash
cd web_attack_detection_system
python module1_capture/demo_module1.py
```

### 方式二：运行自动化单元测试

```bash
pip install pytest
pytest tests/test_module1.py -v           # 全部 32 项

# 分类运行
pytest tests/test_module1.py -v -k "TestPacketParser"    # 协议解析 13 项
pytest tests/test_module1.py -v -k "TestCaptureEngine"   # 引擎 7 项
pytest tests/test_module1.py -v -k "TestPerformance"     # 性能 1 项
```

测试覆盖：HTTP GET/POST/响应/编码、DNS查询、TLS检测、SYN包标志、非IP跳过、空载荷/二进制/Unicode边界、引擎状态/回调/离线读取/多回调/接口回退、引擎-解析器集成、批量解析、配置兼容性。

### 方式三：快速验证（复制即用）

```python
# 1. 模拟数据（最快，无需任何依赖）
from module1_capture import create_fake_http_record, create_fake_dns_record
r = create_fake_http_record(method="GET", uri="/test?id=1", host="demo.com")
print(f"HTTP: {r.http_method} {r.http_uri} → {r.http_host}  [{r.protocol.value}]")

d = create_fake_dns_record(query="evil.c2.com", query_type="A")
print(f"DNS: {d.dns_query} ({d.dns_query_type}) → {d.dst.ip}:{d.dst.port}")

# 2. 离线解析 PCAP
from module1_capture import CaptureEngine
records = []
engine = CaptureEngine(use_message_bus=False)
engine.set_on_traffic_callback(lambda r: records.append(r))
engine.start(offline_pcap="data/test/demo_test.pcap")  # 上一步生成的
print(f"PCAP 解析了 {len(records)} 个包")
for r in records[:3]:
    print(f"  {r.protocol.value}: {r.src.ip}:{r.src.port} → {r.dst.ip}:{r.dst.port}")
```

### 方式四：在线抓包（需管理员权限 + Npcap）

```bash
# Windows: 以管理员身份运行终端
# Linux: sudo python

# 运行在线抓包演示脚本（含网卡列表、自动/手动选择、多网卡参考）
python module1_capture/demo_live_capture.py
```

该脚本会依次展示：

  1. 列出系统所有可用网卡（含类型标签和 IP）
  2. 自动选择最优物理网卡抓包
  3. 手动指定网卡抓包（可选）
  4. 多网卡综合抓包参考代码

**快捷验证（一行命令）：**

```bash
python -c "
from module1_capture import CaptureEngine
engine = CaptureEngine()
engine.set_on_traffic_callback(lambda r: print(r))
engine.start(interface=None, filter_expr='tcp', packet_count=4)
input('抓包中，按 Enter 停止...\n')
engine.stop()
"
```

---

## 六、TrafficRecord 字段速查

```python
record.id              # str  唯一标识（12位hex）
record.timestamp       # float  时间戳
record.protocol        # ProtocolType  TCP/UDP/HTTP/DNS/TLS/ICMP...
record.protocol_detail # str  协议详情如 "HTTP/1.1"
record.src.ip          # str  源IP地址
record.src.port        # int  源端口
record.dst.ip          # str  目的IP地址
record.dst.port        # int  目的端口
record.src.mac         # str  源MAC（在线抓包时捕获）
record.dst.mac         # str  目的MAC
record.flags           # int  TCP标志位（0x02=SYN, 0x10=ACK, 0x18=PSH+ACK）
record.flow_id         # str  五元组流ID
record.payload         # str  文本载荷（UTF-8解码）
record.payload_raw     # bytes  原始字节载荷
record.payload_size    # int  载荷长度

# HTTP 字段（仅 HTTP 协议时有值）
record.http_method     # str  GET/POST/RESPONSE
record.http_uri        # str  请求URI（已URL解码）
record.http_host       # str  Host头
record.http_headers    # dict  所有HTTP头
record.http_body       # str  请求/响应体
record.http_status_code # int  响应状态码
record.http_referer    # str  Referer头
record.http_user_agent # str  User-Agent头

# DNS 字段（仅 DNS 协议时有值）
record.dns_query       # str  查询域名
record.dns_query_type  # str  A/AAAA/MX/TXT...

# TLS 字段（仅 TLS 协议时有值）
record.tls_version     # str  TLS 1.2 / TLS 1.3
```

---

## 七、常见问题

| 问题 | 回答 |
|------|------|
| 模块一需要哪些 Python 包？ | `scapy`（抓包/解析PCAP），`pytest`（测试） |
| 一定要安装 Npcap 吗？ | 只有**在线抓包**需要。纯离线 PCAP 解析和模拟数据不需要 |
| 为什么抓包要管理员权限？ | 原始套接字操作需要系统级权限。Windows 需管理员，Linux 需 sudo |
| 解析结果为零怎么办？ | 检查 PCAP 中是否包含 IP 包（ARP/PPPoE 等非 IP 包会被 `parse_packet` 跳过） |
| 能解析 HTTPS 内容吗？ | 不能。HTTPS 是加密的，模块一只检测到 TLS 握手，无法解密应用层数据 |
| 如何关闭 MessageBus？ | `CaptureEngine(use_message_bus=False)` |
| `to_dict()` 报错 FlagValue？ | 已修复：scapy 的 TCP flags 类型在序列化时自动转为 int |
