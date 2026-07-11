# common 公共模块说明

本目录是整个 NIDS 项目的**公共基础设施层**。它不包含任何检测逻辑，只定义了所有模块共享的"约定"——数据长什么样、接口长什么样、怎么通信。



---

## 文件结构

```
common/
├── __init__.py           # 包入口，统一导出所有公开内容
├── config.py             # 全局配置参数 + 攻击类型注册表
├── data_structures.py    # 统一数据模型（TrafficRecord / Alert / Baseline / AttackChain / SignatureRule）
├── message_bus.py        # 发布-订阅消息总线（MessageBus）
├── engine.py             # 各模块抽象接口（ABC）
├── utils.py              # 工具函数（Logger / ConfigManager / IP 工具）
└── README.md             # 本文件
```

---

## 一、config.py —— 全局配置 + 攻击类型注册表

### 1.1 配置块一览

| 配置块 | 说明 | 使用者 |
|--------|------|--------|
| `SYSTEM_CONFIG` | 系统名称、版本、日志级别 | 所有人 |
| `CAPTURE_CONFIG` | 抓包网卡、BPF 过滤、混杂模式、流重组、离线 PCAP | 模块1 |
| `SIGNATURE_CONFIG` | 各类攻击检测开关、暴力破解阈值、告警去重、特征文件路径 | 模块2 |
| `ANOMALY_CONFIG` | 基线学习周期、异常检测阈值、TLS 检测、ML 参数、攻击链配置 | 模块3 |
| `UI_CONFIG` | GUI 窗口参数、刷新间隔、日志格式、数据库路径 | 模块4 |
| `SEVERITY_LEVELS` | 告警严重度 1~5 的中文名与色值 | 所有人 |
| `ATTACK_TYPES` | 22 种攻击类型的统一定义（名称/分类/默认严重度） | 模块2/3/4 |
| `PRIVATE_IP_RANGES` | 内网 IP 起止范围 | 模块3（异常外联判断） |

### 1.2 SEVERITY_LEVELS 详细定义

| 数值 | 枚举值 | 中文名 | 色值 | 含义 |
|------|--------|--------|------|------|
| 1 | `INFO` | 信息 | `#1890ff` | 普通信息类通知 |
| 2 | `LOW` | 低危 | `#52c41a` | 低风险可疑行为 |
| 3 | `MEDIUM` | 中危 | `#faad14` | 疑似攻击 |
| 4 | `HIGH` | 高危 | `#fa8c16` | 确认攻击 |
| 5 | `CRITICAL` | 严重 | `#f5222d` | 正在进行的入侵 |

### 1.3 ATTACK_TYPES 完整列表

| key | 中文名 | 分类 | 默认严重度 |
|-----|--------|------|-----------|
| `sql_injection` | SQL注入 | web | 5 |
| `xss` | XSS跨站脚本 | web | 4 |
| `command_injection` | 命令注入 | web | 5 |
| `path_traversal` | 路径遍历 | web | 4 |
| `lfi` | 本地文件包含(LFI) | web | 5 |
| `rfi` | 远程文件包含(RFI) | web | 5 |
| `webshell` | WebShell后门 | web | 5 |
| `brute_force` | 暴力破解 | auth | 4 |
| `login_anomaly` | 登录异常 | auth | 3 |
| `port_scan` | 端口扫描 | recon | 2 |
| `malware_c2` | 恶意C2通信 | malware | 5 |
| `reverse_shell` | 反弹Shell | malware | 5 |
| `dns_tunnel` | DNS隧道 | malware | 4 |
| `lateral_movement` | 横向扩散 | lateral | 5 |
| `data_exfil` | 数据外泄 | exfil | 5 |
| `ddos` | DDoS攻击 | dos | 5 |
| `tls_anomaly` | TLS异常 | crypto | 4 |
| `unknown_anomaly` | 未知异常行为 | anomaly | 3 |
| `ml_anomaly` | ML检测异常流量 | anomaly | 3 |
| `abnormal_outbound` | 异常外联 | anomaly | 4 |

### 1.4 使用方式

```python
from common.config import (
    CAPTURE_CONFIG, SIGNATURE_CONFIG, ANOMALY_CONFIG,
    ATTACK_TYPES, SEVERITY_LEVELS,
    get_attack_info, load_config_from_file, get_config,
)

# 读各模块配置
bpf = CAPTURE_CONFIG["bpf_filter"]
threshold = SIGNATURE_CONFIG["brute_force_threshold"]
window = ANOMALY_CONFIG["port_scan_window_sec"]

# 查攻击类型信息
info = ATTACK_TYPES["sql_injection"]
# {"name": "SQL注入", "category": "web", "default_severity": 5}

info = get_attack_info("unknown_key")   # 不存在时返回安全默认值，不会抛异常
# {"name": "unknown_key", "category": "unknown", "default_severity": 3}

# 从 JSON 文件覆盖默认配置
load_config_from_file("my_config.json")

# 导出所有配置（调试用）
all_cfg = get_config()
```

### 1.5 PRIVATE_IP_RANGES 的格式

```python
PRIVATE_IP_RANGES = [
    ("10.0.0.0",     "10.255.255.255"),
    ("172.16.0.0",   "172.31.255.255"),
    ("192.168.0.0",  "192.168.255.255"),
    ("127.0.0.0",    "127.255.255.255"),
]
```

---

## 二、data_structures.py —— 统一数据模型

### 2.1 数据流

```
模块1(抓包)                    模块2/3(检测)                   模块4(UI)
    │                               │                             │
    ▼                               ▼                             ▲
TrafficRecord ──────────────▶ Alert ─────────────────────────▶ 展示
                      ┌──────▶ Baseline ─────────────────────▶ 基线查看
                      └──────▶ AttackChain ──────────────────▶ 攻击链视图
            SignatureRule ──▶ 模块2 加载使用
```

### 2.2 枚举类型

| 枚举 | 可选值 |
|------|--------|
| `ProtocolType` | `TCP`, `UDP`, `HTTP`, `HTTPS`, `DNS`, `TLS`, `ICMP`, `SSH`, `FTP`, `SMTP`, `UNKNOWN` |
| `AlertSeverity` | `INFO=1`, `LOW=2`, `MEDIUM=3`, `HIGH=4`, `CRITICAL=5` |
| `AlertType` | `SIGNATURE`（模块2）, `ANOMALY`（模块3）, `ML`（模块3 扩展） |
| `AlertStatus` | `NEW`, `CONFIRMED`, `FALSE_POSITIVE`, `RESOLVED`, `IGNORED` |

### 2.3 IPEndpoint —— IP 端点

```python
from common import IPEndpoint

src = IPEndpoint(ip="192.168.1.100", port=54321, mac="aa:bb:cc:dd:ee:ff")
src.is_internal   # True（自动判断是否内网）
src.to_dict()     # {"ip": "...", "port": ..., "mac": "...", "is_internal": True}
```

### 2.4 TrafficRecord —— 流量记录（旧名 PacketInfo）

> `PacketInfo` 仍保留作为 `TrafficRecord` 的别名，兼容旧代码。

**模块1 产出，模块2/3 消费。**

```python
from common import TrafficRecord, ProtocolType, IPEndpoint

record = TrafficRecord()
record.src = IPEndpoint(ip="192.168.1.100", port=54321)
record.dst = IPEndpoint(ip="10.0.0.1", port=80)
record.protocol = ProtocolType.HTTP
record.payload = "GET /index.php?id=1' OR '1'='1 HTTP/1.1"
# 模块1 应填充以下 HTTP 字段：
record.http_method = "GET"
record.http_uri = "/index.php?id=1' OR '1'='1"
record.http_host = "10.0.0.1"
record.http_user_agent = "Mozilla/5.0 ..."
print(record)
# TrafficRecord(id=a1b2c3d4e5f6, 192.168.1.100:54321 -> 10.0.0.1:80, HTTP)
```

**关键属性和方法（模块2/3 会用到的）：**

| 字段/属性 | 类型 | 说明 |
|-----------|------|------|
| `id` | `str` | 12 位 UUID 唯一标识 |
| `timestamp` | `float` | Unix 时间戳 |
| `src` / `dst` | `IPEndpoint` | 通信双方（`.ip` / `.port` / `.mac` / `.is_internal`） |
| `protocol` | `ProtocolType` | 协议枚举 |
| `payload` | `str` | UTF-8 解码后的载荷文本——**直接用于特征匹配** |
| `payload_raw` | `bytes` | 原始字节（`repr=False`，打印时隐藏） |
| `http_method` / `http_uri` / `http_host` | `str` | HTTP 请求行 |
| `http_headers` | `Dict[str,str]` | HTTP 头部字典 |
| `http_body` | `str` | HTTP 消息体 |
| `http_referer` / `http_user_agent` | `str` | Referer 和 User-Agent |
| `http_query_params` | **属性** → `Dict[str,str]` | 自动解析 `http_uri` 中的 `?k=v&k=v` 为字典 |
| `all_http_text` | **属性** → `str` | 拼接 URI/body/headers/referer/ua，方便**一次性多模式扫描** |
| `dns_query` / `dns_query_type` / `dns_answers` | 对应类型 | DNS 查询名、类型和应答列表 |
| `tls_sni` / `tls_ja3_hash` / `tls_cipher_suite` | `str` | TLS 指纹信息（用于 C2/TLS 异常检测） |
| `tls_is_self_signed` | `bool` | 证书是否自签名 |
| `flags` / `seq_num` / `ack_num` | `int` | TCP 标志位掩码 |
| `is_syn()` / `is_syn_ack()` | → `bool` | TCP flags 快速判断 |
| `flow_id` / `flow_bytes_sent` / `flow_bytes_received` | 对应类型 | 五元组 hash / 流统计 |
| `to_dict()` / `to_json()` | → `dict` / `str` | 序列化（`payload_raw` 不会输出） |

### 2.5 Alert —— 告警记录

**模块2/3 产出，模块4 消费。**

```python
from common import Alert, AlertSeverity, AlertType, AlertStatus

alert = Alert(
    attack_type="sql_injection",
    attack_name="SQL注入 - 联合查询",
    severity=AlertSeverity.CRITICAL,
    confidence=0.95,
    alert_source=AlertType.SIGNATURE,
    rule_id="SQL-001",
    src_ip="192.168.1.100",
    dst_ip="10.0.0.1",
    title="检测到 SQL 注入攻击",
    description="在 HTTP 请求中检测到经典 OR 1=1 注入模式",
    matched_pattern="' OR '1'='1",
    payload_snippet="GET /index.php?id=1' OR '1'='1 HTTP/1.1",
    suggestion="建议检查 Web 应用输入过滤，部署 WAF",
)
```

**全部字段：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `alert_id` | `str` | 12 位 UUID 唯一标识 |
| `timestamp` | `float` | 告警时间戳 |
| `attack_type` | `str` | 攻击标识，对应 `ATTACK_TYPES` 的 key（如 `"sql_injection"`） |
| `attack_name` | `str` | UI 展示用名称（如 `"SQL注入 - 联合查询"`） |
| `severity` | `AlertSeverity` | 1~5 严重度枚举 |
| `confidence` | `float` | 置信度 0.0~1.0 |
| `status` | `AlertStatus` | 处理状态：NEW / CONFIRMED / FALSE_POSITIVE / RESOLVED / IGNORED |
| `alert_source` | `AlertType` | 来源：SIGNATURE / ANOMALY / ML |
| `rule_id` | `str` | 触发的特征规则 ID（特征匹配时有效） |
| `src_ip` / `src_port` / `dst_ip` / `dst_port` | `str`/`int` | 网络五元组 |
| `title` / `description` | `str` | 告警标题和详细描述 |
| `matched_pattern` | `str` | 匹配到的攻击特征 |
| `payload_snippet` | `str` | 触发告警的载荷片段（UI 展示用） |
| `suggestion` | `str` | 处理建议 |
| `to_dict()` | → `dict` | 返回字典（枚举值已转为字符串） |
| `to_json()` | → `str` | JSON 字符串 |
| `to_csv_line()` | → `str` | CSV 格式行，逗号分隔 |

### 2.6 SignatureRule —— 攻击特征规则

**模块2 从 JSON 特征库加载使用。**

```python
from common import SignatureRule

# 从 JSON 字典创建
rule = SignatureRule.from_dict({
    "rule_id": "SQL-001",
    "attack_name": "SQL注入 - OR 1=1",
    "attack_type": "sql_injection",
    "pattern": r"(?i)('|\").*?\bOR\b.*?=?.*?\1",
    "severity": 4,
    "description": "检测经典 OR 1=1 SQL注入绕过尝试",
    "protocol": "TCP",
    "dst_port": 0,          # 0 = 不限端口
})
```

### 2.7 Baseline —— 主机行为基线（模块3）

```python
from common import Baseline

baseline = Baseline(host_ip="192.168.1.100")
baseline.conn_avg_per_min = 45.2
baseline.unique_ports = 12
baseline.bw_avg = 1024000.0
baseline.sample_count = 500
baseline.is_established()   # True（sample_count >= 100）
```

**关键字段：** `host_ip`, `conn_avg_per_min`, `conn_max_per_min`, `conn_std_per_min`, `unique_ports`, `common_ports`, `bw_avg`, `bw_max`, `session_duration_avg`, `internal_peers`, `external_peers`, `internal_ratio`, `sample_count`, `is_established()`。

### 2.8 AttackChain —— 攻击链（模块3 选做）

将零散的告警串联为完整攻击过程：`侦察 → 武器化 → 投递 → 利用 → 安装 → C2 → 目标达成`。

```python
from common import AttackChain

chain = AttackChain(title="针对 10.0.0.1 的 Web 攻击链")
chain.add_stage("recon", "alert-001", "端口扫描发现 80 开放")
chain.add_stage("exploitation", "alert-005", "SQL 注入尝试成功")
chain.phase_count       # 2
chain.coverage          # 0.2857（2/7）
chain.check_complete()  # True（覆盖了 recon + exploitation 两个关键阶段）
```

---

## 三、message_bus.py —— 消息总线（发布-订阅）

基于发布-订阅模式实现模块间**完全解耦**通信。各模块只关心自己发布和订阅的事件，不需要知道其他模块的存在。

### 3.1 核心概念

```python
from common import message_bus, TrafficRecord, Alert

# ==== 模块1：发布流量记录 ====
message_bus.publish("traffic_record", record)

# ==== 模块2：订阅流量 + 发布告警 ====
def handle_traffic(record: TrafficRecord):
    alerts = engine.process_traffic(record)
    for alert in alerts:
        message_bus.publish("signature_alert", alert)

message_bus.subscribe("traffic_record", handle_traffic)

# ==== 模块4：订阅告警 ====
def handle_alert(alert: Alert):
    gui.add_alert(alert)

message_bus.subscribe("signature_alert", handle_alert)
message_bus.subscribe("anomaly_alert", handle_alert)
```

### 3.2 标准事件名

| 事件常量 | 事件名 | 载荷类型 | 流向 |
|----------|--------|----------|------|
| `message_bus.EVENT_TRAFFIC_RECORD` | `"traffic_record"` | `TrafficRecord` | 模块1 → 模块2/3 |
| `message_bus.EVENT_SIGNATURE_ALERT` | `"signature_alert"` | `Alert` | 模块2 → 模块4 |
| `message_bus.EVENT_ANOMALY_ALERT` | `"anomaly_alert"` | `Alert` | 模块3 → 模块4 |
| `message_bus.EVENT_ATTACK_CHAIN` | `"attack_chain"` | `AttackChain` | 模块3 → 模块4 |
| `message_bus.EVENT_STATISTICS` | `"statistics"` | `dict` | 模块1/2/3 → 模块4 |
| `message_bus.EVENT_CONFIG_CHANGE` | `"config_change"` | `dict` | 模块4 → 模块1/2/3 |

> 推荐使用 `message_bus.EVENT_TRAFFIC_RECORD` 等常量，避免字符串拼写错误。

### 3.3 全部 API

| 方法 | 说明 |
|------|------|
| `subscribe(event_type, callback)` | 订阅事件，同一 callback 不会重复注册 |
| `unsubscribe(event_type, callback)` | 取消订阅 |
| `publish(event_type, data)` | 发布事件，通知所有订阅者（异常会被捕获记录日志） |
| `subscriber_count(event_type=None)` | 查询订阅者数，不传参返回全部订阅总数 |
| `get_statistics()` | 返回 `{"message_counts": {...}, "total_subscribers": ..., "event_types": [...]}` |
| `reset_statistics()` | 重置消息计数器 |

### 3.4 消息总线本身也是全局单例

```python
from common import message_bus

# 所有模块导入的 message_bus 是同一个实例
message_bus.get_statistics()
```

---

## 四、engine.py —— 抽象接口（ABC）

定义三个模块的**方法签名契约**。**强烈建议各模块类继承对应接口**，IDE 会自动提示需要实现哪些方法。

### 4.1 ICaptureEngine（模块1）

| 方法 | 返回值 | 说明 |
|------|--------|------|
| `start()` | `bool` | 启动抓包，返回是否成功 |
| `stop()` | - | 停止抓包，清理资源 |
| `set_on_traffic_callback(callback)` | - | 注册回调：`callback(TrafficRecord)` |
| `get_statistics()` | `dict` | 返回 `{packet_count, bytes_total, tcp_flows, udp_flows, protocols, start_time, running}` |

### 4.2 ISignatureEngine（模块2）

| 方法 | 返回值 | 说明 |
|------|--------|------|
| `load_rules(rule_file=None)` | `int` | 加载特征规则，返回规则数 |
| `process_traffic(record)` | `List[Alert]` | 检测一条流量，返回告警列表 |
| `set_on_alert_callback(callback)` | - | 注册告警回调：`callback(Alert)` |
| `get_rule_count()` | `int` | 已加载规则总数 |
| `add_custom_rule(rule_dict)` | `bool` | 动态添加自定义规则 |
| `remove_rule(rule_id)` | `bool` | 移除规则 |
| `enable_category(category, enabled)` | - | 启用/禁用某类检测（如 `"sql_injection"`） |
| `get_statistics()` | `dict` | 返回 `{total_alerts, alerts_by_type, rules_loaded, traffic_processed}` |

### 4.3 IAnomalyEngine（模块3）

| 方法 | 返回值 | 说明 |
|------|--------|------|
| `start_baseline_learning(duration=3600)` | - | 开始基线学习（秒，0=无限） |
| `get_baselines()` | `List[Baseline]` | 获取所有基线 |
| `get_host_baseline(host_ip)` | `Optional[Baseline]` | 获取指定 IP 基线 |
| `process_traffic(record)` | `List[Alert]` | 检测异常，返回告警列表 |
| `set_on_alert_callback(callback)` | - | 注册异常告警回调 |
| `set_on_chain_callback(callback)` | - | 注册攻击链回调 |
| `get_attack_chains()` | `List[AttackChain]` | 获取所有攻击链（选做，有默认实现） |
| `get_attack_chain(chain_id)` | `Optional[AttackChain]` | 获取指定攻击链（选做，有默认实现） |
| `get_statistics()` | `dict` | 返回 `{baselines_established, anomaly_alerts, chains_detected, noise_reduced}` |

### 4.4 使用示例

```python
from common.engine import ISignatureEngine
from common import TrafficRecord, Alert

class MySignatureEngine(ISignatureEngine):
    def load_rules(self, rule_file=None):
        return len(self._rules)

    def process_traffic(self, record: TrafficRecord) -> list[Alert]:
        # 对 record.payload / record.all_http_text 做特征匹配
        return alerts

    # ... IDE 会提示需要实现其余抽象方法
```

---

## 五、utils.py —— 工具函数

| 工具 | 说明 |
|------|------|
| `setup_logger(name, log_file, level, log_to_console)` → `Logger` | 创建统一日志器，重复调用同名不会重复添加 handler |
| `ConfigManager(config_path)` | JSON 配置管理器，支持 `get("a.b.c")` 点号多级键、`set`、`save` |
| `is_private_ip(ip)` → `bool` | 判断是否内网 IP（统一使用 `config.py` 的 `PRIVATE_IP_RANGES`） |
| `ip_to_int(ip)` → `int` | IP 字符串转 32 位整数 |
| `format_timestamp(datetime)` → `str` | 格式化为 `"2026-07-10 10:30:00.123"` |
| `AlertIdGenerator.next_id()` → `int` | 全局自增整数 ID（未在 `__init__.py` 中导出，需从 `common.utils` 导入） |

---

## 六、统一导入方式

**推荐：全部从 `common` 包一行导入**，无需记子模块路径。

```python
from common import (
    # 配置
    SYSTEM_CONFIG, CAPTURE_CONFIG, SIGNATURE_CONFIG,
    ANOMALY_CONFIG, UI_CONFIG,
    SEVERITY_LEVELS, ATTACK_TYPES, PRIVATE_IP_RANGES,
    load_config_from_file, get_config, get_attack_info,
    # 数据模型
    ProtocolType, AlertSeverity, AlertType, AlertStatus,
    IPEndpoint, TrafficRecord, PacketInfo,       # PacketInfo 是 TrafficRecord 的别名
    Alert, Baseline, AttackChain, SignatureRule,
    is_private_ip,
    # 消息总线
    MessageBus, message_bus,
    # 引擎接口
    ICaptureEngine, ISignatureEngine, IAnomalyEngine,
    # 工具函数
    setup_logger, ConfigManager,
    ip_to_int, format_timestamp,
)
```

---

## 七、各模块开发规范

### 模块1（数据包捕获与预处理）

1. 继承 `ICaptureEngine` 接口
2. 每解析完一条流量，创建 `TrafficRecord`，填充尽可能多的字段（尤其是 HTTP/DNS/TLS）
3. 通过 `message_bus.publish("traffic_record", record)` 发布
4. 或使用 `set_on_traffic_callback()` 回调方式输出
5. `get_statistics()` 返回包数/字节数/协议分布等实时统计

### 模块2（特征匹配检测引擎）

1. 继承 `ISignatureEngine` 接口
2. `load_rules()` 中从 `data/signatures.json` 加载规则，用 `SignatureRule.from_dict()` 解析
3. `process_traffic(record)` 中扫描 `record.all_http_text` 或 `record.payload`
4. 生成 `Alert` 时：`alert_source=AlertType.SIGNATURE`，`attack_type` 填 `ATTACK_TYPES` 中的 key
5. 通过 `message_bus.publish("signature_alert", alert)` 发布告警

### 模块3（异常行为检测引擎）

1. 继承 `IAnomalyEngine` 接口
2. `start_baseline_learning()` 收集正常流量，建立各主机的 `Baseline`
3. `process_traffic(record)` 对比基线和各阈值判断异常
4. 生成 `Alert` 时：`alert_source=AlertType.ANOMALY`
5. 异常告警 → `message_bus.publish("anomaly_alert", alert)`
6. 攻击链 → `message_bus.publish("attack_chain", chain)`（选做）
7. 使用 `record.src.is_internal` / `record.dst.is_internal` 判断内外网

### 模块4（告警输出与图形界面）

1. 订阅 `"signature_alert"` 和 `"anomaly_alert"` 事件
2. 实时展示告警列表（参考 `Alert.to_dict()` 确定表格列）
3. 写入告警日志文件（`Alert.to_csv_line()` 或 `Alert.to_json()`）
4. 订阅 `"statistics"` 事件展示实时统计
5. 提供配置面板，修改时发布 `message_bus.publish("config_change", ...)`

---

## 八、快速验证

在项目根目录（`network_attack_detection/`）下创建 `test_common.py` 运行：

```python
import sys
sys.path.insert(0, ".")

from common import (
    TrafficRecord, Alert, AlertSeverity, AlertType, AlertStatus,
    Baseline, AttackChain, SignatureRule,
    IPEndpoint, ProtocolType,
    message_bus, ISignatureEngine,
    CAPTURE_CONFIG, SIGNATURE_CONFIG, ATTACK_TYPES, SEVERITY_LEVELS,
    load_config_from_file, get_attack_info,
    setup_logger, ConfigManager, is_private_ip, format_timestamp,
)

# ========== 1. 创建 TrafficRecord ==========
record = TrafficRecord()
record.src = IPEndpoint(ip="192.168.1.100", port=54321)
record.dst = IPEndpoint(ip="10.0.0.1", port=80)
record.protocol = ProtocolType.HTTP
record.payload = "GET /index.php?id=1' OR '1'='1 HTTP/1.1"
record.http_method = "GET"
record.http_uri = "/index.php?id=1' OR '1'='1"
print(record)
# TrafficRecord(id=a1b2..., 192.168.1.100:54321 -> 10.0.0.1:80, HTTP)

# ========== 2. 创建 Alert ==========
alert = Alert(
    attack_type="sql_injection",
    attack_name="SQL注入测试",
    severity=AlertSeverity.CRITICAL,
    confidence=0.95,
    alert_source=AlertType.SIGNATURE,
    rule_id="SQL-001",
    src_ip="192.168.1.100", dst_ip="10.0.0.1",
    title="测试 SQL 注入告警",
    payload_snippet="id=1' OR '1'='1",
)
print(alert.to_dict())

# ========== 3. 测试 MessageBus ==========
alerts_received = []

def on_alert(a):
    alerts_received.append(a)
    print(f"  -> 收到告警: {a.attack_name} (severity={a.severity.value})")

message_bus.subscribe("signature_alert", on_alert)
message_bus.publish("signature_alert", alert)
assert len(alerts_received) == 1, "MessageBus 失败"

# 取消订阅后不再收到
message_bus.unsubscribe("signature_alert", on_alert)
message_bus.publish("signature_alert", alert)
assert len(alerts_received) == 1, "unsubscribe 失败"

# ========== 4. 配置和攻击类型 ==========
assert SIGNATURE_CONFIG["brute_force_threshold"] == 10
assert get_attack_info("xss")["default_severity"] == 4
assert get_attack_info("unknown")["default_severity"] == 3   # 安全默认值

# ========== 5. IP 判断 ==========
assert is_private_ip("192.168.1.1") == True
assert is_private_ip("8.8.8.8") == False
ep = IPEndpoint(ip="10.0.0.5")
assert ep.is_internal == True

# ========== 6. Baseline ==========
bl = Baseline(host_ip="192.168.1.100", sample_count=50)
assert bl.is_established() == False
bl.sample_count = 200
assert bl.is_established() == True

# ========== 7. AttackChain ==========
chain = AttackChain(title="测试攻击链")
chain.add_stage("recon", "a-001", "端口扫描")
chain.add_stage("exploitation", "a-005", "SQL 注入")
assert chain.phase_count == 2
assert chain.check_complete() == True

# ========== 8. SignatureRule ==========
rule = SignatureRule.from_dict({"rule_id": "R1", "pattern": "test", "severity": 3})
assert rule.rule_id == "R1"

# ========== 9. Logger ==========
logger = setup_logger("test", log_to_console=False)
logger.info("common 模块测试通过")

# ========== 10. 枚举值 ==========
assert AlertSeverity.CRITICAL.value == 5
assert AlertType.SIGNATURE.value == "signature"
assert AlertStatus.NEW.value == "new"
assert ProtocolType.HTTP.value == "HTTP"

print("\n=== common 模块全部验证通过 ===")
```
