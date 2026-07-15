# 网络攻击检测系统 (NIDS)

基于特征匹配 + 异常行为分析的双引擎网络入侵检测系统，四模块架构，纯 Python + tkinter 实现。

---

## 一、系统架构

```
                       MessageBus (消息总线)
                              │
    ┌─────────────────────────┼──────────────────────────┐
    │                         │                          │
 [模块1]                    [模块2]                    [模块3]
 Capture                   SignatureEngine            AnomalyEngine
 抓包引擎                   特征匹配检测               异常行为检测
    │                         │                          │
    ▼                         ▼                          ▼
                  [模块4] GUI  统一告警展示 + 流量统计
```

---

## 二、快速启动

### 方式 A：一键启动（推荐，无需命令行）

| 操作 | 说明 |
|------|------|
| 双击 `一键启动.bat` | 菜单式选择 GUI / 自动抓包 / 模拟演示 / 测试 |
| 双击 `dist/NetworkAttackDetector.exe` | 直接打开 GUI 主界面 |

> exe 独立运行，无需安装 Python。

### 方式 B：命令行

```bash
# 模拟演示（无需管理员权限）
python tests/live_demo.py

# 实时抓包检测（需管理员 + Npcap）
python main.py --auto

# 离线 PCAP 分析
python main.py --pcap 文件路径.pcap --auto

# 普通 GUI 模式
python main.py

# 运行集成测试
python tests/quick_test.py
```

### 环境要求

| 依赖 | 用途 |
|------|------|
| Python 3.8+ | 运行环境 |
| Npcap / WinPcap | Windows 实时抓包（离线分析/演示无需） |
| tkinter | GUI（Python 内置，通常已安装） |

**无额外 pip 依赖**（除 scapy 用于在线抓包）。

---

## 三、功能特性

### 检测引擎

| 引擎 | 类型 | 检测能力 |
|------|------|---------|
| 模块2 特征匹配 | 已知攻击 | SQL注入、XSS、命令注入、路径遍历、LFI/RFI、WebShell、暴力破解、恶意C2、反弹Shell、DNS隧道、数据外泄等 20+ 种 |
| 模块3 异常检测 | 未知行为 | 端口扫描、DDoS、异常外联、行为突变（连接数/对端数/SYN比例）、带宽异常、横向扩散、攻击链 |

### GUI 功能

- **告警列表**：实时展示，按严重度着色，支持双击查看详情、右键标记状态/备注
- **流量列表**：显示通过检测的正常流量，支持协议着色
- **筛选栏**：IP/协议/端口三维组合筛选，带下拉建议
- **统计面板**：告警数、攻击类型分布、严重度分布
- **白名单管理**：添加后引擎自动静默，即时生效
- **导出报告**：HTML 分析报告（含分布图 + 明细表）、CSV/TXT 告警导出
- **流量下载**：双击流量行 → 详细弹窗 → 下载原始载荷（.bin/.json）
- **使用帮助**：帮助 → 使用帮助，5 标签页完整指引

---

## 四、项目结构

```
network_attack_detection/
├── main.py                    # 主入口（三模块串联 + 参数解析）
├── 一键启动.bat                # Windows 一键运行菜单
├── README.md                  # 本文件
├── .gitignore
│
├── common/                    # 公共基础设施
│   ├── config.py              # 全局配置（含检测阈值、白名单）
│   ├── data_structures.py     # 数据模型（TrafficRecord / Alert / Baseline）
│   ├── message_bus.py         # 发布-订阅消息总线
│   ├── engine.py              # 抽象接口（ABC）
│   └── utils.py               # 工具函数（日志/IP/配置管理）
│
├── module1_capture/           # 数据包捕获与预处理
│   ├── capture.py             # 抓包引擎（在线/离线/模拟）
│   ├── packet_parser.py       # 协议解析（HTTP/DNS/TLS/ICMP/ARP/SMB等）
│   └── demo_live_capture.py   # 在线抓包演示
│
├── module2_signature/         # 特征匹配检测引擎
│   ├── signature_engine.py    # 规则匹配（Snort 风格 + 正则）
│   ├── matcher.py             # 匹配器（协议/端口/载荷）
│   └── integration.py         # 集成接口
│
├── module3_anomaly/           # 异常行为检测引擎
│   └── anomaly_engine.py      # 端口扫描/DDoS/外联/突变/攻击链
│
├── module4_gui/               # 图形界面
│   └── main_window.py         # tkinter GUI（含筛选/导出/白名单/帮助）
│
├── tests/                     # 测试
│   ├── quick_test.py          # 集成测试（27项）
│   ├── live_demo.py           # 模拟演示
│   ├── test_module1.py        # 模块1 测试（32项）
│   └── test_module3.py        # 模块3 测试
│
├── data/                      # 数据文件
│   └── signatures.json        # 签名规则库
│
└── dist/                      # 构建产物
    └── NetworkAttackDetector.exe  # 独立可执行文件
```

---

## 五、配置说明

所有阈值在 `common/config.py` 中，分为两套：

| 配置 | 阈值 | 适用场景 |
|------|:---:|------|
| `ANOMALY_CONFIG` | 低 | tests/live_demo.py 等测试演示 |
| `REALTIME_ANOMALY_CONFIG` | 高 | main.py 真实环境抓包 |

白名单 `WHITELIST_IPS` 在 GUI 中「配置 → 白名单管理」操作，修改即时生效。

---

## 六、构建 exe

```bash
pip install pyinstaller
cd network_attack_detection
pyinstaller --onefile --noconsole --name "NetworkAttackDetector" main.py
# 产物: dist/NetworkAttackDetector.exe
```

---

## 七、常见问题

| 问题 | 回答 |
|------|------|
| 为什么大量误报？ | 真实环境中使用 main.py（高阈值），不要用 tests/live_demo.py（低阈值用于演示） |
| 无法打开 GUI？ | 确保 tkinter 可用：`python -c "import tkinter"` |
| 流量显示为空？ | 需要 Npcap + 管理员权限才能实时抓包；或使用 --pcap 离线分析 |
| 端口扫描误报？ | 将网关/DNS/打印机加入白名单 |
