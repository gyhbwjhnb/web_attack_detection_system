# 网络攻击检测系统 (NIDS)

基于特征匹配 + 异常行为分析的双引擎网络入侵检测系统，四模块松耦合架构，纯 Python + tkinter 实现，插件化检测器 + 规则热加载 + 智能评分。

---

## 一、系统架构

```
                        MessageBus (消息总线)
                               │
     ┌─────────────────────────┼──────────────────────────┐
     │                         │                          │
  [模块1]                    [模块2]                    [模块3]
  Capture                   SignatureEngine            AnomalyEngine
  抓包引擎（3 种源）         特征匹配检测（20+ 类攻击）   异常行为检测（10 个插件）
     │                         │                          │
     │                         │              ┌───────┬───┴───┬───────┐
     │                         │        后处理阶段   置信度   时段  误报抑制
     │                         │
     ▼                         ▼                          ▼
                   [模块4] GUI 统一告警展示 + 流量统计 + 报告导出
```

---

## 二、快速启动

### 方式 A：一键启动（推荐）

| 操作 | 说明 |
|------|------|
| 双击 `一键启动.bat` | 菜单式选择 GUI / 自动抓包 / 模拟演示 / 测试 |
| 双击 `dist/NetworkAttackDetector.exe` | 直接打开 GUI 主界面（无需 Python） |

### 方式 B：命令行

```bash
# 模拟演示（无需管理员权限 + Npcap）
python tests/live_demo.py

# 智能特性测试（S6/S7/S8 功能验证）
python test_intelligence.py

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
| Npcap / WinPcap | Windows 实时抓包（离线分析/演示/test_intelligence.py 无需） |
| tkinter | GUI（Python 内置） |
| scapy | 在线抓包（`pip install scapy`） |

> 离线模式 / 模拟脚本只需 `scapy`，无其他第三方依赖。

---

## 三、功能特性

### 3.1 检测引擎能力

| 引擎 | 类型 | 检测范围 |
|------|------|---------|
| **模块2 特征匹配** | 已知攻击 | SQL注入、XSS、命令注入、路径遍历、LFI/RFI、WebShell（ASP/PHP/JSP）、一句话木马、CVE利用、反弹Shell、DNS隧道、Cobalt Strike Beacon、Shadowsocks协议、UPX壳PE文件、信息泄露（.env/phpinfo/swagger）、高危HTTP方法（PUT/DELETE）、恶意User-Agent、敏感路径扫描 等 20+ 种 |
| **模块3 异常检测** | 未知行为 | 端口扫描、暴力破解、异常外联、SYN Flood、带宽异常、行为突变（4维度）、横向扩散、C2 Beacon、异常时段活动 |
| **智能增强（v2.0）** | 告警优化 | 置信度动态评分（7 种攻击类型）、24h 时段基线 EMA、自学习误报抑制（跨会话持久化） |

### 3.2 检测器插件化

模块3 全部 10 个检测器均为独立插件（`module3_anomaly/detectors/` 下各自一个文件），继承 `IDetector` 接口，支持：

- **热插拔**：运行时 `add_detector()` / `remove_detector()` 即时生效
- **自注册**：新建文件 + 注册表加一行 → 自动注入上下文并排序
- **后处理阶段**：`post_process_batch()` 在全部检测器运行后统一处理告警

### 3.3 规则管理

| 功能 | 说明 |
|------|------|
| 规则文件 | `data/signatures.json`（主）+ `data/rules/` 目录（支持多文件） |
| 热加载 | `data/rules/` 下 JSON 文件变化 3 秒内自动重载，无需重启 |
| 导入规则 | GUI 工具栏 `📂 导入规则` 按钮 / 菜单「配置 → 导入自定义规则…」 |
| 规则格式 | 帮助 → 使用帮助 →「自定义规则」标签页完整参考 |

### 3.4 GUI 功能

- **告警列表**：实时展示，按严重度着色（蓝/绿/黄/橙/红），双击查看详情，右键标记状态/备注
- **流量列表**：显示通过检测的正常流量，按协议着色
- **筛选栏**：IP/协议/端口三维组合筛选，带下拉建议
- **统计面板**：告警总数、攻击类型分布、严重度分布、攻击链
- **置信度列**：每条告警的动态置信度评分（0.00-1.00）
- **白名单管理**：添加后引擎自动静默，即时生效
- **导出报告**：HTML 分析报告（含分布图 + 明细表）、CSV/TXT 告警导出
- **流量下载**：双击流量行 → 详细弹窗 → 下载原始载荷（.bin/.json）
- **使用帮助**：帮助 → 使用帮助，6 标签页（快速开始 / 界面指南 / 筛选与标记 / 白名单与配置 / 导出报告 / 自定义规则）

---

## 四、项目结构

```
network_attack_detection/
├── main.py                      # 主入口（四模块串联 + 参数解析）
├── test_intelligence.py         # 智能特性测试（S6/S7/S8 验证）
├── 一键启动.bat                  # Windows 一键运行菜单
├── README.md                    # 本文件
├── requirements.txt
├── .gitignore
│
├── common/                      # 公共基础设施
│   ├── config.py                # 全局配置（含检测阈值、20+ 攻击类型注册表）
│   ├── data_structures.py       # 数据模型（TrafficRecord / Alert / Baseline 等）
│   ├── message_bus.py           # 发布-订阅消息总线（6 个标准事件）
│   ├── detector.py              # ★ IDetector 插件接口（抽象基类）
│   ├── engine.py                # 模块抽象接口（ABC）
│   └── utils.py                 # 工具函数（日志/IP/配置管理）
│
├── module1_capture/             # 模块一：数据包捕获与预处理
│   ├── capture.py               # 抓包引擎（在线/离线/模拟 三种模式）
│   ├── packet_parser.py         # 协议解析（HTTP/DNS/TLS/ICMP/ARP...）
│   ├── demo_module1.py          # 功能演示（模拟/PCAP/MessageBus/性能）
│   └── demo_live_capture.py     # 在线抓包演示
│
├── module2_signature/           # 模块二：特征匹配检测引擎
│   ├── signature_engine.py      # 规则匹配 + 热加载 + 暴力破解统计 + 告警去重
│   ├── matcher.py               # Aho-Corasick 多模式匹配器（URL 解码对抗）
│   └── integration.py           # MessageBus 集成（一行 connect 完成订阅）
│
├── module3_anomaly/             # 模块三：异常行为检测引擎
│   ├── anomaly_engine.py        # 核心引擎（EMA 基线 + 滑动窗口 + 攻击链）
│   └── detectors/               # ★ 10 个检测器插件
│       ├── __init__.py          # 注册表（_ALL_DETECTORS）
│       ├── port_scan.py         # 端口扫描检测
│       ├── brute_force.py       # 暴力破解检测（敏感端口加分）
│       ├── abnormal_outbound.py # 异常外联检测
│       ├── lateral_movement.py  # 横向扩散检测（跨子网）
│       ├── syn_flood.py         # SYN Flood 检测
│       ├── bandwidth_anomaly.py # 带宽异常检测
│       ├── behavioral_deviation.py # 行为突变检测（4 维度）
│       ├── time_profile.py      # ★ 24h 异常时段检测（EMA 基线）
│       ├── confidence_scorer.py # ★ 置信度评分（后处理阶段）
│       └── suppression_learner.py # ★ 自学习误报抑制（跨会话持久化）
│
├── module4_gui/                 # 模块四：图形用户界面
│   └── main_window.py           # tkinter GUI（告警/流量表格 + 统计 + 导出 + 帮助）
│
├── tests/                       # 测试
│   ├── quick_test.py            # 快速集成测试
│   ├── live_demo.py             # 实机演示（模拟攻击 → GUI）
│   ├── check_env.py             # 环境检查
│   ├── test_module1.py          # 模块1 单元测试
│   ├── test_module2.py          # 模块2 单元测试
│   ├── test_module3.py          # 模块3 单元测试
│   └── test_protocol_fix.py     # 协议字段修复验证
│
├── data/                        # 数据文件
│   ├── signatures.json          # 攻击特征规则库（20+ 类）
│   └── rules/                   # ★ 热加载规则目录
│       └── signatures.json      # 规则副本（目录存在即启用热加载）
│
├── logs/                        # 日志输出
│
└── dist/                        # 构建产物
    └── NetworkAttackDetector.exe  # 独立可执行文件（PyInstaller 打包）
```

---

## 五、配置说明

所有阈值在 `common/config.py` 中，分为两套：

| 配置 | 阈值 | 适用场景 |
|------|:---:|------|
| `ANOMALY_CONFIG` | 低 | tests/live_demo.py / test_intelligence.py 等测试演示 |
| `REALTIME_ANOMALY_CONFIG` | 高 | main.py 真实环境抓包 |

### 可调参数（GUI 菜单 → 检测阈值设置）

| 参数 | 默认（测试/真实） | 说明 |
|------|:---:|------|
| port_scan_threshold | 3 / 20 | 时间窗口内的不同目标端口数 |
| brute_force_threshold | 3 / 8 | 敏感端口连接次数 |
| syn_flood_threshold | 50 / 500 | 时间窗口内 SYN 包数 |
| bandwidth_upper_factor | 3.0 / 4.0 | 触发带宽告警的基线倍数 |
| behavior_mutation_factor | 2.5 / 3.0 | 行为突变标准差倍数 |

### 白名单

菜单「配置 → 白名单管理…」即时操作，添加后引擎自动忽略该 IP 的所有告警（流量仍正常统计更新基线）。

---

## 六、扩展开发

### 新增检测器（4 步）

```
1. 在 module3_anomaly/detectors/ 新建 my_detector.py
2. class MyDetector(IDetector):
       name = "my_detector"
       priority = 35
       def process(self, record, now) -> List[Alert]: ...
3. 在 detectors/__init__.py 的 _ALL_DETECTORS 加 MyDetector()
4. 重启 → 自动注入上下文，按 priority 排序执行
```

不改 `anomaly_engine.py`，不改 `process_traffic()`。

### 新增自定义规则（JSON）

在 `data/rules/` 下放置 `.json` 文件，3 秒内自动生效。格式参考帮助 → 自定义规则标签页。

---

## 七、构建 exe

```bash
pip install pyinstaller
cd network_attack_detection
pyinstaller NetworkAttackDetector.spec --clean
# 产物: dist/NetworkAttackDetector.exe
```

---

## 八、常见问题

| 问题 | 回答 |
|------|------|
| 为什么大量误报？ | 真实环境用 main.py（高阈值），别用 tests/live_demo.py（低阈值演示用） |
| 无法打开 GUI？ | `python -c "import tkinter"` 检查 |
| 流量显示为空？ | 需要 Npcap + 管理员权限实时抓包；或使用 --pcap 离线分析 |
| 端口扫描误报？ | 将网关/DNS/打印机加入白名单 |
| 导入规则没反应？ | 检查 JSON 格式，控制台会打印"检测到规则变更，已重新加载 N 条规则" |
| 告警有 confidence 列吗？ | v2.0 新增，需确保主程序已更新到最新版本 |
