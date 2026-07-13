"""
============================================================================
全局配置模块
============================================================================
所有子模块通过此模块获取统一配置参数与攻击类型定义。

- 各模块默认配置块（CAPTURE_CONFIG / SIGNATURE_CONFIG / ANOMALY_CONFIG / UI_CONFIG）
- 告警严重度定义（SEVERITY_LEVELS）
- 攻击类型注册表（ATTACK_TYPES）
- 内网 IP 范围（PRIVATE_IP_RANGES）

用法:
    from common.config import CAPTURE_CONFIG, ATTACK_TYPES, SEVERITY_LEVELS

    # 从 JSON 文件覆盖默认值
    from common.config import load_config_from_file
    load_config_from_file("my_config.json")
============================================================================
"""

import os
import json


# ==================== 系统基础配置 ====================

SYSTEM_CONFIG = {
    "name": "常见网络攻击检测系统 (NIDS)",
    "version": "1.0.0",
    "log_level": "INFO",
    "log_file": "logs/nids.log",
    "data_dir": "data/",
}


# ==================== 模块1：数据包捕获配置 ====================

CAPTURE_CONFIG = {
    "interface": None,              # None = 自动选择网卡，或指定如 "eth0"
    "offline_pcap": None,           # 离线 PCAP 文件路径，不为 None 时优先使用
    "bpf_filter": "",               # BPF 过滤规则，如 "tcp port 80 or tcp port 443"
    "snapshot_len": 65535,          # 抓包快照长度
    "promiscuous": True,            # 混杂模式
    "timeout_ms": 1000,             # 超时(毫秒)
    "packet_count": 0,              # 0 = 持续抓包，>0 = 抓指定数量后停止
    "enable_flow_reassembly": True, # TCP 流重组
    "flow_timeout": 120,            # 流超时(秒)
}


# ==================== 模块2：特征匹配检测配置 ====================

SIGNATURE_CONFIG = {
    "enable_sql_injection":     True,
    "enable_xss":               True,
    "enable_command_injection": True,
    "enable_web_attack":        True,
    "enable_malware_c2":        True,
    "enable_brute_force":       True,
    "brute_force_threshold": 10,     # N 秒内失败登录次数阈值
    "brute_force_window": 60,        # 检测时间窗口(秒)
    "alert_dedup_window": 300,       # 同源目+攻击类型去重窗口(秒)
    "rules_file": "data/signatures.json",
}


# ==================== 模块3：异常行为检测配置 ====================

ANOMALY_CONFIG = {
    "baseline_learning_period": 3600,    # 基线学习周期(秒)
    "baseline_update_interval": 300,     # 基线更新间隔(秒)
    "conn_rate_threshold": 3.0,          # 连接速率异常倍数
    "port_scan_threshold": 50,           # 端口扫描阈值(60s内不同端口数)
    "port_scan_window_sec": 10,
    "login_anomaly_threshold": 20,       # 登录异常阈值
    "brute_force_threshold": 10,
    "brute_force_window_sec": 5,
    "syn_flood_threshold": 100,
    "syn_flood_window_sec": 1,
    "bandwidth_anomaly_threshold": 5.0,  # 带宽异常倍数
    "session_duration_max": 7200,        # 会话时长上限(秒)
    "enable_tls_detection": True,
    "weak_ciphers": ["RC4", "DES", "3DES", "EXPORT", "NULL", "anon"],
    "enable_ml_detection": False,        # 是否启用 ML（选做）
    "ml_model_path": "data/models/ml_model.pkl",
    "enable_attack_chain": False,        # 是否启用攻击链（选做）
    "chain_time_window": 600,
    "enable_noise_reduction": True,
    "noise_min_severity": 3,
    "internal_networks": ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"],
    # ---- 行为突变检测 ----
    "mutation_conn_ratio": 10.0,           # 连接数突变倍数阈值
    "mutation_conn_min": 100,              # 连接数突变的绝对最小值
    "mutation_peer_ratio": 10.0,           # 对端数突变倍数阈值
    "mutation_peer_min": 50,              # 对端数突变绝对最小值
    "mutation_syn_ratio": 8.0,            # SYN 比例异常倍数
    "mutation_syn_min": 100,              # SYN 比例异常绝对最小值
}

# ==================== 真实环境配置（降低误报率） ====================

REALTIME_ANOMALY_CONFIG = {
    **ANOMALY_CONFIG,
    "conn_rate_threshold": 10.0,           # 连接速率异常倍数（3→10）
    "port_scan_threshold": 500,            # 端口扫描阈值（50→500）
    "port_scan_window_sec": 60,            # 窗口扩大到 60s
    "brute_force_threshold": 50,           # 暴力破解阈值（10→50）
    "brute_force_window_sec": 30,          # 窗口（5→30s）
    "syn_flood_threshold": 5000,           # SYN Flood 阈值（100→5000）
    "syn_flood_window_sec": 5,             # 窗口（1→5s）
    "bandwidth_anomaly_threshold": 30.0,   # 带宽异常倍数（5→30x）
    "enable_noise_reduction": True,
    "noise_min_severity": 4,              # 只显示高危及以上（3→4）
    # ---- 行为突变检测 ----
    "mutation_conn_ratio": 20.0,           # 连接数突变倍数（10→20）
    "mutation_conn_min": 200,              # 连接数突变最小绝对值
    "mutation_peer_ratio": 20.0,           # 对端数突变倍数（10→20）
    "mutation_peer_min": 100,             # 对端数突变最小绝对值
    "mutation_syn_ratio": 15.0,           # SYN 比例异常倍数（8→15）
    "mutation_syn_min": 300,              # SYN 比例异常最小绝对值
}


# ==================== 模块4：GUI 配置 ====================

UI_CONFIG = {
    "window_title": "网络攻击检测系统",
    "window_width": 1200,
    "window_height": 800,
    "refresh_interval": 2,              # 界面刷新间隔(秒)
    "max_alerts_display": 1000,         # 界面最多展示告警数
    "alert_log_file": "logs/alerts.log",
    "alert_log_format": "csv",          # csv / json
    "db_path": "data/alerts.db",        # SQLite 告警存储路径（选做）
}


# ==================== 告警严重度定义 ====================

SEVERITY_LEVELS = {
    1: {"name": "信息",   "color": "#1890ff"},
    2: {"name": "低危",   "color": "#52c41a"},
    3: {"name": "中危",   "color": "#faad14"},
    4: {"name": "高危",   "color": "#fa8c16"},
    5: {"name": "严重",   "color": "#f5222d"},
}


# ==================== 攻击类型定义 ====================

ATTACK_TYPES = {
    # --- Web 类 ---
    "sql_injection":        {"name": "SQL注入",             "category": "web",     "default_severity": 5},
    "xss":                  {"name": "XSS跨站脚本",         "category": "web",     "default_severity": 4},
    "command_injection":    {"name": "命令注入",            "category": "web",     "default_severity": 5},
    "path_traversal":       {"name": "路径遍历",            "category": "web",     "default_severity": 4},
    "lfi":                  {"name": "本地文件包含(LFI)",    "category": "web",     "default_severity": 5},
    "rfi":                  {"name": "远程文件包含(RFI)",    "category": "web",     "default_severity": 5},
    "webshell":             {"name": "WebShell后门",        "category": "web",     "default_severity": 5},

    # --- 认证类 ---
    "brute_force":          {"name": "暴力破解",            "category": "auth",    "default_severity": 4},

    # --- 侦察类 ---
    "port_scan":            {"name": "端口扫描",            "category": "recon",   "default_severity": 2},

    # --- 恶意软件类 ---
    "malware_c2":           {"name": "恶意C2通信",          "category": "malware", "default_severity": 5},
    "reverse_shell":        {"name": "反弹Shell",           "category": "malware", "default_severity": 5},
    "dns_tunnel":           {"name": "DNS隧道",             "category": "malware", "default_severity": 4},

    # --- 横向移动 ---
    "lateral_movement":     {"name": "横向扩散",            "category": "lateral", "default_severity": 5},

    # --- 数据外泄 ---
    "data_exfil":           {"name": "数据外泄",            "category": "exfil",   "default_severity": 5},

    # --- 拒绝服务 ---
    "ddos":                 {"name": "DDoS攻击",            "category": "dos",     "default_severity": 5},

    # --- 加密类 ---
    "tls_anomaly":          {"name": "TLS异常",             "category": "crypto",  "default_severity": 4},

    # --- 通用异常 ---
    "unknown_anomaly":      {"name": "未知异常行为",         "category": "anomaly", "default_severity": 3},
    "ml_anomaly":           {"name": "ML检测异常流量",       "category": "anomaly", "default_severity": 3},

    # --- 异常外联 ---
    "abnormal_outbound":    {"name": "异常外联",            "category": "anomaly", "default_severity": 4},

    # --- 登录异常 ---
    "login_anomaly":        {"name": "登录异常",            "category": "auth",    "default_severity": 3},
}


# ==================== 内网 IP 范围 ====================

PRIVATE_IP_RANGES = [
    ("10.0.0.0",     "10.255.255.255"),
    ("172.16.0.0",   "172.31.255.255"),
    ("192.168.0.0",  "192.168.255.255"),
    ("127.0.0.0",    "127.255.255.255"),
]


# ==================== 工具函数 ====================

def load_config_from_file(filepath: str):
    """
    从 JSON 文件加载自定义配置，覆盖默认值。

    JSON 文件格式示例:
    {
        "CAPTURE_CONFIG": { "interface": "eth0", "bpf_filter": "tcp port 80" },
        "SIGNATURE_CONFIG": { "enable_xss": false }
    }
    """
    if not os.path.exists(filepath):
        print(f"[Config] 配置文件不存在: {filepath}")
        return

    with open(filepath, "r", encoding="utf-8") as f:
        user_config = json.load(f)

    for key in ["SYSTEM_CONFIG", "CAPTURE_CONFIG", "SIGNATURE_CONFIG",
                "ANOMALY_CONFIG", "UI_CONFIG"]:
        if key in user_config and key in globals():
            globals()[key].update(user_config[key])

    print(f"[Config] 已加载自定义配置: {filepath}")


def get_config() -> dict:
    """返回全部配置的合并视图，方便调试"""
    return {
        "system":   SYSTEM_CONFIG,
        "capture":  CAPTURE_CONFIG,
        "signature": SIGNATURE_CONFIG,
        "anomaly":  ANOMALY_CONFIG,
        "ui":       UI_CONFIG,
        "severity": SEVERITY_LEVELS,
    }


def get_attack_info(attack_type: str) -> dict:
    """根据攻击类型标识获取攻击信息（名称、分类、默认严重度）"""
    return ATTACK_TYPES.get(attack_type, {
        "name": attack_type,
        "category": "unknown",
        "default_severity": 3,
    })
