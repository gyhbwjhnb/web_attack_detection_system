"""
网络攻击检测系统 (NIDS) - 公共模块

提供所有子模块共享的基础设施：
  - config.py        : 全局配置参数 + 攻击类型注册表
  - data_structures.py : 统一数据模型 (TrafficRecord / Alert / Baseline / AttackChain / SignatureRule)
  - message_bus.py   : 发布-订阅消息总线
  - engine.py        : 各模块抽象接口 (ABC)
  - utils.py         : 工具函数 (日志 / ConfigManager / IP工具)

用法示例:
    from common import (
        TrafficRecord, Alert, message_bus,
        ICaptureEngine, ISignatureEngine,
        CAPTURE_CONFIG, ATTACK_TYPES, SEVERITY_LEVELS,
        setup_logger, ConfigManager,
    )
"""

from common.config import (
    SYSTEM_CONFIG, CAPTURE_CONFIG, SIGNATURE_CONFIG,
    ANOMALY_CONFIG, UI_CONFIG,
    SEVERITY_LEVELS, ATTACK_TYPES, PRIVATE_IP_RANGES,
    load_config_from_file, get_config, get_attack_info,
)

from common.data_structures import (
    ProtocolType, AlertSeverity, AlertType, AlertStatus,
    IPEndpoint, TrafficRecord, PacketInfo,
    Alert, Baseline, AttackChain, SignatureRule,
    is_private_ip,
)

from common.message_bus import (
    MessageBus, message_bus,
)

from common.engine import (
    ICaptureEngine, ISignatureEngine, IAnomalyEngine,
)

from common.detector import (
    IDetector,
)

from common.utils import (
    setup_logger, ConfigManager,
    ip_to_int, format_timestamp,
)

__all__ = [
    # 配置
    "SYSTEM_CONFIG", "CAPTURE_CONFIG", "SIGNATURE_CONFIG",
    "ANOMALY_CONFIG", "UI_CONFIG",
    "SEVERITY_LEVELS", "ATTACK_TYPES", "PRIVATE_IP_RANGES",
    "load_config_from_file", "get_config", "get_attack_info",
    # 数据模型
    "ProtocolType", "AlertSeverity", "AlertType", "AlertStatus",
    "IPEndpoint", "TrafficRecord", "PacketInfo",
    "Alert", "Baseline", "AttackChain", "SignatureRule",
    "is_private_ip",
    # 消息总线
    "MessageBus", "message_bus",
    # 引擎接口
    "ICaptureEngine", "ISignatureEngine", "IAnomalyEngine",
    # 检测器插件接口
    "IDetector",
    # 工具函数
    "setup_logger", "ConfigManager",
    "ip_to_int", "format_timestamp",
]
