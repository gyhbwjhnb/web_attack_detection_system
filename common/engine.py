"""
============================================================================
引擎抽象接口（ABC）
============================================================================
定义各模块的接口规范（抽象基类），使模块可独立开发并保证集成兼容。

各模块实现对应的接口类，然后挂载到 MessageBus 或 main.py 主控。

设计原则:
  - 接口只定义"做什么"，不定义"怎么做"
  - 每个接口只包含模块对外暴露的必要方法
  - 模块内部细节（用什么库、什么算法）完全黑盒

用法（以模块2为例）:
    from common.engine import ISignatureEngine
    from common.data_structures import TrafficRecord, Alert

    class MySignatureEngine(ISignatureEngine):
        def load_rules(self, rule_file=None):
            # 实现规则加载
            return len(self._rules)

        def process_traffic(self, record: TrafficRecord) -> list[Alert]:
            # 实现检测逻辑
            return alerts
============================================================================
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Callable
from common.data_structures import TrafficRecord, Alert, Baseline, AttackChain


# ==================== 模块1 接口：数据包捕获引擎 ====================

class ICaptureEngine(ABC):
    """
    数据包捕获与协议解析引擎接口

    职责:
      1. 从网卡 / PCAP 文件捕获网络数据包
      2. 解析 TCP/IP / HTTP / DNS / TLS 等协议
      3. 生成 TrafficRecord，通过回调或 MessageBus 输出

    生命周期:
      engine = MyCaptureEngine()
      engine.set_on_traffic_callback(my_handler)
      engine.start()
      # ... 运行 ...
      engine.stop()
    """

    @abstractmethod
    def start(self) -> bool:
        """
        启动数据包捕获。

        Returns:
            True 启动成功，False 失败
        """
        ...

    @abstractmethod
    def stop(self):
        """停止数据包捕获，清理资源"""
        ...

    @abstractmethod
    def set_on_traffic_callback(self, callback: Callable[[TrafficRecord], None]):
        """
        注册流量记录回调函数。
        每解析完一条流量，调用 callback(record)。
        """
        ...

    @abstractmethod
    def get_statistics(self) -> dict:
        """
        获取捕获统计信息。

        Returns:
            {
                "packet_count": int,     已捕获包总数
                "bytes_total": int,       总字节数
                "tcp_flows": int,         TCP 流数
                "udp_flows": int,         UDP 流数
                "protocols": dict,        协议分布 {"HTTP": 100, "DNS": 50}
                "start_time": float,      开始时间
                "running": bool,          是否运行中
            }
        """
        ...


# ==================== 模块2 接口：特征匹配检测引擎 ====================

class ISignatureEngine(ABC):
    """
    特征匹配检测引擎接口

    职责:
      1. 维护攻击特征库（规则）
      2. 接收 TrafficRecord，执行模式匹配
      3. 检测暴力破解行为
      4. 生成 Alert 通过回调或 MessageBus 输出

    生命周期:
      engine = MySignatureEngine()
      engine.load_rules()
      engine.set_on_alert_callback(my_handler)
      engine.process_traffic(record)    # 对每条流量调用
    """

    @abstractmethod
    def load_rules(self, rule_file: Optional[str] = None) -> int:
        """
        加载攻击特征规则。

        Args:
            rule_file: JSON 规则文件路径，None 使用默认路径

        Returns:
            成功加载的规则数量
        """
        ...

    @abstractmethod
    def process_traffic(self, record: TrafficRecord) -> List[Alert]:
        """
        处理一条流量记录，返回检测到的告警列表。

        Args:
            record: 模块1 输出的流量记录

        Returns:
            Alert 列表（可能为空）
        """
        ...

    @abstractmethod
    def set_on_alert_callback(self, callback: Callable[[Alert], None]):
        """注册告警回调。callback(alert)"""
        ...

    @abstractmethod
    def get_rule_count(self) -> int:
        """获取当前已加载的规则总数"""
        ...

    @abstractmethod
    def add_custom_rule(self, rule: dict) -> bool:
        """
        动态添加一条自定义规则。

        Args:
            rule: {"id": "CUSTOM-001", "name": "...", "pattern": "...", "severity": 4, ...}

        Returns:
            True 添加成功
        """
        ...

    @abstractmethod
    def remove_rule(self, rule_id: str) -> bool:
        """移除一条规则。True 成功"""
        ...

    @abstractmethod
    def enable_category(self, category: str, enabled: bool):
        """
        启用/禁用某类检测。

        Args:
            category: "sql_injection" / "xss" / "command_injection" / "web_attack" / "malware_c2" / "brute_force"
            enabled:  True 启用 / False 禁用
        """
        ...

    @abstractmethod
    def get_statistics(self) -> dict:
        """
        获取检测统计。

        Returns:
            {
                "total_alerts": int,      累计告警数
                "alerts_by_type": dict,   各攻击类型告警数
                "rules_loaded": int,      已加载规则数
                "traffic_processed": int, 已处理流量数
            }
        """
        ...


# ==================== 模块3 接口：异常行为检测引擎 ====================

class IAnomalyEngine(ABC):
    """
    异常行为检测引擎接口

    职责:
      1. 建立正常行为基线
      2. 检测偏离基线的异常行为
      3. ML 模型检测未知攻击（选做）
      4. 攻击链关联分析（选做）
      5. 误报降噪（选做）

    生命周期:
      engine = MyAnomalyEngine()
      engine.start_baseline_learning()
      engine.set_on_alert_callback(my_alert_handler)
      engine.process_traffic(record)    # 对每条流量调用
    """

    # ---- 基线 ----

    @abstractmethod
    def start_baseline_learning(self, duration: float = 3600):
        """
        开始基线学习阶段。

        Args:
            duration: 学习时长(秒)，默认 3600（1小时）。0 = 无限学习
        """
        ...

    @abstractmethod
    def get_baselines(self) -> List[Baseline]:
        """获取所有已建立的基线列表"""
        ...

    @abstractmethod
    def get_host_baseline(self, host_ip: str) -> Optional[Baseline]:
        """获取指定 IP 的基线"""
        ...

    # ---- 检测 ----

    @abstractmethod
    def process_traffic(self, record: TrafficRecord) -> List[Alert]:
        """
        处理流量记录，检测异常行为。

        Returns:
            异常告警列表
        """
        ...

    @abstractmethod
    def set_on_alert_callback(self, callback: Callable[[Alert], None]):
        """注册异常告警回调"""
        ...

    @abstractmethod
    def set_on_chain_callback(self, callback: Callable[[AttackChain], None]):
        """注册攻击链回调"""
        ...

    # ---- 攻击链（选做） ----

    def get_attack_chains(self) -> List[AttackChain]:
        """获取所有攻击链。选做功能，默认返回空列表"""
        return []

    def get_attack_chain(self, chain_id: str) -> Optional[AttackChain]:
        """获取指定 ID 的攻击链"""
        return None

    # ---- 统计 ----

    @abstractmethod
    def get_statistics(self) -> dict:
        """
        获取检测统计。

        Returns:
            {
                "baselines_established": int, 已建立基线数
                "anomaly_alerts": int,        累计异常告警数
                "chains_detected": int,       发现攻击链数
                "noise_reduced": int,         被降噪消除的告警数
            }
        """
        ...
