"""
============================================================================
可扩展检测器插件接口（IDetector）
============================================================================
为模块3提供插件化检测架构，使每个检测器成为独立类，支持热插拔。

设计原则:
  - 每个检测器是独立文件中的独立类
  - 通过 IDetector 接口统一管理
  - 新增检测器 = 新增一个文件 + 实现 IDetector，无需修改引擎代码
  - 检测器之间通过共享的 HostStats / Baselines 字典间接耦合（通过 AnomalyEngine 注入）

用法（自定义检测器）:
    from common.detector import IDetector
    from common.data_structures import TrafficRecord, Alert

    class MyDetector(IDetector):
        @property
        def name(self) -> str:
            return "my_detector"

        @property
        def category(self) -> str:
            return "custom"

        def process(self, record: TrafficRecord, now: float) -> List[Alert]:
            # 检测逻辑
            return alerts
============================================================================
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Optional
from common.data_structures import TrafficRecord, Alert


class IDetector(ABC):
    """
    异常检测器插件接口。

    每个检测器负责一类攻击行为的检测，返回 Alert 列表。
    同一个检测器可以被多次调用（每条流量调用一次）。

    检测器通过 AnomalyEngine 注入以下共享资源（在 set_context() 中）:
      - hosts:     Dict[str, HostStats]        — 主机行为统计（读写）
      - baselines: Dict[str, Baseline]         — 基线数据（只读）
      - config:    dict                        — 配置参数（只读）
      - lock:      threading.Lock              — 线程锁
    """

    # ==================== 元信息（必须覆盖） ====================

    @property
    @abstractmethod
    def name(self) -> str:
        """检测器唯一标识，如 "port_scan" """
        ...

    @property
    @abstractmethod
    def category(self) -> str:
        """
        检测器分类:
          "scan"   — 扫描类（端口扫描、横向扩散）
          "abuse"  — 滥用类（暴力破解、SYN Flood）
          "exfil"  — 外泄类（异常外联、带宽异常）
          "mutate" — 突变类（行为突变）
          "custom" — 自定义
        """
        ...

    @property
    def priority(self) -> int:
        """
        执行优先级（0-100，数字越小越先执行），默认 50。
        扫描类检测器建议设为 10，突变类建议设为 90。
        """
        return 50

    @property
    def enabled(self) -> bool:
        """是否启用，默认 True"""
        return True

    # ==================== 上下文注入 ====================

    def set_context(self, hosts: Dict, baselines: Dict, config: Dict, lock,
                     syn_timestamps: Optional[List] = None,
                     known_external: Optional[set] = None,
                     count_recent: Optional[callable] = None,
                     count_unique_recent: Optional[callable] = None,
                     sum_recent: Optional[callable] = None,
                     make_alert: Optional[callable] = None):
        """
        引擎在初始化检测器时调用，注入共享上下文。

        基础上下文:
          - hosts / baselines / config / lock

        可选上下文（需要时才传入）:
          - syn_timestamps:  全局 SYN 时间戳列表（SynFlood / BehavioralDeviation 需要）
          - known_external:  已知外部 IP 集合（AbnormalOutbound 需要）
          - count_recent:    滑动窗口计数函数 (timestamps, now, window) -> int
          - count_unique_recent: 滑动窗口去重计数 (mapping, now, window) -> int
          - sum_recent:      滑动窗口求和函数 (byte_timestamps, now, window) -> int
          - make_alert:      告警工厂函数 (record, attack_type, severity, title, matched, suggestion) -> Alert
        """
        self._hosts = hosts
        self._baselines = baselines
        self._config = config
        self._lock = lock
        self._syn_timestamps = syn_timestamps or []
        self._known_external = known_external or set()
        self._count_recent = count_recent or (lambda ts, now, w: sum(1 for t in ts if now - t <= w))
        self._count_unique_recent = count_unique_recent or (lambda m, now, w: 0)
        self._sum_recent = sum_recent or (lambda bt, now, w: 0)
        self._make_alert = make_alert or (lambda *a: None)

    # ==================== 核心方法（必须覆盖） ====================

    @abstractmethod
    def process(self, record: TrafficRecord, now: float) -> List[Alert]:
        """
        对一条流量记录执行检测。

        Args:
            record: 流量记录（包含 src_ip/dst_ip/port/payload 等）
            now:    当前时间戳（避免重复调用 time.time()）

        Returns:
            Alert 列表（无告警返回空列表）
        """
        ...

    # ==================== 生命周期 ====================

    def on_start(self):
        """引擎启动时调用一次，可用于初始化"""
        pass

    def on_stop(self):
        """引擎停止时调用一次，可用于清理"""
        pass

    def on_stats_reset(self):
        """统计重置时调用"""
        pass

    def post_process_batch(self, alerts: List[Alert]) -> List[Alert]:
        """
        可选：对当前批次所有告警进行后处理（如置信度评分、关联补充）。
        在所有检测器的 process() 执行完毕后调用，接收并返回修改后的告警列表。

        Returns:
            处理后的告警列表（原样返回或修改后返回）
        """
        return alerts

    def get_statistics(self) -> Optional[Dict]:
        """
        返回检测器自身的统计信息（可选）。
        
        Returns:
            {"alerts_generated": 10, "last_detection": 1234567890.0} 或 None
        """
        return None
