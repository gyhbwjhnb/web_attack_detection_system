"""
可扩展检测器插件包 —— 每个检测器是独立类，实现 IDetector 接口。

新增自定义检测器步骤:
  1. 在此目录下创建 my_detector.py
  2. 实现 IDetector 接口的 name / category / process 方法
  3. 在 _ALL_DETECTORS 列表中注册

AnomalyEngine 启动时会自动加载 _ALL_DETECTORS 中的所有已启用检测器。
"""

from .port_scan import PortScanDetector
from .brute_force import BruteForceDetector
from .abnormal_outbound import AbnormalOutboundDetector
from .lateral_movement import LateralMovementDetector
from .syn_flood import SynFloodDetector
from .bandwidth_anomaly import BandwidthAnomalyDetector
from .behavioral_deviation import BehavioralDeviationDetector
from .time_profile import TimeProfileDetector
from .confidence_scorer import ConfidenceScorer
from .suppression_learner import SuppressionLearner

# 注册所有内置检测器（按优先级排序，AnomalyEngine 启动时加载）
_ALL_DETECTORS = [
    PortScanDetector(),
    TimeProfileDetector(),
    LateralMovementDetector(),
    BruteForceDetector(),
    SynFloodDetector(),
    AbnormalOutboundDetector(),
    BandwidthAnomalyDetector(),
    ConfidenceScorer(),
    SuppressionLearner(),
    BehavioralDeviationDetector(),
]


def get_default_detectors():
    """返回所有内置检测器实例（仅已启用的）"""
    return [d for d in _ALL_DETECTORS if d.enabled]
