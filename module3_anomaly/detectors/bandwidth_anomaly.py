"""
带宽异常检测器
"""

from typing import List
from common.detector import IDetector
from common.data_structures import TrafficRecord, Alert, AlertSeverity, AlertType


class BandwidthAnomalyDetector(IDetector):
    """检测近期流量突发超过历史基线倍数"""

    @property
    def name(self) -> str:
        return "bandwidth_anomaly"

    @property
    def category(self) -> str:
        return "exfil"

    @property
    def priority(self) -> int:
        return 40

    def process(self, record: TrafficRecord, now: float) -> List[Alert]:
        recent_window = self._config.get("recent_window", 300)

        with self._lock:
            host = self._hosts.get(record.src.ip)
            baseline = self._baselines.get(record.src.ip)
            if not host or not baseline:
                return []

            min_samples = self._config.get("baseline_min_samples", 10)
            if baseline.sample_count < min_samples:
                return []

            recent_bytes = self._sum_recent(host.byte_timestamps, now, recent_window)
            recent_rate = recent_bytes / max(recent_window, 1)
            baseline_rate = baseline.bw_avg
            mult = self._config.get("bandwidth_anomaly_threshold", 5.0)

            if baseline_rate > 0 and recent_rate > baseline_rate * mult:
                return [self._make_alert(
                    record, "ddos", AlertSeverity.HIGH,
                    f"带宽异常: {record.src.ip} 近5分钟速率 {recent_rate:.0f}B/s，基线 {baseline_rate:.0f}B/s (×{recent_rate/baseline_rate:.1f})",
                    f"速率{recent_rate:.0f}B/s vs 基线{baseline_rate:.0f}B/s",
                    "检查该主机是否遭受 DDoS 或正在发起大流量攻击"
                )]

        return []
