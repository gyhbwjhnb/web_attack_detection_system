"""
SYN Flood 检测器
"""

from typing import List
from common.detector import IDetector
from common.data_structures import TrafficRecord, Alert, AlertSeverity, AlertType


class SynFloodDetector(IDetector):
    """检测短时间内大量 SYN 包"""

    @property
    def name(self) -> str:
        return "syn_flood"

    @property
    def category(self) -> str:
        return "abuse"

    @property
    def priority(self) -> int:
        return 25

    def process(self, record: TrafficRecord, now: float) -> List[Alert]:
        threshold = self._config.get("syn_flood_threshold", 100)
        window = self._config.get("syn_flood_window_sec", 1)

        syn_ts = self._syn_timestamps
        syn_ts[:] = [t for t in syn_ts if now - t <= window]
        count = len(syn_ts)

        if count >= threshold:
            syn_ts.clear()
            return [Alert(
                timestamp=now,
                attack_type="ddos",
                attack_name="SYN Flood 攻击",
                severity=AlertSeverity.CRITICAL,
                confidence=min(count / threshold / 2, 1.0),
                alert_source=AlertType.ANOMALY,
                title="SYN Flood 攻击",
                description=f"SYN Flood: {count}包/{window}s (阈值={threshold})",
                matched_pattern=f"SYN速率{count}/s",
                suggestion="启用 SYN Cookie、限流或联系上游 ISP 清洗",
            )]

        return []
