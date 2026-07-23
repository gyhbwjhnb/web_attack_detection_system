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
        if not record.is_syn():
            return []

        threshold = self._config.get("syn_flood_threshold", 100)
        window = self._config.get("syn_flood_window_sec", 1)

        with self._lock:
            host = self._hosts.get(record.src.ip)
            if not host:
                return []

            # 使用主机级 SYN 时间戳（修复：之前使用全局计数器导致全网误报）
            syn_timestamps = getattr(host, 'syn_timestamps', [])
            syn_count = self._count_recent(syn_timestamps, now, window)

            if syn_count < threshold:
                return []

            # 修剪过期时间戳（不再 clear() 全部）
            cutoff = now - window
            host.syn_timestamps = [t for t in syn_timestamps if t > cutoff]

            # 同时修剪全局 SYN 队列
            if self._syn_timestamps:
                self._syn_timestamps[:] = [t for t in self._syn_timestamps if now - t <= self._config.get("recent_window", 300)]

            return [self._make_alert(
                record, "ddos", AlertSeverity.CRITICAL,
                f"SYN Flood: {record.src.ip} {syn_count}包/{window}s (阈值={threshold})",
                f"SYN速率{syn_count}/s",
                "启用 SYN Cookie、限流或联系上游 ISP 清洗"
            )]
