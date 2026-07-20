"""
端口扫描检测器
"""

from typing import List
from common.detector import IDetector
from common.data_structures import TrafficRecord, Alert, AlertSeverity, AlertType


class PortScanDetector(IDetector):
    """检测单 IP 在时间窗口内访问大量不同端口"""

    @property
    def name(self) -> str:
        return "port_scan"

    @property
    def category(self) -> str:
        return "scan"

    @property
    def priority(self) -> int:
        return 10

    def process(self, record: TrafficRecord, now: float) -> List[Alert]:
        threshold = self._config.get("port_scan_threshold", 50)
        window = self._config.get("port_scan_window_sec", 10)

        with self._lock:
            host = self._hosts.get(record.src.ip)
            if not host:
                return []

            recent_ports = self._count_unique_recent(host.port_timestamps, now, window)
            if recent_ports < threshold:
                return []

            baseline = self._baselines.get(record.src.ip)
            if baseline and baseline.is_established():
                ratio = recent_ports / max(baseline.unique_ports, 1)
                if ratio < self._config.get("conn_rate_threshold", 3.0):
                    return []

            scan_rate = recent_ports / max(window, 1)
            return [self._make_alert(
                record, "port_scan", AlertSeverity.LOW,
                f"端口扫描: {record.src.ip} {window}秒内访问{recent_ports}个端口 (速率 {scan_rate:.1f}/s)",
                f"扫描{recent_ports}端口/{window}s",
                "检查来源 IP 是否为外部扫描器，加入黑名单或防火墙规则"
            )]

        return []
