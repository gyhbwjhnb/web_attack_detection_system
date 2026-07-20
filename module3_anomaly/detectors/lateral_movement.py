"""
内网横向扩散检测器
"""

from typing import List, Set
from common.detector import IDetector
from common.data_structures import TrafficRecord, Alert, AlertSeverity, AlertType, is_private_ip


class LateralMovementDetector(IDetector):
    """检测内网 IP 短时间连接多个内网 IP 的同一端口"""

    @property
    def name(self) -> str:
        return "lateral_movement"

    @property
    def category(self) -> str:
        return "scan"

    @property
    def priority(self) -> int:
        return 15

    def process(self, record: TrafficRecord, now: float) -> List[Alert]:
        if not is_private_ip(record.src.ip) or not is_private_ip(record.dst.ip):
            return []

        window = self._config.get("port_scan_window_sec", 10)
        threshold = self._config.get("port_scan_threshold", 50) // 2

        with self._lock:
            host = self._hosts.get(record.src.ip)
            if not host:
                return []

            same_port_peers: Set[str] = set()
            for (peer_ip, port), ts_list in host.service_attempts.items():
                if is_private_ip(peer_ip) and port == record.dst.port:
                    if any(now - t <= window for t in ts_list):
                        same_port_peers.add(peer_ip)

            if len(same_port_peers) >= threshold:
                return [self._make_alert(
                    record, "lateral_movement", AlertSeverity.CRITICAL,
                    f"内网横向扩散: {record.src.ip} {window}s内连接{len(same_port_peers)}台主机 (端口{record.dst.port})",
                    f"横向{len(same_port_peers)}台:{record.dst.port}",
                    "立即隔离该主机，检查是否为跳板攻击，全网扫描"
                )]

        return []
