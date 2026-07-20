"""
异常外联检测器
"""

from typing import List
from common.detector import IDetector
from common.data_structures import TrafficRecord, Alert, AlertSeverity, AlertType, is_private_ip


class AbnormalOutboundDetector(IDetector):
    """检测内网 IP 连接外部陌生 IP"""

    STANDARD_PORTS = {80, 443, 53, 8080, 8443, 123}

    @property
    def name(self) -> str:
        return "abnormal_outbound"

    @property
    def category(self) -> str:
        return "exfil"

    @property
    def priority(self) -> int:
        return 30

    def process(self, record: TrafficRecord, now: float) -> List[Alert]:
        src_ip, dst_ip = record.src.ip, record.dst.ip

        if not is_private_ip(src_ip) or is_private_ip(dst_ip):
            return []
        if dst_ip in self._known_external:
            return []

        self._known_external.add(dst_ip)

        severity = AlertSeverity.HIGH if record.dst.port not in self.STANDARD_PORTS else AlertSeverity.MEDIUM

        return [self._make_alert(
            record, "abnormal_outbound", severity,
            f"异常外联: 内网 {src_ip} → 外部 {dst_ip}:{record.dst.port}",
            f"未知外部IP {dst_ip}:{record.dst.port}",
            "检查该主机是否感染恶意软件或存在 C2 通信，建议临时隔离"
        )]
