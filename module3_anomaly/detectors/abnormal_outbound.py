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
        dst_port = record.dst.port

        # port=0 表示非传输层协议（IGMP/ICMP等），不是C2流量
        if dst_port == 0 or record.src.port == 0:
            return []

        if not is_private_ip(src_ip) or is_private_ip(dst_ip):
            return []

        key = (dst_ip, dst_port)

        # 标准端口：静默记录，永不告警（正常上网行为）
        if dst_port in self.STANDARD_PORTS:
            self._known_external.add(key)
            return []

        # 非标准端口：首次连接记录，第二次+才告警
        if key in self._known_external:
            return [self._make_alert(
                record, "abnormal_outbound", AlertSeverity.HIGH,
                f"异常外联: 内网 {src_ip} → 外部 {dst_ip}:{dst_port}（非标准端口重复连接）",
                f"重复外联 {dst_ip}:{dst_port}",
                "检查该主机是否感染恶意软件或存在 C2 通信，建议临时隔离"
            )]

        # 首次连接非标准端口：静默记录，暂不告警
        self._known_external.add(key)
        return []
