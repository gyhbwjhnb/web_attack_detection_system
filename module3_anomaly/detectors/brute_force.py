"""
暴力破解检测器
"""

from typing import List
from common.detector import IDetector
from common.data_structures import TrafficRecord, Alert, AlertSeverity, AlertType


class BruteForceDetector(IDetector):

    SENSITIVE_PORTS = {21, 22, 23, 3389, 3306, 5432, 6379, 27017, 1433, 8080, 8443}
    SERVICE_MAP = {22: "SSH", 21: "FTP", 3389: "RDP", 3306: "MySQL",
                   5432: "PostgreSQL", 1433: "MSSQL", 6379: "Redis",
                   27017: "MongoDB", 23: "Telnet", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt"}

    @property
    def name(self) -> str:
        return "brute_force"

    @property
    def category(self) -> str:
        return "abuse"

    @property
    def priority(self) -> int:
        return 20

    def process(self, record: TrafficRecord, now: float) -> List[Alert]:
        dst_port = record.dst.port
        if dst_port not in self.SENSITIVE_PORTS:
            return []

        threshold = self._config.get("brute_force_threshold", 10)
        window = self._config.get("brute_force_window_sec", 5)

        with self._lock:
            host = self._hosts.get(record.src.ip)
            if not host:
                return []

            key = (record.dst.ip, dst_port)
            timestamps = host.service_attempts.get(key, [])
            count = self._count_recent(timestamps, now, window)

            if count >= threshold:
                svc = self.SERVICE_MAP.get(dst_port, str(dst_port))
                return [self._make_alert(
                    record, "brute_force", AlertSeverity.HIGH,
                    f"{svc} 暴力破解: {record.src.ip} → {record.dst.ip}:{dst_port} ({count}次/{window}s)",
                    f"{svc}爆破{count}次/{window}s",
                    f"检查 {svc} 服务日志，建议启用 fail2ban 或限制登录频率"
                )]

        return []
