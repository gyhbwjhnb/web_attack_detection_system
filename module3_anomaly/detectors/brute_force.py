"""
暴力破解检测器
"""

from typing import List
from common.detector import IDetector
from common.data_structures import TrafficRecord, Alert, AlertSeverity, AlertType


class BruteForceDetector(IDetector):

    SENSITIVE_PORTS = {21, 22, 23, 80, 443, 3389, 3306, 5432, 6379, 27017, 1433, 8080, 8443}
    SERVICE_MAP = {22: "SSH", 21: "FTP", 3389: "RDP", 3306: "MySQL",
                   5432: "PostgreSQL", 1433: "MSSQL", 6379: "Redis",
                   27017: "MongoDB", 23: "Telnet", 80: "HTTP", 443: "HTTPS",
                   8080: "HTTP-Proxy", 8443: "HTTPS-Alt"}

    # 登录失败特征（与模块二 BRUTE-001/002/003 保持一致）
    _LOGIN_FAIL_PATTERNS = [
        "login failed", "password incorrect", "invalid username",
        "authentication failed", "access denied", "bad password",
        "wrong password", "login incorrect", "incorrect password",
    ]

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

        base_threshold = self._config.get("brute_force_threshold", 10)
        window = self._config.get("brute_force_window_sec", 5)

        # 检查登录失败特征（与模块二保持一致，防止SCP/DB连接池误报）
        payload_lower = (record.payload or "").lower()
        has_login_failure = any(p in payload_lower for p in self._LOGIN_FAIL_PATTERNS)

        with self._lock:
            host = self._hosts.get(record.src.ip)
            if not host:
                return []

            key = (record.dst.ip, dst_port)
            timestamps = host.service_attempts.get(key, [])
            count = self._count_recent(timestamps, now, window)

            # 自适应阈值：有登录失败内容→低阈值，无内容→5倍阈值
            threshold = base_threshold if has_login_failure else base_threshold * 5

            if count >= threshold:
                svc = self.SERVICE_MAP.get(dst_port, str(dst_port))
                evidence = "含登录失败" if has_login_failure else "高频连接"
                return [self._make_alert(
                    record, "brute_force", AlertSeverity.HIGH,
                    f"{svc} 暴力破解: {record.src.ip} -> {record.dst.ip}:{dst_port} ({count}次/{window}s, {evidence})",
                    f"{svc}爆破{count}次/{window}s",
                    f"检查 {svc} 服务日志，建议启用 fail2ban 或限制登录频率"
                )]

        return []
