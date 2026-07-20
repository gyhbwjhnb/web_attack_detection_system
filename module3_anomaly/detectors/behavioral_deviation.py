"""
行为突变检测器
"""

from typing import List
from common.detector import IDetector
from common.data_structures import TrafficRecord, Alert, AlertSeverity, AlertType


class BehavioralDeviationDetector(IDetector):
    """
    检测主机行为是否在近期发生显著突变。

    比较维度: 连接数 / 对端数 / 端口数 / SYN 比例
    """

    @property
    def name(self) -> str:
        return "behavioral_deviation"

    @property
    def category(self) -> str:
        return "mutate"

    @property
    def priority(self) -> int:
        return 90

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

            alerts = []

            # --- 连接数突变 ---
            recent_conn = self._count_recent(host.conn_timestamps, now)
            recent_conn_rate = recent_conn / max(recent_window / 60.0, 1)
            baseline_conn_rate = baseline.conn_avg_per_min
            conn_ratio = recent_conn_rate / max(baseline_conn_rate, 0.01)

            if conn_ratio > self._config.get("mutation_conn_ratio", 5.0) and recent_conn > self._config.get("mutation_conn_min", 20):
                alerts.append(self._make_alert(
                    record, "unknown_anomaly", AlertSeverity.HIGH,
                    f"连接数突变: {record.src.ip} 近期 {recent_conn_rate:.1f}次/分钟，基线 {baseline_conn_rate:.1f}次/分钟 (×{conn_ratio:.1f})",
                    f"连接速率×{conn_ratio:.1f}",
                    "检查该主机是否被入侵后发起扫描或大流量通信"
                ))

            # --- 对端数突变 ---
            recent_peers = self._count_unique_recent(host.peer_timestamps, now)
            baseline_peers = max(len(baseline.internal_peers), 1)
            peer_ratio = recent_peers / baseline_peers

            if peer_ratio > self._config.get("mutation_peer_ratio", 5.0) and recent_peers > self._config.get("mutation_peer_min", 15):
                alerts.append(self._make_alert(
                    record, "unknown_anomaly", AlertSeverity.MEDIUM,
                    f"对端数突变: {record.src.ip} 近期通信 {recent_peers} 个对端，基线约 {baseline_peers} 个 (×{peer_ratio:.1f})",
                    f"对端数×{peer_ratio:.1f}",
                    "检查是否在进行扫描或横向移动"
                ))

            # --- SYN 比例突变 ---
            syn_in_window = self._count_recent(self._syn_timestamps, now, recent_window)
            syn_rate = syn_in_window / max(recent_window / 60.0, 1)
            normal_syn_rate = baseline_conn_rate * 0.3
            if syn_rate > normal_syn_rate * self._config.get("mutation_syn_ratio", 3.0) and syn_in_window > self._config.get("mutation_syn_min", 30):
                alerts.append(self._make_alert(
                    record, "ddos", AlertSeverity.MEDIUM,
                    f"SYN比例异常: {record.src.ip} 近期 SYN {syn_rate:.1f}/分钟 (正常约{normal_syn_rate:.1f})",
                    f"SYN比例异常 {syn_rate:.1f}/min",
                    "检查该主机是否发起 SYN Flood 或进行大量端口扫描"
                ))

            return alerts[:2]  # 最多 2 条，避免刷屏
