"""
置信度评分检测器 —— 后处理阶段运行，为每条告警计算攻击置信度评分。

评分逻辑（依据攻击类型动态调整）:
  - port_scan:     基于目标端口数 + 扫描速率
  - brute_force:   基于失败次数 + 连接频率
  - abnormal_outbound: 基于目标稀有度 + 上传量
  - syn_flood:     基于 SYN 密度 + 峰值倍率
  - bandwidth_anomaly: 基于偏离基线的倍数
  - lateral_movement:  基于接触主机数 + 跨度
  - behavioral_deviation: 基于偏离基线的标准差倍数

所有告警保留（不抑制低于某个阈值的），仅补充 confidence 评分供 GUI 展示。
"""

import math
from typing import List

from common.detector import IDetector
from common.data_structures import TrafficRecord, Alert


class ConfidenceScorer(IDetector):
    """后处理阶段：为每条告警补充置信度评分"""

    @property
    def name(self) -> str:
        return "confidence_scorer"

    @property
    def category(self) -> str:
        return "enhance"

    @property
    def priority(self) -> int:
        return 85  # 在所有检测器之后、behavioral_deviation(90) 之前

    # 不产生新告警，只做后处理
    def process(self, record: TrafficRecord, now: float) -> List[Alert]:
        return []

    def post_process_batch(self, alerts: List[Alert]) -> List[Alert]:
        """为每条告警动态计算置信度"""
        for alert in alerts:
            score = self._calculate_confidence(alert)
            alert.confidence = score
        return alerts

    # ==================== 评分规则 ====================

    def _calculate_confidence(self, alert: Alert) -> float:
        """根据攻击类型调用对应的评分函数"""
        atype = alert.attack_type
        if atype == "port_scan":
            return self._score_port_scan(alert)
        elif atype == "brute_force":
            return self._score_brute_force(alert)
        elif atype == "abnormal_outbound":
            return self._score_outbound(alert)
        elif atype == "syn_flood":
            return self._score_syn_flood(alert)
        elif atype == "bandwidth_anomaly":
            return self._score_bandwidth(alert)
        elif atype == "lateral_movement":
            return self._score_lateral(alert)
        elif atype == "behavioral_deviation":
            return self._score_behavioral(alert)
        else:
            # 后端告警关联器产出的聚合告警：默认高分
            return 0.90

    # ---- 各类型评分 ----

    def _score_port_scan(self, alert: Alert) -> float:
        """端口扫描：端口数越多、越集中 → 置信越高"""
        port_count = self._extract_int("扫描", alert.matched_pattern, 0)
        window = self._config.get("port_scan_window_sec", 10)
        rate = port_count / max(window, 1) if window > 0 else 0  # ports/s

        # 基础分：扫描端口数
        score = min(0.5, port_count / 100.0 * 0.5)  # 100 端口 = 0.5
        # 速率加成
        score += min(0.4, rate * 0.02)               # 20 port/s = 0.4

        base = self._hosts.get(alert.src_ip)
        if base and port_count > 5:
            # 端口离散度低（集中在连续范围）更可疑
            ports = sorted(base.all_ports)
            if len(ports) >= 2:
                consec = sum(1 for i in range(1, len(ports)) if ports[i] - ports[i - 1] <= 5)
                consec_ratio = consec / max(len(ports) - 1, 1)
                score += min(0.1, consec_ratio * 0.1)

        return round(min(1.0, score + 0.1), 2)  # 保底 0.1

    def _score_brute_force(self, alert: Alert) -> float:
        """暴力破解：单服务连接密度越高 → 置信越高"""
        port_count = self._extract_int("端口", alert.matched_pattern, 0)
        window = self._config.get("brute_force_window_sec", 60)
        rate = port_count / max(window, 1) if window > 0 else 0  # 次/s

        score = min(0.4, rate * 0.5)  # 0.8 次/s = 0.4
        score += min(0.3, port_count / 200.0 * 0.3)  # 200 次 = 0.3

        # 高关注端口（SSH=22, RDP=3389, MySQL=3306）额外加分
        critical_ports = {22, 3389, 3306, 6379, 27017, 1433}
        if alert.dst_port in critical_ports:
            score += 0.2

        return round(min(1.0, score + 0.1), 2)

    def _score_outbound(self, alert: Alert) -> float:
        """异常外联：目标稀有度 + 字节量"""
        score = 0.15  # 保底

        # 外联已知恶意端口
        suspicious_ports = {4444, 1337, 31337, 6666, 6667, 8888, 9999}
        if alert.dst_port in suspicious_ports:
            score += 0.3

        # 非标准端口
        standard_ports = {80, 443, 53, 8080, 8443}
        if alert.dst_port not in standard_ports:
            score += 0.15

        # 外部 IP 首次出现
        if alert.dst_ip not in self._known_external:
            score += 0.2

        return round(min(1.0, score), 2)

    def _score_syn_flood(self, alert: Alert) -> float:
        """SYN Flood：密度越高置信越高"""
        rate = self._extract_int("SYN", alert.matched_pattern, 0)
        syn_threshold = self._config.get("syn_flood_threshold_per_sec", 100)

        score = 0.2
        if syn_threshold > 0:
            ratio = rate / syn_threshold
            score += min(0.7, ratio * 0.7)  # 10 倍阈值 = 0.7

        return round(min(1.0, score), 2)

    def _score_bandwidth(self, alert: Alert) -> float:
        """带宽异常：偏离倍率 → 置信度"""
        multiplier = 1.0
        text = alert.matched_pattern
        if "倍" in text:
            multiplier = self._extract_float(text, 1.0)

        score = 0.2 + min(0.7, math.log2(max(multiplier, 1.1)) * 0.2)
        return round(min(1.0, score), 2)

    def _score_lateral(self, alert: Alert) -> float:
        """横向扩散：接触主机数越多越可疑"""
        peers = self._extract_int("主机", alert.matched_pattern, 0)
        score = min(0.6, peers / 10.0 * 0.6)  # 10 台 = 0.6

        # 跨度检测：不同子网
        with self._lock:
            host = self._hosts.get(alert.src_ip)
            if host:
                subnets = {ip.rsplit(".", 1)[0] for ip in host.all_peers if "." in ip}
                if len(subnets) >= 2:
                    score += min(0.3, (len(subnets) - 1) * 0.1)

        return round(min(1.0, score + 0.1), 2)

    def _score_behavioral(self, alert: Alert) -> float:
        """行为突变：偏离标准差倍数 → 置信度"""
        text = alert.matched_pattern
        multiplier = self._extract_float(text, 3.0)
        score = min(0.8, multiplier / 10.0 * 0.8)
        return round(min(1.0, score + 0.2), 2)

    # ==================== 工具 ====================

    @staticmethod
    def _extract_int(prefix: str, text: str, default: int) -> int:
        """从告警描述中提取第一个紧跟前缀的数字"""
        import re
        m = re.search(rf'{prefix}[^\d]*(\d+)', text)
        return int(m.group(1)) if m else default

    @staticmethod
    def _extract_float(text: str, default: float) -> float:
        """从告警描述中提取第一个浮点数"""
        import re
        m = re.search(r'(\d+\.?\d*)倍', text)
        if m:
            return float(m.group(1))
        m = re.search(r'(\d+\.?\d*)', text)
        return float(m.group(1)) if m else default
