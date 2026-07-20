"""
自学习误报抑制器 —— 从用户反馈中学习，降低已知误报模式的告警置信度。

工作流程:
  1. 用户在 GUI 将告警标记为"误报"或"已忽略"
  2. GUI 通过 MessageBus 发布 EVENT_ALERT_STATUS_CHANGE 事件
  3. SuppressionLearner 订阅该事件，提取 (src_ip, attack_type, dst_port) 签名
  4. 在 post_process_batch 中，匹配签名自动降低置信度
  5. 规则持久化到 data/suppression_rules.json，重启保留
"""

import json
import os
import threading
from typing import List, Dict, Set, Optional
from pathlib import Path

from common.detector import IDetector
from common.data_structures import TrafficRecord, Alert


class SuppressionLearner(IDetector):
    """从用户反馈中学习误报模式"""

    _SUPPRESSION_FILE = "data/suppression_rules.json"

    # 抑制规则类型: rule_key → {"src_ip": str, "attack_type": str, "dst_port": int, "count": int, "created": float}
    # rule_key = f"{src_ip}|{attack_type}|{dst_port}"

    @property
    def name(self) -> str:
        return "suppression_learner"

    @property
    def category(self) -> str:
        return "feedback"

    @property
    def priority(self) -> int:
        return 88  # 在 ConfidenceScorer 之后运行

    def __init__(self):
        self._rules: Dict[str, dict] = {}
        self._suppress_threshold = 2  # 同模式被标记 ≥N 次才启用抑制
        self._confidence_penalty = 0.35  # 匹配时降低的置信度幅度
        self._load_rules()

    def process(self, record: TrafficRecord, now: float) -> List[Alert]:
        return []

    def post_process_batch(self, alerts: List[Alert]) -> List[Alert]:
        """降低已知误报模式的告警置信度"""
        for alert in alerts:
            keys = self._match_keys(alert)
            for key in keys:
                rule = self._rules.get(key)
                if rule and rule.get("count", 0) >= self._suppress_threshold:
                    alert.confidence = round(max(0.0, alert.confidence - self._confidence_penalty), 2)
                    alert.tags.append("user_suppressed")
                    break  # 一个告警只惩罚一次
        return alerts

    def on_user_ignore(self, alert_data: dict):
        """用户标记告警为误报/已忽略时调用"""
        key = self._make_key(
            alert_data.get("src_ip", ""),
            alert_data.get("attack_type", ""),
            alert_data.get("dst_port", 0),
        )
        if not key or alert_data.get("src_ip", "") == "0.0.0.0":
            return

        with self._lock:
            if key in self._rules:
                self._rules[key]["count"] += 1
            else:
                self._rules[key] = {
                    "src_ip": alert_data.get("src_ip", ""),
                    "attack_type": alert_data.get("attack_type", ""),
                    "dst_port": alert_data.get("dst_port", 0),
                    "count": 1,
                    "created": alert_data.get("timestamp", 0),
                }
        # 异步保存（避免阻塞 GUI）
        threading.Thread(target=self._save_rules, daemon=True).start()

    def get_active_rules(self) -> List[dict]:
        """返回已达到抑制阈值的规则列表（供 GUI 展示）"""
        return [r for r in self._rules.values() if r.get("count", 0) >= self._suppress_threshold]

    # ==================== 内部方法 ====================

    @staticmethod
    def _make_key(src_ip: str, attack_type: str, dst_port: int) -> Optional[str]:
        if not src_ip or not attack_type:
            return None
        return f"{src_ip}|{attack_type}|{dst_port}"

    def _match_keys(self, alert: Alert) -> List[str]:
        """生成告警可能匹配的所有规则 key"""
        keys = []
        # 精确匹配
        k = self._make_key(alert.src_ip, alert.attack_type, alert.dst_port)
        if k:
            keys.append(k)
        # 仅 IP + 类型（忽略端口）
        k2 = self._make_key(alert.src_ip, alert.attack_type, 0)
        if k2:
            keys.append(k2)
        return keys

    def _save_rules(self):
        try:
            path = Path(self._SUPPRESSION_FILE)
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self._rules, f, ensure_ascii=False, indent=2)
        except Exception:
            pass  # 静默失败，不影响主流程

    def _load_rules(self):
        try:
            path = Path(self._SUPPRESSION_FILE)
            if path.exists():
                with open(path, "r", encoding="utf-8") as f:
                    self._rules = json.load(f)
        except Exception:
            pass

    def on_stats_reset(self):
        pass
