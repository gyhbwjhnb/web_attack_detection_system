"""
异常时段检测器 —— 学习主机 24 小时活动基线，检测非正常时段的异常活动。

原理:
  - 维护每台主机的 24 小时连接数直方图（EMA 均值 + 标准差）
  - 凌晨（0-6 点）> 均值 + 3σ → 疑似夜间异常活动
  - 不产生新告警类型，而是对夜间活动的其他告警提升置信度
"""

import threading
from typing import List, Dict, Tuple

from common.detector import IDetector
from common.data_structures import TrafficRecord, Alert


class TimeProfileDetector(IDetector):
    """24 小时活动基线 + 时段异常检测"""

    @property
    def name(self) -> str:
        return "time_profile"

    @property
    def category(self) -> str:
        return "baseline"

    @property
    def priority(self) -> int:
        return 35

    def __init__(self):
        # hour_baselines[host_ip][hour] = (ema_mean, ema_variance, sample_count)
        self._hour_baselines: Dict[str, Dict[int, Tuple[float, float, int]]] = {}
        # 当前小时窗口的临时计数
        self._hourly_counts: Dict[str, Dict[int, int]] = {}
        self._last_hour: Dict[str, int] = {}
        self._ema_alpha = 0.1  # EMA 平滑系数

    def process(self, record: TrafficRecord, now: float) -> List[Alert]:
        """更新 24 小时直方图，检测时段异常"""
        src_ip = record.src.ip
        hour = int(now / 3600) % 24  # 当前小时 (0-23)

        with self._lock:
            # 更新小时计数器
            if src_ip not in self._hourly_counts:
                self._hourly_counts[src_ip] = {}
                self._hour_baselines[src_ip] = {}
                self._last_hour[src_ip] = hour

            last_hour = self._last_hour[src_ip]
            if hour != last_hour:
                # 小时切换：提交上一小时数据到 baseline
                if last_hour in self._hourly_counts[src_ip]:
                    count = self._hourly_counts[src_ip].pop(last_hour)
                    self._update_hour_baseline(src_ip, last_hour, count)
                self._last_hour[src_ip] = hour

            self._hourly_counts[src_ip][hour] = self._hourly_counts[src_ip].get(hour, 0) + 1

            # 检测：凌晨时段且有其他告警 -> 先不急，仅用 post_process 增强置信度
            if 0 <= hour < 6:
                baseline = self._hour_baselines[src_ip].get(hour)
                if baseline and baseline[1] > 0:
                    mean, var, _ = baseline
                    current = self._hourly_counts[src_ip].get(hour, 0)
                    if current > mean + 3 * (var ** 0.5):
                        # 标记当前主机处于夜间异常状态（供后处理使用）
                        return []  # 不单独产生告警，由 post_process 增强

        return []

    def post_process_batch(self, alerts: List[Alert]) -> List[Alert]:
        """夜间连接数异常的告警提升置信度"""
        for alert in alerts:
            src_ip = alert.src_ip
            hour = int(alert.timestamp / 3600) % 24

            # 仅凌晨时段增强
            if 0 <= hour < 6:
                baseline = self._hour_baselines.get(src_ip, {}).get(hour)
                if baseline:
                    mean, var, samples = baseline
                    if samples >= 3 and var > 0:
                        current = self._hourly_counts.get(src_ip, {}).get(hour, 0)
                        if current > mean + 2 * (var ** 0.5):
                            # 夜间活动显著高于历史均值 → 提升置信度
                            boost = min(0.25, (current - mean) / max(mean * 10, 1))
                            alert.confidence = min(1.0, round(alert.confidence + boost, 2))
                            alert.description += " [夜间异常时段]"

        return alerts

    def _update_hour_baseline(self, host_ip: str, hour: int, count: int):
        """用 EMA 更新指定小时的基线"""
        entry = self._hour_baselines[host_ip].get(hour)
        if entry is None:
            self._hour_baselines[host_ip][hour] = (float(count), 0.0, 1)
            return

        mean, var, n = entry
        # EMA 更新均值
        new_mean = self._ema_alpha * count + (1 - self._ema_alpha) * mean
        # EMA 更新方差
        new_var = self._ema_alpha * (count - new_mean) ** 2 + (1 - self._ema_alpha) * var
        self._hour_baselines[host_ip][hour] = (new_mean, new_var, min(n + 1, 100))

    def on_stats_reset(self):
        with self._lock:
            self._hour_baselines.clear()
            self._hourly_counts.clear()
            self._last_hour.clear()
