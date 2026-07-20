"""
异常行为检测引擎 —— 实现 IAnomalyEngine 接口。

检测能力:
  - 端口扫描: 单 IP 在时间窗口内访问 N 个不同端口超过阈值
  - 暴力破解: 单 IP 短时间内对同一服务发起大量 SYN 连接
  - 异常外联: 内网 IP 连接外部陌生 IP
  - 内网横向扩散: 内网 IP 短时间连接多个内网 IP 的同一端口
  - SYN Flood: 短时间内大量 SYN 包无对应 ACK
  - 带宽异常: 近期流量突发超过历史基线倍数
  - ★ 行为突变检测: 主机行为相比近期历史出现显著偏离

核心机制:
  - 滑动窗口统计: 每条时间戳记录在滑动窗口内衰减，避免"只涨不跌"
  - 连续自适应基线: 初始学习期结束后，通过 EMA 持续更新基线
  - 近期 vs 历史对比: 将"最近 N 秒"行为与基线做比较，发现突变
"""

import os
import sys
import time
import threading

# 允许直接运行此文件时也能找到 common 模块
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from collections import defaultdict
from typing import Dict, List, Optional, Callable, Set, Tuple

from common.engine import IAnomalyEngine
from common.data_structures import (
    TrafficRecord, Alert, Baseline, AttackChain,
    AlertSeverity, AlertType, AlertStatus, ProtocolType,
)
from common.config import ANOMALY_CONFIG, WHITELIST_IPS, get_attack_info
from common.utils import setup_logger

logger = setup_logger("module3_anomaly", "logs/module3.log")


class HostStats:
    """单主机行为统计 —— 基于时间戳滑动窗口"""

    def __init__(self, ip: str):
        self.ip = ip

        # ---- 累计计数（全生命周期） ----
        self.total_conn = 0
        self.total_bytes = 0
        self.total_syn = 0

        # ---- 时间戳记录（用于滑动窗口统计） ----
        self.conn_timestamps: List[float] = []          # 每条连接的时间戳
        self.port_timestamps: Dict[int, List[float]] = defaultdict(list)
        self.peer_timestamps: Dict[str, List[float]] = defaultdict(list)
        self.service_attempts: Dict[Tuple[str, int], List[float]] = defaultdict(list)
        self.byte_timestamps: List[Tuple[float, int]] = []  # (timestamp, bytes)

        # ---- 所有见过的（全生命周期，不衰减） ----
        self.all_ports: Set[int] = set()
        self.all_peers: Set[str] = set()

        self.last_seen = time.time()


class AnomalyEngine(IAnomalyEngine):
    """
    异常行为检测引擎 —— 基于可扩展插件架构。

    每个检测器是实现 IDetector 的独立类，支持热插拔。
    新增检测器 = 在 detectors/ 目录新增一个文件 + 实现 IDetector。

    自适应机制:
      1. 初始学习期: 收集数据建立第一版基线
      2. 运行期每 60 秒用 EMA 更新基线（alpha=0.1）
      3. 所有时间窗口统计用滑动窗口
      4. 行为突变检测: 近期 vs 基线偏离超阈值 → 告警

    用法:
        engine = AnomalyEngine()
        engine.start_baseline_learning(duration=60)

        # 每条流量
        alerts = engine.process_traffic(record)
    """

    SENSITIVE_PORTS = {21, 22, 23, 3389, 3306, 5432, 6379, 27017, 1433, 8080, 8443}

    def __init__(self, config: dict = None, detectors: list = None):
        self._config = config or ANOMALY_CONFIG

        # ---- 主机统计 ----
        self._hosts: Dict[str, HostStats] = {}
        self._lock = threading.Lock()

        # ---- 基线（EMA 持续更新） ----
        self._baselines: Dict[str, Baseline] = {}
        self._baseline_ema_alpha = 0.1
        self._last_baseline_update = 0.0

        # ---- 学习模式 ----
        self._learning = False
        self._learning_start = 0.0
        self._learning_duration = 0.0

        # ---- 滑动窗口参数 ----
        self._recent_window = 300
        self._medium_window = 1800

        # ---- SYN Flood（全局共享状态） ----
        self._syn_timestamps: List[float] = []

        # ---- 攻击链 ----
        self._chains: List[AttackChain] = []
        self._active_chain: Optional[AttackChain] = None

        # ---- 回调 ----
        self._on_alert: Optional[Callable[[Alert], None]] = None
        self._on_chain: Optional[Callable[[AttackChain], None]] = None

        # ---- 统计 ----
        self._anomaly_alert_count = 0
        self._noise_reduced_count = 0
        self._behavior_deviation_count = 0

        # ---- 清理 ----
        self._cleanup_interval = 60
        self._last_cleanup = time.time()

        # ---- 外联白名单 ----
        self._known_external: Set[str] = set()

        # ---- ★ 插件化检测器注册表 ----
        from module3_anomaly.detectors import get_default_detectors
        self._detectors = detectors or get_default_detectors()
        self._detectors_by_name: Dict[str, IDetector] = {}
        self._init_detectors()

        # ---- 订阅 GUI 重置事件 ----
        from common.message_bus import message_bus
        message_bus.subscribe(message_bus.EVENT_CONFIG_CHANGE, self._on_config_change)

        logger.info(f"异常检测引擎初始化完成（{len(self._detectors)} 个检测器插件）")

    # ==================== ★ 插件管理 ====================

    def _init_detectors(self):
        """初始化所有检测器，注入共享上下文，并按优先级排序"""
        from common.detector import IDetector

        # 按优先级排序
        self._detectors.sort(key=lambda d: d.priority)

        for detector in self._detectors:
            detector.set_context(
                hosts=self._hosts,
                baselines=self._baselines,
                config=self._config,
                lock=self._lock,
                syn_timestamps=self._syn_timestamps,
                known_external=self._known_external,
                count_recent=self._count_recent,
                count_unique_recent=self._count_unique_recent,
                sum_recent=self._sum_recent,
                make_alert=self._make_alert,
            )
            self._detectors_by_name[detector.name] = detector
            detector.on_start()
            logger.debug(f"  检测器已加载: {detector.name} (优先级={detector.priority}, 类别={detector.category})")

    def add_detector(self, detector) -> bool:
        """动态添加一个新检测器（运行时热插拔）"""
        from common.detector import IDetector
        if detector.name in self._detectors_by_name:
            logger.warning(f"检测器 {detector.name} 已存在，跳过")
            return False
        detector.set_context(
            hosts=self._hosts, baselines=self._baselines, config=self._config,
            lock=self._lock, syn_timestamps=self._syn_timestamps,
            known_external=self._known_external,
            count_recent=self._count_recent,
            count_unique_recent=self._count_unique_recent,
            sum_recent=self._sum_recent, make_alert=self._make_alert,
        )
        detector.on_start()
        self._detectors.append(detector)
        self._detectors_by_name[detector.name] = detector
        self._detectors.sort(key=lambda d: d.priority)
        logger.info(f"检测器已添加: {detector.name}")
        return True

    def remove_detector(self, name: str) -> bool:
        """动态移除一个检测器"""
        detector = self._detectors_by_name.pop(name, None)
        if detector:
            detector.on_stop()
            self._detectors.remove(detector)
            logger.info(f"检测器已移除: {name}")
            return True
        return False

    def get_detector(self, name: str):
        """获取指定名称的检测器实例（用于运行时调整配置等）"""
        return self._detectors_by_name.get(name)

    def list_detectors(self) -> List[Dict]:
        """列出所有已注册的检测器"""
        return [
            {"name": d.name, "category": d.category, "priority": d.priority,
             "enabled": d.enabled}
            for d in self._detectors
        ]

    # ==================== 窗口统计工具 ====================

    def _count_recent(self, timestamps: List[float], now: float, window: float = None) -> int:
        """统计滑动窗口内的时间戳数量"""
        w = window or self._recent_window
        return sum(1 for t in timestamps if now - t <= w)

    def _count_unique_recent(self, mapping: Dict, now: float, window: float = None) -> int:
        """统计滑动窗口内不同 key 的数量"""
        w = window or self._recent_window
        count = 0
        for ts_list in mapping.values():
            if any(now - t <= w for t in ts_list):
                count += 1
        return count

    # 保留旧名称以兼容（被 detector 调用）
    def _unique_recent(self, mapping: Dict, now: float, window: float = None) -> int:
        return self._count_unique_recent(mapping, now, window)

    def _sum_recent(self, byte_timestamps: List[Tuple[float, int]], now: float, window: float = None) -> int:
        """统计滑动窗口内的字节数"""
        w = window or self._recent_window
        return sum(b for t, b in byte_timestamps if now - t <= w)

    def _recent_bytes(self, host: HostStats, now: float, window: float = None) -> int:
        """统计主机滑动窗口内的字节数"""
        w = window or self._recent_window
        return sum(b for t, b in host.byte_timestamps if now - t <= w)

    # ==================== 基线 ====================

    def start_baseline_learning(self, duration: float = 3600):
        self._learning = True
        self._learning_start = time.time()
        self._learning_duration = duration
        logger.info(f"基线学习开始，持续 {duration} 秒")

    def get_baselines(self) -> List[Baseline]:
        with self._lock:
            return list(self._baselines.values())

    def get_host_baseline(self, host_ip: str) -> Optional[Baseline]:
        with self._lock:
            return self._baselines.get(host_ip)

    def _build_baseline(self, host: HostStats, now: float) -> Baseline:
        """从 HostStats 近期数据建立 Baseline"""
        recent_conn = self._count_recent(host.conn_timestamps, now)
        recent_bytes = self._recent_bytes(host, now)
        recent_ports = self._count_unique_recent(host.port_timestamps, now)
        recent_peers = self._count_unique_recent(host.peer_timestamps, now)

        minutes = max(self._recent_window / 60.0, 1.0)

        return Baseline(
            host_ip=host.ip,
            conn_avg_per_min=recent_conn / minutes,
            conn_max_per_min=recent_conn / minutes,
            conn_std_per_min=0.0,
            unique_ports=recent_ports,
            common_ports=sorted(host.all_ports)[:20],
            bw_avg=recent_bytes / max(self._recent_window, 1),
            bw_max=recent_bytes / max(self._recent_window, 1),
            internal_peers=list(host.all_peers),
            internal_ratio=0.0,
            sample_count=recent_conn,
        )

    def _update_baselines_ema(self, now: float):
        """用 EMA 持续更新基线"""
        with self._lock:
            for ip, host in self._hosts.items():
                recent = self._build_baseline(host, now)
                if ip in self._baselines:
                    old = self._baselines[ip]
                    alpha = self._baseline_ema_alpha
                    old.conn_avg_per_min = alpha * recent.conn_avg_per_min + (1 - alpha) * old.conn_avg_per_min
                    old.conn_max_per_min = max(old.conn_max_per_min, recent.conn_max_per_min)
                    old.unique_ports = int(alpha * recent.unique_ports + (1 - alpha) * old.unique_ports)
                    old.bw_avg = alpha * recent.bw_avg + (1 - alpha) * old.bw_avg
                    old.bw_max = max(old.bw_max, recent.bw_max)
                    old.internal_peers = list(set(old.internal_peers) | set(recent.internal_peers))
                    old.sample_count += recent.sample_count
                    old.updated_at = now
                else:
                    self._baselines[ip] = recent

        self._last_baseline_update = now
        logger.debug(f"基线 EMA 更新完成，{len(self._baselines)} 个主机")

    # ==================== 告警工厂 ====================

    def _make_alert(self, record: TrafficRecord, attack_type: str,
                     severity: AlertSeverity, title: str,
                     matched: str, suggestion: str) -> Alert:
        attack_info = get_attack_info(attack_type)
        return Alert(
            timestamp=time.time(),
            attack_type=attack_type,
            attack_name=attack_info.get("name", attack_type),
            severity=severity,
            confidence=0.85,
            alert_source=AlertType.ANOMALY,
            src_ip=record.src.ip,
            src_port=record.src.port,
            dst_ip=record.dst.ip,
            dst_port=record.dst.port,
            protocol=record.protocol.value,
            title=title,
            description=title,
            matched_pattern=matched,
            payload_snippet=record.payload[:200] if record.payload else "",
            suggestion=suggestion,
            flow_id=record.flow_id,
            traffic_record_id=record.id,
        )

    # ==================== 回调 ====================

    def set_on_alert_callback(self, callback: Callable[[Alert], None]):
        self._on_alert = callback

    def set_on_chain_callback(self, callback: Callable[[AttackChain], None]):
        self._on_chain = callback

    # ==================== ★ 主检测（插件化） ====================

    def process_traffic(self, record: TrafficRecord) -> List[Alert]:
        # 白名单检查
        if record.src.ip in WHITELIST_IPS or record.dst.ip in WHITELIST_IPS:
            return []

        alerts: List[Alert] = []
        now = time.time()

        # ---- 定期维护 ----
        if now - self._last_cleanup > self._cleanup_interval:
            self._prune_expired(now)
            self._last_cleanup = now

            if not self._learning and now - self._last_baseline_update > 60:
                self._update_baselines_ema(now)

        # ---- 更新主机统计 ----
        src_ip = record.src.ip
        dst_ip = record.dst.ip
        dst_port = record.dst.port

        with self._lock:
            if src_ip not in self._hosts:
                self._hosts[src_ip] = HostStats(src_ip)
            host = self._hosts[src_ip]

            host.total_conn += 1
            host.total_bytes += record.payload_size
            host.conn_timestamps.append(now)
            host.byte_timestamps.append((now, record.payload_size))
            host.all_ports.add(dst_port)
            host.all_peers.add(dst_ip)
            host.port_timestamps[dst_port].append(now)
            host.peer_timestamps[dst_ip].append(now)
            host.service_attempts[(dst_ip, dst_port)].append(now)
            host.last_seen = now

            if record.is_syn():
                host.total_syn += 1
                self._syn_timestamps.append(now)

        # ---- 学习模式 ----
        if self._learning:
            if self._learning_duration > 0 and (now - self._learning_start) >= self._learning_duration:
                self._finish_learning(now)
            return alerts

        # ---- ★ 遍历所有检测器插件 ----
        for detector in self._detectors:
            if not detector.enabled:
                continue
            try:
                result = detector.process(record, now)
                if result:
                    alerts.extend(result)
            except Exception as e:
                logger.error(f"检测器 {detector.name} 异常: {e}")

        # ---- 降噪 ----
        if self._config.get("enable_noise_reduction", True):
            min_sev = self._config.get("noise_min_severity", 3)
            before = len(alerts)
            alerts = [a for a in alerts if a.severity.value >= min_sev]
            self._noise_reduced_count += (before - len(alerts))

        # ---- 回调 ----
        for alert in alerts:
            self._anomaly_alert_count += 1
            if self._on_alert:
                self._on_alert(alert)

        return alerts

    # ==================== 攻击链 ====================

    def _update_attack_chain(self, record: TrafficRecord, alerts: List[Alert]):
        pass  # 保留为未来扩展

    # ==================== 统计 ====================

    def get_statistics(self) -> dict:
        with self._lock:
            detector_stats = {}
            for d in self._detectors:
                s = d.get_statistics()
                if s:
                    detector_stats[d.name] = s

            return {
                "hosts_tracked": len(self._hosts),
                "baselines_established": len(self._baselines),
                "anomaly_alerts": self._anomaly_alert_count,
                "behavior_deviations": self._behavior_deviation_count,
                "chains_detected": len(self._chains),
                "noise_reduced": self._noise_reduced_count,
                "learning_mode": self._learning,
                "detectors_loaded": len([d for d in self._detectors if d.enabled]),
                "detector_stats": detector_stats,
            }

    def get_host_statistics(self) -> List[dict]:
        now = time.time()
        with self._lock:
            result = []
            for host in self._hosts.values():
                result.append({
                    "ip": host.ip,
                    "total_conn": host.total_conn,
                    "recent_conn_5min": self._count_recent(host.conn_timestamps, now, 300),
                    "recent_ports_5min": self._count_unique_recent(host.port_timestamps, now, 300),
                    "recent_peers_5min": self._count_unique_recent(host.peer_timestamps, now, 300),
                    "total_bytes": host.total_bytes,
                    "all_ports": len(host.all_ports),
                    "all_peers": len(host.all_peers),
                    "last_seen": host.last_seen,
                })
            return result

    def reset_statistics(self):
        with self._lock:
            self._hosts.clear()
            self._baselines.clear()
            self._syn_timestamps.clear()
            self._known_external.clear()
            self._anomaly_alert_count = 0
            self._behavior_deviation_count = 0
            self._chains.clear()
            self._active_chain = None
            for d in self._detectors:
                d.on_stats_reset()
        logger.info("统计已重置")

    def _on_config_change(self, data: dict):
        """响应 GUI 重置按钮"""
        if data and data.get("action") == "reset":
            self.reset_statistics()

    # ==================== 内部方法 ====================

    def _finish_learning(self, now: float):
        with self._lock:
            for ip, host in self._hosts.items():
                self._baselines[ip] = self._build_baseline(host, now)
            self._last_baseline_update = now
        self._learning = False
        logger.info(f"基线学习完成，{len(self._baselines)} 个主机基线已建立")

    def _prune_expired(self, now: float):
        """清理过期数据：删除 10 分钟未活跃的主机"""
        with self._lock:
            expired = [ip for ip, h in self._hosts.items() if now - h.last_seen > 600]
            for ip in expired:
                del self._hosts[ip]
                self._baselines.pop(ip, None)

        self._syn_timestamps = [t for t in self._syn_timestamps if now - t <= self._recent_window]
