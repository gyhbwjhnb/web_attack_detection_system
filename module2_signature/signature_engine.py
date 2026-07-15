"""
============================================================================
特征匹配检测引擎 —— 模块2 核心
============================================================================

职责:
  1. 加载 JSON 格式的攻击特征规则库
  2. 使用 Aho-Corasick 多模式匹配算法高效检测
  3. 对 TrafficRecord 的载荷（payload / HTTP 全字段）做特征扫描
  4. 暴力破解检测：基于登录失败消息的频次统计
  5. 告警去重：同源同目的同攻击类型在窗口期内不重复告警
  6. 支持按攻击类别启用/禁用检测
  7. 统计信息收集

用法:
    from module2_signature.signature_engine import SignatureEngine

    engine = SignatureEngine()
    engine.load_rules("data/signatures.json")
    engine.set_on_alert_callback(lambda alert: print(alert))

    for record in traffic_stream:
        alerts = engine.process_traffic(record)

接口实现:
    实现了 common.engine.ISignatureEngine 的全部抽象方法。
============================================================================
"""

import json
import time
import threading
from pathlib import Path
from typing import List, Dict, Optional, Callable, Tuple

from common.data_structures import (
    TrafficRecord, Alert, SignatureRule,
    AlertSeverity, AlertType, AlertStatus,
)
from common.config import SIGNATURE_CONFIG, ATTACK_TYPES, SEVERITY_LEVELS, WHITELIST_IPS
from common.engine import ISignatureEngine
from common.utils import setup_logger

from module2_signature.matcher import AhoCorasickMatcher


logger = setup_logger("module2_signature", "logs/module2_signature.log")


class SignatureEngine(ISignatureEngine):
    """
    特征匹配检测引擎。

    内部使用 AhoCorasickMatcher 做多模式匹配，同时维护:
      - 规则库 (SignatureRule 列表)
      - 暴力破解计数器
      - 告警去重表
      - 统计数据
    """

    def __init__(self):
        # --- 规则与匹配器 ---
        self._rules: Dict[str, SignatureRule] = {}  # rule_id -> SignatureRule
        self._matcher = AhoCorasickMatcher(case_sensitive=False, url_decode=True)

        # --- 分类开关 ---
        self._category_enabled: Dict[str, bool] = {
            "sql_injection":     SIGNATURE_CONFIG.get("enable_sql_injection", True),
            "xss":               SIGNATURE_CONFIG.get("enable_xss", True),
            "command_injection": SIGNATURE_CONFIG.get("enable_command_injection", True),
            "web_attack":        SIGNATURE_CONFIG.get("enable_web_attack", True),
            "malware_c2":        SIGNATURE_CONFIG.get("enable_malware_c2", True),
            "brute_force":       SIGNATURE_CONFIG.get("enable_brute_force", True),
        }

        # --- 暴力破解检测 ---
        # key: (src_ip, dst_ip, dst_port) -> list of timestamps
        self._login_failures: Dict[Tuple[str, str, int], List[float]] = {}
        self._brute_force_threshold: int = SIGNATURE_CONFIG.get("brute_force_threshold", 10)
        self._brute_force_window: int = SIGNATURE_CONFIG.get("brute_force_window", 60)
        # 已触发的暴力破解告警，避免重复: (src, dst, port) -> last_alert_time
        self._brute_force_alerted: Dict[Tuple[str, str, int], float] = {}

        # --- 告警去重 ---
        # key: (src_ip, dst_ip, attack_type) -> last_alert_timestamp
        self._dedup_cache: Dict[Tuple[str, str, str], float] = {}
        self._dedup_window: int = SIGNATURE_CONFIG.get("alert_dedup_window", 300)

        # --- 回调 ---
        self._on_alert_callback: Optional[Callable[[Alert], None]] = None

        # --- 统计 ---
        self._lock = threading.Lock()
        self._total_alerts: int = 0
        self._alerts_by_type: Dict[str, int] = {}
        self._traffic_processed: int = 0

    # ==================================================================
    # ISignatureEngine 接口实现
    # ==================================================================

    def load_rules(self, rule_file: Optional[str] = None) -> int:
        """
        从 JSON 文件加载攻击特征规则。

        Args:
            rule_file: JSON 文件路径，None 则使用 SIGNATURE_CONFIG["rules_file"] 默认值。

        Returns:
            成功加载的规则数量。
        """
        if rule_file is None:
            rule_file = SIGNATURE_CONFIG.get("rules_file", "data/signatures.json")

        filepath = Path(str(rule_file))
        if not filepath.exists():
            logger.warning("规则文件不存在: %s", rule_file)
            return 0

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                raw_rules = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.error("加载规则文件失败: %s  错误: %s", rule_file, e)
            return 0

        # 清空旧规则和匹配器
        self._rules.clear()
        self._matcher.clear()

        loaded = 0
        for item in raw_rules:
            try:
                rule = SignatureRule.from_dict(item)
                if not rule.rule_id or not rule.pattern:
                    continue
                self._rules[rule.rule_id] = rule
                self._matcher.add_pattern(rule.pattern, rule.rule_id)
                loaded += 1
            except Exception as e:
                logger.warning("跳过无效规则: %s  错误: %s", item.get("rule_id", "?"), e)

        self._matcher.build()
        logger.info("特征库加载完成: %s, 共 %d 条规则", rule_file, loaded)
        return loaded

    def process_traffic(self, record: TrafficRecord) -> List[Alert]:
        """
        处理一条流量记录，执行特征匹配检测。

        流程:
          1. 提取待检测文本（HTTP 全字段 > payload）
          2. 通过 AhoCorasickMatcher 多模式匹配
          3. 对命中的规则做协议/端口过滤、分类开关过滤
          4. 暴力破解特殊处理（频次检测）
          5. 告警去重
          6. 生成 Alert 列表并通过回调通知

        Args:
            record: 模块1 输出的 TrafficRecord

        Returns:
            检测到的 Alert 列表（可能为空）
        """
        with self._lock:
            # 白名单检查：来源或目标 IP 在白名单中 → 静默
            if record.src.ip in WHITELIST_IPS or record.dst.ip in WHITELIST_IPS:
                return []

            self._traffic_processed += 1

        alerts: List[Alert] = []

        try:
            # --- 1. 提取待检测文本 ---
            text_to_scan = self._extract_scan_text(record)
            if not text_to_scan:
                # 载荷为空，无法匹配
                return alerts

            # --- 2. Aho-Corasick 多模式匹配 ---
            matches = self._matcher.search(text_to_scan)

            # --- 3. 去重 + 过滤 + 生成告警 ---
            seen_rules: set = set()
            for rule_id, matched_pattern, position in matches:
                if rule_id in seen_rules:
                    continue
                seen_rules.add(rule_id)

                rule = self._rules.get(rule_id)
                if rule is None:
                    continue

                # 分类开关检查
                if not self._is_category_enabled(rule.attack_type):
                    continue

                # 协议过滤
                if rule.protocol != "ANY" and rule.protocol != record.protocol.value:
                    continue

                # 端口过滤
                if rule.dst_port != 0 and rule.dst_port != record.dst.port:
                    continue

                # --- 4. 暴力破解特殊处理 ---
                if rule.attack_type == "brute_force":
                    bf_alerts = self._handle_brute_force_match(record, rule, matched_pattern)
                    alerts.extend(bf_alerts)
                    continue

                # --- 5. 告警去重 ---
                dedup_key = (record.src.ip, record.dst.ip, rule.attack_type)
                if self._is_dedup(dedup_key):
                    continue

                # --- 6. 生成 Alert ---
                alert = self._create_alert(record, rule, matched_pattern)
                alerts.append(alert)

        except Exception as e:
            logger.error("特征匹配检测异常: %s", e, exc_info=True)

        # 触发回调
        for alert in alerts:
            self._fire_alert(alert)

        return alerts

    def set_on_alert_callback(self, callback: Callable[[Alert], None]):
        """注册告警回调函数。"""
        self._on_alert_callback = callback

    def get_rule_count(self) -> int:
        """获取当前已加载的规则总数。"""
        return len(self._rules)

    def add_custom_rule(self, rule: dict) -> bool:
        """
        动态添加一条自定义规则并重建匹配器。

        Args:
            rule: 规则字典，需包含 rule_id, pattern, attack_name, attack_type 等字段。

        Returns:
            True 添加成功，False 失败（如 rule_id 重复或 pattern 为空）。
        """
        try:
            sig_rule = SignatureRule.from_dict(rule)
            if not sig_rule.rule_id or not sig_rule.pattern:
                return False
            if sig_rule.rule_id in self._rules:
                logger.warning("规则 ID 已存在: %s", sig_rule.rule_id)
                return False

            self._rules[sig_rule.rule_id] = sig_rule
            self._rebuild_matcher()
            logger.info("动态添加规则: %s (%s)", sig_rule.rule_id, sig_rule.attack_name)
            return True
        except Exception as e:
            logger.error("添加自定义规则失败: %s", e)
            return False

    def remove_rule(self, rule_id: str) -> bool:
        """移除一条规则并重建匹配器。"""
        if rule_id not in self._rules:
            return False
        del self._rules[rule_id]
        self._rebuild_matcher()
        logger.info("移除规则: %s", rule_id)
        return True

    def enable_category(self, category: str, enabled: bool):
        """
        启用/禁用某类检测。

        Args:
            category: 攻击类型标识，如 "sql_injection", "xss" 等。
            enabled: True 启用 / False 禁用。
        """
        self._category_enabled[category] = enabled
        logger.info("分类 %s 已 %s", category, "启用" if enabled else "禁用")

    def get_statistics(self) -> dict:
        """获取检测统计信息。"""
        with self._lock:
            return {
                "total_alerts": self._total_alerts,
                "alerts_by_type": dict(self._alerts_by_type),
                "rules_loaded": len(self._rules),
                "traffic_processed": self._traffic_processed,
                "categories_enabled": {
                    k: v for k, v in self._category_enabled.items() if v
                },
            }

    # ==================================================================
    # 内部辅助方法
    # ==================================================================

    def _extract_scan_text(self, record: TrafficRecord) -> str:
        """
        从 TrafficRecord 中提取待扫描文本。

        优先使用 HTTP 全字段（URI + body + headers 等），
        否则使用 payload 文本。
        """
        # HTTP 流量：拼接所有 HTTP 相关字段
        if record.http_uri or record.http_body:
            return record.all_http_text

        # 普通流量：使用 payload
        if record.payload:
            return record.payload

        return ""

    def _is_category_enabled(self, attack_type: str) -> bool:
        """检查攻击类型是否启用检测。"""
        # 映射 attack_type 到分类开关
        category_map = {
            "sql_injection":     "sql_injection",
            "xss":               "xss",
            "command_injection": "command_injection",
            "path_traversal":    "web_attack",
            "lfi":               "web_attack",
            "rfi":               "web_attack",
            "webshell":          "web_attack",
            "brute_force":       "brute_force",
            "malware_c2":        "malware_c2",
            "reverse_shell":     "malware_c2",
            "dns_tunnel":        "malware_c2",
        }
        category = category_map.get(attack_type, attack_type)
        return self._category_enabled.get(category, True)

    def _is_dedup(self, key: Tuple[str, str, str]) -> bool:
        """告警去重检查：同源同目的同类型在窗口期内是否已告警。"""
        now = time.time()
        last_time = self._dedup_cache.get(key, 0)
        if now - last_time < self._dedup_window:
            return True
        self._dedup_cache[key] = now
        return False

    def _create_alert(self, record: TrafficRecord,
                      rule: SignatureRule,
                      matched_pattern: str) -> Alert:
        """根据匹配结果生成 Alert 对象。"""
        attack_info = ATTACK_TYPES.get(rule.attack_type, {})
        severity_val = rule.severity if 1 <= rule.severity <= 5 else 3
        try:
            severity = AlertSeverity(severity_val)
        except ValueError:
            severity = AlertSeverity.MEDIUM

        # 截取载荷片段（前 200 字符）
        snippet = (record.payload or "")[:200]

        alert = Alert(
            attack_type=rule.attack_type,
            attack_name=rule.attack_name,
            severity=severity,
            confidence=0.9,
            status=AlertStatus.NEW,
            alert_source=AlertType.SIGNATURE,
            rule_id=rule.rule_id,
            src_ip=record.src.ip,
            src_port=record.src.port,
            dst_ip=record.dst.ip,
            dst_port=record.dst.port,
            protocol=record.protocol.value,
            title=f"[{attack_info.get('name', rule.attack_type)}] {rule.attack_name}",
            description=rule.description,
            matched_pattern=matched_pattern,
            payload_snippet=snippet,
            suggestion=f"检查来源 {record.src.ip} 的请求是否包含恶意内容",
            flow_id=record.flow_id,
            traffic_record_id=record.id,
            tags=[rule.attack_type, "signature"],
        )

        with self._lock:
            self._total_alerts += 1
            self._alerts_by_type[rule.attack_type] = (
                self._alerts_by_type.get(rule.attack_type, 0) + 1
            )

        logger.warning(
            "检测到攻击: %s | 规则=%s | %s:%d -> %s:%d",
            rule.attack_name, rule.rule_id,
            record.src.ip, record.src.port,
            record.dst.ip, record.dst.port,
        )
        return alert

    def _fire_alert(self, alert: Alert):
        """触发告警回调。"""
        if self._on_alert_callback:
            try:
                self._on_alert_callback(alert)
            except Exception as e:
                logger.error("告警回调异常: %s", e)

    def _rebuild_matcher(self):
        """重建 Aho-Corasick 匹配器（增删规则后调用）。"""
        self._matcher.clear()
        for rule_id, rule in self._rules.items():
            self._matcher.add_pattern(rule.pattern, rule_id)
        self._matcher.build()

    # ------------------------------------------------------------------
    # 暴力破解检测
    # ------------------------------------------------------------------

    def _handle_brute_force_match(self, record: TrafficRecord,
                                  rule: SignatureRule,
                                  matched_pattern: str) -> List[Alert]:
        """
        处理暴力破解特征命中。

        逻辑:
          1. 记录本次登录失败的时间戳
          2. 清理过期记录
          3. 判断窗口期内失败次数是否超阈值
          4. 超阈值则生成告警（去重）
        """
        alerts: List[Alert] = []

        # 记录登录失败
        bf_key = (record.src.ip, record.dst.ip, record.dst.port)
        now = time.time()

        with self._lock:
            if bf_key not in self._login_failures:
                self._login_failures[bf_key] = []
            self._login_failures[bf_key].append(now)

            # 清理过期记录
            cutoff = now - self._brute_force_window
            self._login_failures[bf_key] = [
                t for t in self._login_failures[bf_key] if t > cutoff
            ]

            fail_count = len(self._login_failures[bf_key])

        if fail_count < self._brute_force_threshold:
            return alerts

        # 去重：同一组 (src, dst, port) 60 秒内只告警一次
        last_alert_time = self._brute_force_alerted.get(bf_key, 0)
        if now - last_alert_time < self._brute_force_window:
            return alerts
        self._brute_force_alerted[bf_key] = now

        # 生成暴力破解告警
        attack_info = ATTACK_TYPES.get("brute_force", {})
        try:
            severity = AlertSeverity(rule.severity)
        except ValueError:
            severity = AlertSeverity.MEDIUM

        alert = Alert(
            attack_type="brute_force",
            attack_name=f"暴力破解 - {fail_count}次失败登录",
            severity=severity,
            confidence=0.85,
            status=AlertStatus.NEW,
            alert_source=AlertType.SIGNATURE,
            rule_id=rule.rule_id,
            src_ip=record.src.ip,
            src_port=record.src.port,
            dst_ip=record.dst.ip,
            dst_port=record.dst.port,
            protocol=record.protocol.value,
            title=f"[暴力破解] {self._brute_force_window}秒内{fail_count}次登录失败",
            description=(
                f"来源 {record.src.ip} 在 {self._brute_force_window} 秒内 "
                f"向 {record.dst.ip}:{record.dst.port} 发起 {fail_count} 次失败登录，"
                f"疑似暴力破解攻击"
            ),
            matched_pattern=matched_pattern,
            payload_snippet=(record.payload or "")[:200],
            suggestion=f"封禁来源 IP {record.src.ip} 或启用账户锁定策略",
            flow_id=record.flow_id,
            traffic_record_id=record.id,
            tags=["brute_force", "signature"],
        )

        with self._lock:
            self._total_alerts += 1
            self._alerts_by_type["brute_force"] = (
                self._alerts_by_type.get("brute_force", 0) + 1
            )

        logger.warning(
            "检测到暴力破解: %s:%d -> %s:%d (%d次/%d秒)",
            record.src.ip, record.src.port,
            record.dst.ip, record.dst.port,
            fail_count, self._brute_force_window,
        )
        alerts.append(alert)
        return alerts

    def _check_brute_force(self, record: TrafficRecord) -> List[Alert]:
        """
        对无载荷的包也做暴力破解频次检查（如果已有累积记录）。
        通常在有载荷时由 _handle_brute_force_match 处理。
        """
        # 这里不做额外检查，暴力破解由特征命中触发
        return []

    # ------------------------------------------------------------------
    # 清理方法
    # ------------------------------------------------------------------

    def cleanup_expired(self):
        """清理过期的暴力破解计数器和去重缓存，防止内存膨胀。"""
        now = time.time()
        cutoff_bf = now - self._brute_force_window
        cutoff_dedup = now - self._dedup_window

        with self._lock:
            # 清理暴力破解计数器
            expired_bf = [
                k for k, v in self._login_failures.items()
                if not v or v[-1] < cutoff_bf
            ]
            for k in expired_bf:
                del self._login_failures[k]

            # 清理过期告警记录
            expired_bf_alert = [
                k for k, v in self._brute_force_alerted.items()
                if v < cutoff_bf
            ]
            for k in expired_bf_alert:
                del self._brute_force_alerted[k]

            # 清理去重缓存
            expired_dedup = [
                k for k, v in self._dedup_cache.items()
                if v < cutoff_dedup
            ]
            for k in expired_dedup:
                del self._dedup_cache[k]