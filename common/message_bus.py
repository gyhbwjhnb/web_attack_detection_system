"""
============================================================================
消息总线（MessageBus）—— 发布-订阅模式实现模块间解耦通信
============================================================================

每个模块通过 subscribe 注册回调、publish 发送消息，
不需要知道其他模块的实现细节。

用法:
    from common.message_bus import message_bus
    from common.data_structures import TrafficRecord, Alert

    # ---- 模块1：发送流量记录 ----
    def on_packet_parsed(record: TrafficRecord):
        message_bus.publish("traffic_record", record)

    # ---- 模块2：接收流量 + 发送告警 ----
    def handle_traffic(record: TrafficRecord):
        alerts = engine.process(record)
        for alert in alerts:
            message_bus.publish("signature_alert", alert)

    message_bus.subscribe("traffic_record", handle_traffic)

    # ---- 模块4：接收告警 ----
    def handle_alert(alert: Alert):
        gui.add_alert(alert)

    message_bus.subscribe("signature_alert", handle_alert)
    message_bus.subscribe("anomaly_alert", handle_alert)
============================================================================
"""

import logging
from typing import Any, Callable, Dict, List

logger = logging.getLogger("MessageBus")


class MessageBus:
    """
    简易消息总线 —— 基于发布-订阅模式实现模块间解耦通信。

    标准事件名清单:
        traffic_record    — 模块1 → 模块2/3, 载荷: TrafficRecord
        signature_alert   — 模块2 → 模块4,   载荷: Alert
        anomaly_alert     — 模块3 → 模块4,   载荷: Alert
        attack_chain      — 模块3 → 模块4,   载荷: AttackChain
        statistics        — 模块1/2/3 → 模块4, 载荷: dict
        config_change     — 模块4 → 模块1/2/3, 载荷: dict
    """

    # 标准事件名常量
    EVENT_TRAFFIC_RECORD  = "traffic_record"
    EVENT_SIGNATURE_ALERT = "signature_alert"
    EVENT_ANOMALY_ALERT   = "anomaly_alert"
    EVENT_ATTACK_CHAIN    = "attack_chain"
    EVENT_STATISTICS      = "statistics"
    EVENT_CONFIG_CHANGE   = "config_change"

    def __init__(self):
        self._subscribers: Dict[str, List[Callable]] = {}
        self._message_count: Dict[str, int] = {}

    # ---- 订阅与取消 ----

    def subscribe(self, event_type: str, callback: Callable):
        """
        订阅某类事件。

        Args:
            event_type: 事件名，如 "traffic_record", "signature_alert"
            callback:   回调函数，接收一个参数（事件载荷）
        """
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        if callback not in self._subscribers[event_type]:
            self._subscribers[event_type].append(callback)

    def unsubscribe(self, event_type: str, callback: Callable):
        """取消订阅"""
        if event_type in self._subscribers:
            self._subscribers[event_type] = [
                cb for cb in self._subscribers[event_type]
                if cb is not callback
            ]

    # ---- 发布 ----

    def publish(self, event_type: str, data: Any):
        """
        发布事件，通知所有订阅者。

        Args:
            event_type: 事件名
            data:       事件载荷（TrafficRecord / Alert / AttackChain / dict 等）
        """
        self._message_count[event_type] = self._message_count.get(event_type, 0) + 1

        subscribers = self._subscribers.get(event_type, [])
        if not subscribers:
            return

        for callback in subscribers:
            try:
                callback(data)
            except Exception as e:
                logger.error(f"[{event_type}] 回调异常: {e}", exc_info=True)

    # ---- 查询 ----

    def subscriber_count(self, event_type: str = None) -> int:
        """查询订阅者数量，不传参返回总数"""
        if event_type:
            return len(self._subscribers.get(event_type, []))
        return sum(len(v) for v in self._subscribers.values())

    def get_statistics(self) -> dict:
        """获取消息总线统计信息"""
        return {
            "message_counts": dict(self._message_count),
            "total_subscribers": self.subscriber_count(),
            "event_types": list(self._subscribers.keys()),
        }

    def reset_statistics(self):
        """重置消息计数"""
        self._message_count.clear()


# 全局单例 —— 所有模块共享同一个 MessageBus 实例
message_bus = MessageBus()
