"""
============================================================================
MessageBus 集成层 —— 模块2 与模块1/4 的通信桥梁
============================================================================

职责:
  1. 订阅 MessageBus 的 "traffic_record" 事件，转发给 SignatureEngine
  2. SignatureEngine 产出的 Alert 自动发布到 "signature_alert" 事件
  3. 订阅 "config_change" 事件，动态更新引擎配置
  4. 提供 connect() / disconnect() 一对函数，一行代码完成集成

数据流:
  Module1 --publish("traffic_record")--> MessageBus
  MessageBus --subscribe--> integration._on_traffic_record
  integration --engine.process_traffic()--> List[Alert]
  engine._fire_alert() --publish("signature_alert")--> MessageBus
  MessageBus --subscribe--> Module4 (GUI)

  Module4 --publish("config_change")--> MessageBus
  MessageBus --subscribe--> integration._on_config_change
  integration --engine.enable_category() / engine.load_rules()--> 更新配置

用法:
    # 在 main.py 中:
    from module2_signature import SignatureEngine
    from module2_signature.integration import connect, disconnect

    engine = SignatureEngine()
    engine.load_rules("data/signatures.json")
    connect(engine)

    # ... 系统运行 ...

    disconnect(engine)
============================================================================
"""

from typing import Optional

from common.data_structures import TrafficRecord, Alert
from common.message_bus import message_bus
from common.utils import setup_logger

from module2_signature.signature_engine import SignatureEngine


logger = setup_logger("module2_integration", "logs/module2_signature.log")


# 保存注册的回调引用，用于 disconnect 时取消订阅
_registered_handlers: dict = {}


def connect(engine: SignatureEngine) -> None:
    """
    一次性完成 Module 2 与 MessageBus 的全部订阅。

    订阅事件:
      - "traffic_record": 接收模块1 的流量记录 → 调用 engine.process_traffic
      - "config_change":  接收模块4 的配置变更 → 更新引擎参数

    调用此函数后，SignatureEngine 的告警会自动发布到 MessageBus。

    Args:
        engine: SignatureEngine 实例（需已调用 load_rules）
    """
    global _registered_handlers

    # --- 1. 订阅流量记录 ---
    def _on_traffic_record(record: TrafficRecord):
        """接收模块1 的 TrafficRecord，驱动特征匹配检测。"""
        try:
            engine.process_traffic(record)
        except Exception as e:
            logger.error("处理流量记录异常: %s", e, exc_info=True)

    message_bus.subscribe(message_bus.EVENT_TRAFFIC_RECORD, _on_traffic_record)
    logger.info("已订阅 '%s' 事件", message_bus.EVENT_TRAFFIC_RECORD)

    # --- 2. 订阅配置变更 ---
    def _on_config_change(config: dict):
        """
        接收模块4 的配置变更事件。

        支持的配置项（config 字典中 "signature" 字段）:
          - enable_<category>: 启用/禁用某类检测
          - rules_file: 重新加载特征库
          - brute_force_threshold: 暴力破解阈值
          - brute_force_window: 暴力破解窗口
          - alert_dedup_window: 告警去重窗口
        """
        if not isinstance(config, dict):
            return

        sig_config = config.get("signature")
        if sig_config is None:
            return

        logger.info("收到配置变更: %s", sig_config)

        try:
            # 处理分类开关
            category_keys = [
                "enable_sql_injection",
                "enable_xss",
                "enable_command_injection",
                "enable_web_attack",
                "enable_malware_c2",
                "enable_brute_force",
            ]
            category_map = {
                "enable_sql_injection":     "sql_injection",
                "enable_xss":               "xss",
                "enable_command_injection": "command_injection",
                "enable_web_attack":        "web_attack",
                "enable_malware_c2":        "malware_c2",
                "enable_brute_force":       "brute_force",
            }
            for key in category_keys:
                if key in sig_config:
                    category = category_map[key]
                    engine.enable_category(category, bool(sig_config[key]))

            # 处理特征库重新加载
            if "rules_file" in sig_config:
                count = engine.load_rules(sig_config["rules_file"])
                logger.info("重新加载特征库: %d 条规则", count)

            # 处理暴力破解参数
            if "brute_force_threshold" in sig_config:
                engine._brute_force_threshold = int(sig_config["brute_force_threshold"])
                logger.info("暴力破解阈值已更新: %d", engine._brute_force_threshold)

            if "brute_force_window" in sig_config:
                engine._brute_force_window = int(sig_config["brute_force_window"])
                logger.info("暴力破解窗口已更新: %d 秒", engine._brute_force_window)

            # 处理告警去重窗口
            if "alert_dedup_window" in sig_config:
                engine._dedup_window = int(sig_config["alert_dedup_window"])
                logger.info("告警去重窗口已更新: %d 秒", engine._dedup_window)

        except Exception as e:
            logger.error("处理配置变更异常: %s", e, exc_info=True)

    message_bus.subscribe(message_bus.EVENT_CONFIG_CHANGE, _on_config_change)
    logger.info("已订阅 '%s' 事件", message_bus.EVENT_CONFIG_CHANGE)

    # --- 3. 将告警发布函数注入引擎 ---
    engine.set_on_alert_callback(_publish_alert)
    logger.info("MessageBus 集成完成")

    # 保存引用用于 disconnect
    _registered_handlers = {
        "traffic_record": _on_traffic_record,
        "config_change": _on_config_change,
    }


def disconnect(engine: SignatureEngine) -> None:
    """
    取消所有 MessageBus 订阅。

    Args:
        engine: 之前调用 connect() 时传入的 SignatureEngine 实例
    """
    global _registered_handlers

    if "traffic_record" in _registered_handlers:
        message_bus.unsubscribe(
            message_bus.EVENT_TRAFFIC_RECORD,
            _registered_handlers["traffic_record"],
        )
    if "config_change" in _registered_handlers:
        message_bus.unsubscribe(
            message_bus.EVENT_CONFIG_CHANGE,
            _registered_handlers["config_change"],
        )

    # 清除引擎回调（设为空操作 lambda）
    engine.set_on_alert_callback(lambda alert: None)

    _registered_handlers = {}
    logger.info("MessageBus 集成已断开")


def _publish_alert(alert: Alert) -> None:
    """将告警发布到 MessageBus 的 signature_alert 事件。"""
    try:
        message_bus.publish(message_bus.EVENT_SIGNATURE_ALERT, alert)
    except Exception as e:
        logger.error("发布告警到 MessageBus 失败: %s", e)