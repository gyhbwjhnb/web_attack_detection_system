"""
模块三：异常行为检测引擎

检测能力:
  - 端口扫描
  - 暴力破解
  - 异常外联
  - 内网横向扩散
  - SYN Flood
  - 带宽异常
  - 基线学习与对比

用法:
    from module3_anomaly import AnomalyEngine

    engine = AnomalyEngine()
    engine.start_baseline_learning(duration=3600)
    engine.set_on_alert_callback(lambda alert: print(alert))

    for record in traffic_records:
        alerts = engine.process_traffic(record)
"""

from module3_anomaly.anomaly_engine import AnomalyEngine

__all__ = ["AnomalyEngine"]
