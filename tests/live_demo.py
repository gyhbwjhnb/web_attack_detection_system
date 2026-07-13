"""
实机演示脚本 —— 用模拟攻击流量推送到 GUI，展示完整系统运行效果。

无需 Npcap / 管理员权限，直接运行:
    python tests/live_demo.py
"""

import sys
import os
import time
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import message_bus
from module1_capture.packet_parser import create_fake_http_record, create_fake_dns_record
from module3_anomaly import AnomalyEngine
from module4_gui import MainWindow

# ===== 初始化模块3 =====
engine = AnomalyEngine({"enable_noise_reduction": False, "baseline_min_samples": 3})

# ===== 初始化模块4 GUI =====
gui = MainWindow()
gui._running = True
gui._start_time = time.time()
gui._btn_start.config(state="disabled")
gui._btn_stop.config(state="normal")
gui._lbl_status.config(text="● 运行中（模拟流量）", foreground="green")
gui._status_text.set("实时模拟攻击流量中...")

# 模块4 已订阅 EVENT_ANOMALY_ALERT 和 EVENT_STATISTICS

# ===== 模拟流量发生器（后台线程） =====

def simulate_traffic():
    """模拟多种攻击场景，每条流量送入检测管道"""
    time.sleep(2)

    # 阶段1: 正常流量（建立基线）
    gui._status_text.set("阶段1: 正常流量基线学习...")
    for i in range(20):
        r = create_fake_http_record(method="GET", uri=f"/page{i}.html", dst_port=80)
        push(r)
        time.sleep(0.1)

    engine.start_baseline_learning(duration=0.1)
    time.sleep(0.2)
    engine.process_traffic(create_fake_http_record())

    # 阶段2: 端口扫描
    gui._status_text.set("阶段2: 模拟端口扫描...")
    for port in range(8000, 8020):
        r = create_fake_http_record(dst_port=port)
        push(r)
        time.sleep(0.05)

    # 阶段3: 暴力破解 SSH
    gui._status_text.set("阶段3: 模拟 SSH 暴力破解...")
    for _ in range(10):
        r = create_fake_http_record(dst_ip="10.0.0.5", dst_port=22)
        push(r)
        time.sleep(0.05)

    # 阶段4: 异常外联
    gui._status_text.set("阶段4: 模拟异常外联 (C2通信)...")
    for _ in range(3):
        r = create_fake_http_record(src_ip="192.168.1.50", dst_ip="45.33.32.156", dst_port=4444)
        push(r)
        time.sleep(0.1)

    # 阶段5: DNS 隧道
    gui._status_text.set("阶段5: 模拟 DNS 查询...")
    for i in range(5):
        r = create_fake_dns_record(query=f"tunnel-data-{i}.evil.c2.com")
        push(r)
        time.sleep(0.1)

    # 阶段6: 行为突变（大量突发连接）
    gui._status_text.set("阶段6: 模拟行为突变（突发连接）...")
    for i in range(80):
        r = create_fake_http_record(dst_port=8000 + i % 80)
        push(r)
        time.sleep(0.02)

    gui._status_text.set("模拟完成！可在 GUI 查看所有告警")


def push(record):
    """送入模块3检测，告警通过消息总线推给 GUI"""
    alerts = engine.process_traffic(record)
    for alert in alerts:
        message_bus.publish(message_bus.EVENT_ANOMALY_ALERT, alert)
    # 推送统计
    message_bus.publish(message_bus.EVENT_STATISTICS, engine.get_statistics())


# ===== 启动 =====
t = threading.Thread(target=simulate_traffic, daemon=True)
t.start()

print("=" * 60)
print("  实机演示已启动")
print("  GUI 窗口将依次展示:")
print("    1. 正常流量基线学习")
print("    2. 端口扫描检测")
print("    3. SSH 暴力破解检测")
print("    4. 异常外联 (C2) 检测")
print("    5. DNS 隧道查询")
print("    6. 行为突变检测")
print("=" * 60)

gui.run()
