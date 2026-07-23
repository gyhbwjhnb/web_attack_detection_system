"""
模块3 自测脚本 —— 验证异常行为检测引擎（滑动窗口 + EMA 自适应版）。

运行: python tests/test_module3.py
"""

import sys
sys.path.insert(0, ".")

import time
from module3_anomaly import AnomalyEngine
from common import TrafficRecord, IPEndpoint, Alert, ProtocolType, AlertSeverity

errors = []
total = 0
passed = 0


def check(name, actual, expected):
    global total, passed
    total += 1
    if actual == expected:
        passed += 1
        print(f"  [PASS] {name}")
    else:
        errors.append(f"  [FAIL] {name}: got={actual!r}, expected={expected!r}")
        print(f"  [FAIL] {name}: got={actual!r}, expected={expected!r}")


def make_record(src_ip="192.168.1.100", dst_ip="10.0.0.1",
                src_port=50000, dst_port=80, syn=False, payload_size=100,
                payload=""):
    r = TrafficRecord()
    r.src = IPEndpoint(ip=src_ip, port=src_port)
    r.dst = IPEndpoint(ip=dst_ip, port=dst_port)
    r.protocol = ProtocolType.TCP
    r.payload_size = payload_size
    r.payload = payload
    if syn:
        r.flags = r.FLAG_SYN
    return r


# ============================================================
print("=" * 50)
print("测试1: 基本初始化与接口")
print("=" * 50)

engine = AnomalyEngine()
check("init_hosts", engine.get_statistics()["hosts_tracked"], 0)
check("init_alerts", engine.get_statistics()["anomaly_alerts"], 0)
check("init_baselines", engine.get_statistics()["baselines_established"], 0)
check("init_learning", engine.get_statistics()["learning_mode"], False)
check("init_deviations", engine.get_statistics()["behavior_deviations"], 0)

received = []
engine.set_on_alert_callback(lambda a: received.append(a))

print()

# ============================================================
print("=" * 50)
print("测试2: 端口扫描检测")
print("=" * 50)

e2 = AnomalyEngine({"port_scan_threshold": 5, "port_scan_window_sec": 60, "enable_noise_reduction": False})

for port in range(8000, 8009):
    e2.process_traffic(make_record(dst_port=port, syn=True))

alerts = e2.process_traffic(make_record(dst_port=8009, syn=True))
scan = [a for a in alerts if a.attack_type == "port_scan"]
check("port_scan_detected", len(scan) >= 1, True)

print()

# ============================================================
print("=" * 50)
print("测试3: 暴力破解检测")
print("=" * 50)

e3 = AnomalyEngine({"brute_force_threshold": 3, "brute_force_window_sec": 60, "enable_noise_reduction": False})

# 发送含登录失败内容的连接（新行为：需要登录失败特征才用低阈值）
for i in range(5):
    e3.process_traffic(make_record(dst_ip="10.0.0.5", dst_port=22, syn=True,
                                    payload="Login failed for user root"))

alerts = e3.process_traffic(make_record(dst_ip="10.0.0.5", dst_port=22, syn=True,
                                         payload="Login failed for user root"))
brute = [a for a in alerts if a.attack_type == "brute_force"]
check("brute_detected", len(brute) >= 1, True)
if brute:
    check("brute_severity", brute[0].severity, AlertSeverity.HIGH)
    check("brute_src", brute[0].src_ip, "192.168.1.100")

print()

# ============================================================
print("=" * 50)
print("测试4: 异常外联检测")
print("=" * 50)

e4 = AnomalyEngine({"enable_noise_reduction": False})

# 新行为：首次连接非标准端口静默记录，第二次才告警
e4.process_traffic(make_record(src_ip="192.168.1.50", dst_ip="203.0.113.99", dst_port=4444, syn=True))
alerts = e4.process_traffic(make_record(src_ip="192.168.1.50", dst_ip="203.0.113.99", dst_port=4444, syn=True))
out = [a for a in alerts if a.attack_type == "abnormal_outbound"]
check("outbound_detected", len(out) >= 1, True)
if out:
    check("outbound_dst", out[0].dst_ip, "203.0.113.99")

# 标准端口（443）永远不告警
alerts2 = e4.process_traffic(make_record(src_ip="192.168.1.50", dst_ip="203.0.113.99", dst_port=443, syn=True))
out2 = [a for a in alerts2 if a.attack_type == "abnormal_outbound"]
check("outbound_dedup", len(out2), 0)

print()

# ============================================================
print("=" * 50)
print("测试5: 内网横向扩散检测")
print("=" * 50)

e5 = AnomalyEngine({"port_scan_threshold": 10, "port_scan_window_sec": 60, "enable_noise_reduction": False})

for i in range(1, 8):
    e5.process_traffic(make_record(src_ip="192.168.1.100", dst_ip=f"192.168.1.{i}", dst_port=445, syn=True))

alerts = e5.process_traffic(make_record(src_ip="192.168.1.100", dst_ip="192.168.1.8", dst_port=445, syn=True))
lat = [a for a in alerts if a.attack_type == "lateral_movement"]
check("lateral_detected", len(lat) >= 1, True)

print()

# ============================================================
print("=" * 50)
print("测试6: SYN Flood 检测")
print("=" * 50)

e6 = AnomalyEngine({"syn_flood_threshold": 5, "syn_flood_window_sec": 60, "enable_noise_reduction": False})

for _ in range(4):
    e6.process_traffic(make_record(dst_ip="10.0.0.1", dst_port=80, syn=True))

alerts = e6.process_traffic(make_record(dst_ip="10.0.0.1", dst_port=80, syn=True))
syn_a = [a for a in alerts if a.attack_type == "ddos"]
check("syn_flood_detected", len(syn_a) >= 1, True)

print()

# ============================================================
print("=" * 50)
print("测试7: 非攻击流量不误报")
print("=" * 50)

e7 = AnomalyEngine({"enable_noise_reduction": True, "noise_min_severity": 3})

for _ in range(3):
    r = make_record(dst_ip="93.184.216.34", dst_port=80)
    r.flags = r.FLAG_ACK
    e7.process_traffic(r)

alerts = e7.process_traffic(make_record(dst_ip="93.184.216.34", dst_port=443))
check("no_false_positive", len(alerts), 0)

print()

# ============================================================
print("=" * 50)
print("测试8: 基线学习 + EMA 持续更新")
print("=" * 50)

e8 = AnomalyEngine()

# 模拟学习期流量（正常行为：少量连接）
for i in range(50):
    e8.process_traffic(make_record(dst_port=80 + i % 5, payload_size=200))

# 极短学习期
e8.start_baseline_learning(duration=0.1)
time.sleep(0.2)
e8.process_traffic(make_record())

check("baselines_built", e8.get_statistics()["baselines_established"] >= 1, True)
check("learning_done", e8.get_statistics()["learning_mode"], False)

print()

# ============================================================
print("=" * 50)
print("测试9: ★ 行为突变检测（连接数突增）")
print("=" * 50)

e9 = AnomalyEngine({"enable_noise_reduction": False, "baseline_min_samples": 3})

# 先建立低速率基线：仅 5 个连接（学习期后基线 ≈ 1 连接/分钟）
e9.start_baseline_learning(duration=0.1)
for i in range(5):
    e9.process_traffic(make_record(dst_port=80))
time.sleep(0.15)
e9.process_traffic(make_record())  # 触发学习结束

# 验证基线存在
stats = e9.get_statistics()
check("has_baseline_for_deviation", stats["baselines_established"] >= 1, True)

# 模拟行为突变：短时间内 60 个连接（≈12连接/分钟，远超基线 1连接/分钟）
alerts = []
for i in range(60):
    r = make_record(dst_port=8000 + (i % 60))
    result = e9.process_traffic(r)
    if result:
        alerts.extend(result)

# 行为突变告警
dev_alerts = [a for a in alerts if a.attack_type == "unknown_anomaly"]
check("deviation_detected", len(dev_alerts) >= 1, True)
if dev_alerts:
    has_conn = any("连接" in a.title for a in dev_alerts)
    check("conn_deviation_title", has_conn, True)

print()

# ============================================================
print("=" * 50)
print("测试10: get_host_statistics 近期统计")
print("=" * 50)

hosts = e8.get_host_statistics()
check("hosts_list", len(hosts) >= 1, True)
if hosts:
    check("has_recent_conn", "recent_conn_5min" in hosts[0], True)
    check("has_recent_ports", "recent_ports_5min" in hosts[0], True)
    check("has_recent_peers", "recent_peers_5min" in hosts[0], True)

print()

# ============================================================
print("=" * 50)
print("测试11: reset_statistics 重置")
print("=" * 50)

e8.reset_statistics()
check("after_reset_hosts", e8.get_statistics()["hosts_tracked"], 0)
check("after_reset_baselines", e8.get_statistics()["baselines_established"], 0)

print()

# ============================================================
print("=" * 50)
print("测试12: 回调机制")
print("=" * 50)

e12 = AnomalyEngine({"brute_force_threshold": 3, "brute_force_window_sec": 60, "enable_noise_reduction": False})
cb_alerts = []
e12.set_on_alert_callback(lambda a: cb_alerts.append(a))

# 发送含登录失败内容的连接
for i in range(5):
    e12.process_traffic(make_record(dst_ip="10.0.0.99", dst_port=22, syn=True,
                                     payload="password incorrect for admin"))

check("callback_trig_brute", len(cb_alerts) >= 1, True)

print()

# ============================================================
print("=" * 60)
print(f"结果: {passed}/{total} 通过", end="")
if errors:
    print(f"  ({len(errors)} 失败)")
else:
    print("  全部通过!")
print("=" * 60)
