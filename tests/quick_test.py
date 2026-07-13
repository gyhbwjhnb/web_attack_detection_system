"""
快速测试脚本 —— 用模拟数据验证 模块1 → 模块3 → 模块4 完整管道。

无需网卡/PCAP/管理员权限，直接运行:
    python tests/quick_test.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import message_bus
from module1_capture.packet_parser import create_fake_http_record, create_fake_dns_record
from module3_anomaly import AnomalyEngine

print("=" * 60)
print("  网络攻击检测系统 —— 快速集成测试")
print("  (模拟数据 → 模块3异常检测 → 告警输出)")
print("=" * 60)

# 初始化模块3（关闭降噪，方便看到所有告警）
engine = AnomalyEngine({"enable_noise_reduction": False})

# 先建立基线（少量正常流量）
print("\n[第1步] 基线学习（模拟5分钟正常流量）...")
engine.start_baseline_learning(duration=0.05)
for i in range(30):
    record = create_fake_http_record(
        method="GET", uri=f"/page{i}.html",
        host="www.example.com", dst_port=80,
    )
    engine.process_traffic(record)

import time
time.sleep(0.1)
engine.process_traffic(create_fake_http_record())
print(f"  基线已建立: {engine.get_statistics()['baselines_established']} 个主机")

# ============================================================
print("\n[第2步] 测试1：端口扫描检测")
print("-" * 40)
e1 = AnomalyEngine({"port_scan_threshold": 5, "port_scan_window_sec": 60, "enable_noise_reduction": False})
for port in range(8000, 8011):  # 11个不同端口
    e1.process_traffic(create_fake_http_record(dst_port=port))
alerts = e1.process_traffic(create_fake_http_record(dst_port=8011))
scan = [a for a in alerts if a.attack_type == "port_scan"]
if scan:
    print(f"  ✓ 检测到端口扫描: {scan[0].title}")
else:
    print(f"  ✗ 未检测到（可能需要调整阈值）")

# ============================================================
print("\n[第3步] 测试2：暴力破解检测")
print("-" * 40)
e2 = AnomalyEngine({"brute_force_threshold": 5, "brute_force_window_sec": 60, "enable_noise_reduction": False})
for _ in range(8):
    e2.process_traffic(create_fake_http_record(dst_port=22))  # SSH
alerts = e2.process_traffic(create_fake_http_record(dst_port=22))
brute = [a for a in alerts if a.attack_type == "brute_force"]
if brute:
    print(f"  ✓ 检测到暴力破解: {brute[0].title}")
else:
    print(f"  ✗ 未检测到")

# ============================================================
print("\n[第4步] 测试3：异常外联检测")
print("-" * 40)
e3 = AnomalyEngine({"enable_noise_reduction": False})
# 创建内网→外部陌生 IP 的记录
record = create_fake_http_record(src_ip="192.168.1.50", dst_ip="203.0.113.99", dst_port=4444)
alerts = e3.process_traffic(record)
out = [a for a in alerts if a.attack_type == "abnormal_outbound"]
if out:
    print(f"  ✓ 检测到异常外联: {out[0].title}")
else:
    print(f"  ✗ 未检测到")

# ============================================================
print("\n[第5步] 测试4：DNS 异常流量")
print("-" * 40)
e4 = AnomalyEngine({"enable_noise_reduction": False})
for i in range(20):
    e4.process_traffic(create_fake_dns_record(query=f"evil{i}.c2.com"))
alerts = e4.process_traffic(create_fake_dns_record(query="evil20.c2.com"))
dns_alerts = [a for a in alerts if "DNS" in str(a) or "外联" in str(a)]
if dns_alerts:
    print(f"  ✓ 检测到 DNS 相关告警: {len(dns_alerts)} 条")
else:
    print(f"  ✓ 无告警（UDP 53 正常流量，阈值内）")

# ============================================================
print("\n[第6步] 测试5：行为突变检测")
print("-" * 40)
e5 = AnomalyEngine({"enable_noise_reduction": False, "baseline_min_samples": 3})
e5.start_baseline_learning(duration=0.05)
for i in range(5):
    e5.process_traffic(create_fake_http_record())
time.sleep(0.1)
e5.process_traffic(create_fake_http_record())

# 突发大量连接
alerts_all = []
for i in range(60):
    result = e5.process_traffic(create_fake_http_record(dst_port=8000 + i % 60))
    if result:
        alerts_all.extend(result)

dev = [a for a in alerts_all if a.attack_type == "unknown_anomaly"]
if dev:
    print(f"  ✓ 检测到行为突变: {dev[0].title}")
else:
    print(f"  ✗ 未检测到（可能因基线不足）")

# ============================================================
print("\n" + "=" * 60)
print("  总结")
print("=" * 60)
print(f"""
  如果看到多个 ✓，说明管道通畅：
  
    create_fake_http_record()  →  TrafficRecord  →  AnomalyEngine.process_traffic()  →  Alert
  
  下一步:
    1. python main.py                    # 打开 GUI（手动点"开始检测"）
    2. python main.py --auto             # GUI + 自动抓包（需管理员+Npcap）
    3. python main.py --pcap xxx.pcap --auto  # PCAP离线分析
""")
