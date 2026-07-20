"""
智能特性测试脚本 —— 模拟攻击流量验证 S6/S7/S8 功能。

运行方式:
    cd network_attack_detection
    python test_intelligence.py

测试场景:
    1. 端口扫描 —— 验证置信度评分（端口越多置信越高）
    2. 暴力破解 SSH —— 验证置信度评分 + 高关注端口加分
    3. SYN Flood —— 验证置信度评分
    4. 夜间 C2 外联 —— 验证时段检测（凌晨告警提权）
    5. 异常外联陌生 IP —— 验证置信度评分
    6. 横向扩散 —— 验证跨子网检测
"""

import sys
import os
import time
import random
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common.message_bus import MessageBus
from common.data_structures import TrafficRecord, IPEndpoint, ProtocolType
from module3_anomaly.anomaly_engine import AnomalyEngine
from module4_gui.main_window import MainWindow


# ==================== 流量工厂 ====================

def make_record(src_ip, dst_ip, src_port, dst_port,
                protocol=ProtocolType.TCP,
                flags=0x18,
                payload="",
                payload_size=100,
                timestamp=None):
    ts = timestamp or time.time()
    record = TrafficRecord(
        id=f"{ts:.6f}-{random.randint(0,9999):04d}",
        timestamp=ts,
        src=IPEndpoint(ip=src_ip, port=src_port),
        dst=IPEndpoint(ip=dst_ip, port=dst_port),
        protocol=protocol,
        flags=flags,
        payload=payload,
        payload_size=payload_size,
    )
    record.flow_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol.name}"
    return record


def make_syn_record(src_ip, dst_ip, src_port, dst_port, timestamp=None):
    return make_record(src_ip, dst_ip, src_port, dst_port,
                       protocol=ProtocolType.TCP, flags=0x02,
                       payload="", payload_size=60, timestamp=timestamp)


# ==================== 场景生成 ====================

def gen_port_scan(start_ts):
    """场景1"""
    src, dst = "192.168.1.100", "10.0.0.5"
    ports = random.sample(range(1, 65536), 80)
    records = []
    for i, port in enumerate(ports):
        r = make_record(src, dst, random.randint(30000, 60000), port,
                        timestamp=start_ts + i * 0.12)
        records.append(r)
    print(f"[测试1] 端口扫描: {src} → {dst}，80 个不同端口，10 秒内")
    return records

def gen_brute_force(start_ts):
    """场景2"""
    src, dst = "10.0.0.88", "192.168.1.50"
    records = []
    for i in range(50):
        r = make_record(src, dst, random.randint(40000, 60000), 22,
                        flags=0x02, timestamp=start_ts + i * 0.5)
        records.append(r)
    print(f"[测试2] 暴力破解: {src} → {dst}:22，50 次连接，30 秒内")
    return records

def gen_syn_flood(start_ts):
    """场景3"""
    srcs = [f"10.0.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(20)]
    dst = "192.168.1.10"
    records = []
    for i in range(500):
        ts = start_ts + i * 0.005
        r = make_syn_record(random.choice(srcs), dst, random.randint(10000, 60000), 80, timestamp=ts)
        records.append(r)
    print(f"[测试3] SYN Flood: 20 源 IP → {dst}:80，500 个 SYN 包，3 秒内")
    return records

def gen_night_c2(start_ts):
    """场景4: 凌晨3点 C2 外联"""
    import datetime as dt
    today = dt.date.today()
    night = dt.datetime.combine(today, dt.time(3, 0, 5))
    night_ts = night.timestamp()
    src, dst = "192.168.1.50", "45.33.32.156"
    records = []
    for i in range(20):
        r = make_record(src, dst, random.randint(40000, 50000), 4444,
                        payload="beacon", payload_size=500,
                        timestamp=night_ts + i * 3)
        records.append(r)
    print(f"[测试4] 夜间 C2 外联: {src} → {dst}:4444（凌晨 3 点，20 次）")
    return records

def gen_outbound(start_ts):
    """场景5"""
    src = "192.168.1.30"
    dsts = [f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            for _ in range(15)]
    malicious_ports = [4444, 1337, 31337, 6667, 8888]
    records = []
    for i, dst in enumerate(dsts):
        r = make_record(src, dst, random.randint(40000, 50000),
                        random.choice(malicious_ports),
                        timestamp=start_ts + i * 2)
        records.append(r)
    print(f"[测试5] 异常外联: {src} → 15 个外网 IP，30 秒内")
    return records

def gen_lateral(start_ts):
    """场景6"""
    src = "192.168.1.99"
    dsts = [f"192.168.{random.randint(0,5)}.{random.randint(1,254)}" for _ in range(12)]
    records = []
    for i, dst in enumerate(dsts):
        r = make_record(src, dst, random.randint(40000, 50000), 445,
                        flags=0x02, timestamp=start_ts + i * 2.5)
        records.append(r)
    print(f"[测试6] 横向扩散: {src} → 12 个内网主机，30 秒内")
    return records

def gen_normal(start_ts):
    """基线流量"""
    src = "192.168.1.50"
    records = []
    for i in range(30):
        r = make_record(src, "142.250.80.46", random.randint(50000, 60000), 443,
                        payload="GET / HTTP/1.1\r\nHost: google.com\r\n\r\n",
                        payload_size=300,
                        timestamp=start_ts + i * 1.0)
        records.append(r)
    print(f"[基线] 正常流量 30 条")
    return records


# ==================== 主逻辑 ====================

def main():
    print("=" * 60)
    print("  智能特性测试 — S6(置信度) / S7(时段) / S8(抑制)")
    print("=" * 60)

    bus = MessageBus()
    ano = AnomalyEngine()
    gui = MainWindow()

    # ── 桥接：MessageBus → 引擎 → GUI ──
    def on_traffic(record):
        # 线程安全：通过 root.after 投递到 GUI 主线程
        gui._root.after(0, lambda r=record: _process(r))

    def _process(record):
        gui.add_traffic_record(record)
        for alert in ano.process_traffic(record):
            gui.add_alert(alert)

    bus.subscribe(bus.EVENT_TRAFFIC_RECORD, on_traffic)

    # 启动基线学习（5 秒快速学习）
    ano.start_baseline_learning(duration=5)

    # ── 阶段1: 注入基线流量 ──
    print(f"\n{'='*40}")
    print("[阶段1] 注入基线流量，开始 5 秒学习期")
    print("=" * 40)
    sim_start = time.time()
    for r in gen_normal(sim_start):
        bus.publish("traffic_record", r)

    # 等待学习期
    for _ in range(6):
        gui._root.update()
        time.sleep(1)
    print("[系统] 学习期结束，进入检测模式")

    # ── 阶段2: 逐个场景注入攻击 ──
    print(f"\n{'='*40}")
    print("[阶段2] 注入攻击流量")
    print("=" * 40)

    attack_base = time.time() + 1

    all_attacks = gen_port_scan(attack_base)
    attack_base += 15
    all_attacks += gen_brute_force(attack_base)
    attack_base += 35
    all_attacks += gen_syn_flood(attack_base)
    attack_base += 10
    all_attacks += gen_night_c2(attack_base)
    attack_base += 65
    all_attacks += gen_outbound(attack_base)
    attack_base += 35
    all_attacks += gen_lateral(attack_base)

    print(f"\n[系统] 共生成 {len(all_attacks)} 条攻击流量，正在逐条注入...")

    for i, r in enumerate(all_attacks):
        bus.publish("traffic_record", r)
        if i % 100 == 0:
            gui._root.update()

    gui._root.update()
    time.sleep(2)

    # ── 阶段3: 结果 ──
    print(f"\n{'='*40}")
    print("[阶段3] 检测结果")
    print("=" * 40)

    for d in ano.list_detectors():
        print(f"  [{d['priority']:2d}] {d['name']:25s}  {'ON' if d['enabled'] else 'OFF'}")

    stats = ano.get_statistics()
    print(f"\n总告警数: {stats.get('total_alerts', 0)}")

    scorer = ano.get_detector("confidence_scorer")
    learner = ano.get_detector("suppression_learner")
    timer = ano.get_detector("time_profile")
    print(f"  ConfidenceScorer:     {'就绪' if scorer and scorer.enabled else '未找到'}")
    print(f"  SuppressionLearner:   {'就绪' if learner and learner.enabled else '未找到'}")
    print(f"  TimeProfileDetector:  {'就绪' if timer and timer.enabled else '未找到'}")

    print(f"\n{'='*60}")
    print("  注入完毕！请查看 GUI 告警列表。")
    print("  - 关注 confidence 列（不同的攻击类型应有不同分值）")
    print("  - 夜间 C2 告警描述应包含 [夜间异常时段]")
    print('  - 右键标记某告警为\"误报\"，看后续同类型是否降权')
    print("=" * 60)

    gui.run()


if __name__ == "__main__":
    main()
