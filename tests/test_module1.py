"""
模块1 自测脚本 —— 用 Scapy 构造模拟包，验证 parse_packet 输出正确性。

运行: python tests/test_module1.py
"""

import sys
sys.path.insert(0, ".")

from scapy.all import Ether, IP, TCP, UDP, Raw, DNS, DNSQR
from module1_capture.packet_parser import parse_packet
from module1_capture import CaptureEngine, read_pcap_file
from common import TrafficRecord, IPEndpoint, ProtocolType

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


print("=" * 50)
print("测试1: HTTP GET 请求（含 SQL 注入特征）")
print("=" * 50)

pkt = (
    Ether(dst="00:11:22:33:44:55", src="aa:bb:cc:dd:ee:ff")
    / IP(src="192.168.1.100", dst="10.0.0.1")
    / TCP(sport=54321, dport=80, flags="PA", seq=1000, ack=2000)
    / Raw(load=b"GET /index.php?id=1%27%20OR%201=1 HTTP/1.1\r\nHost: 10.0.0.1\r\nUser-Agent: Mozilla/5.0\r\nReferer: http://evil.com\r\n\r\n<body>test</body>")
)

rec = parse_packet(pkt)

check("src.ip",      rec.src.ip, "192.168.1.100")
check("src.port",    rec.src.port, 54321)
check("src.mac",     rec.src.mac, "aa:bb:cc:dd:ee:ff")
check("dst.ip",      rec.dst.ip, "10.0.0.1")
check("dst.port",    rec.dst.port, 80)
check("dst.mac",     rec.dst.mac, "00:11:22:33:44:55")
check("protocol",    rec.protocol, ProtocolType.HTTP)
check("http_method", rec.http_method, "GET")
check("http_host",   rec.http_host, "10.0.0.1")
check("http_uri",    rec.http_uri, "http://10.0.0.1/index.php?id=1%27%20OR%201=1")
check("http_ua",     rec.http_user_agent, "Mozilla/5.0")
check("http_referer",rec.http_referer, "http://evil.com")
check("http_body",   rec.http_body, "<body>test</body>")
check("payload_sql", "%27%20OR%201=1" in rec.payload, True)
check("is_syn",      rec.is_syn(), False)
print(f"  payload 前80字: {rec.payload[:80]}")
print()

# ============================

print("=" * 50)
print("测试2: HTTP 响应")
print("=" * 50)

pkt2 = (
    IP(src="10.0.0.1", dst="192.168.1.100")
    / TCP(sport=80, dport=54321, flags="A")
    / Raw(load=b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: nginx\r\n\r\n<html>OK</html>")
)

rec2 = parse_packet(pkt2)

check("status_code",  rec2.http_status_code, 200)
check("proto_detail", rec2.protocol_detail, "HTTP/1.1")
check("server_hdr",   rec2.http_headers.get("server"), "nginx")
check("body",         rec2.http_body, "<html>OK</html>")
print()

# ============================

print("=" * 50)
print("测试3: TCP SYN 包（端口扫描特征）")
print("=" * 50)

pkt3 = IP(src="10.0.0.99", dst="192.168.1.1") / TCP(sport=44444, dport=22, flags="S")
rec3 = parse_packet(pkt3)

check("proto_tcp",    rec3.protocol, ProtocolType.TCP)
check("is_syn_true",  rec3.is_syn(), True)
check("dst_port_22",  rec3.dst.port, 22)
check("src_ip_scan",  rec3.src.ip, "10.0.0.99")
check("empty_payload", rec3.payload, "")
print()

# ============================

print("=" * 50)
print("测试4: TCP SYN+ACK 包")
print("=" * 50)

pkt3b = IP(src="192.168.1.1", dst="10.0.0.99") / TCP(sport=22, dport=44444, flags="SA")
rec3b = parse_packet(pkt3b)

check("is_syn_ack",   rec3b.is_syn_ack(), True)
check("is_syn_false", rec3b.is_syn(), True)  # SYN 位也在 SA 中
print()

# ============================

print("=" * 50)
print("测试5: UDP 包")
print("=" * 50)

pkt_udp = IP(src="192.168.1.50", dst="192.168.1.1") / UDP(sport=9999, dport=53)
rec_udp = parse_packet(pkt_udp)

check("proto_udp",    rec_udp.protocol, ProtocolType.DNS)  # UDP 53 应识别为 DNS
check("src_port",     rec_udp.src.port, 9999)
check("dst_port_53",  rec_udp.dst.port, 53)
print()

# ============================

print("=" * 50)
print("测试6: DNS 查询")
print("=" * 50)

pkt4 = (
    IP(src="192.168.1.100", dst="8.8.8.8")
    / UDP(sport=12345, dport=53)
    / DNS(rd=1, qd=DNSQR(qname="evil.malware.com", qtype="A"))
)

rec4 = parse_packet(pkt4)
check("dns_proto",     rec4.protocol, ProtocolType.DNS)
check("dns_query",     rec4.dns_query, "evil.malware.com")
check("dns_qtype",     rec4.dns_query_type, "A")
print()

# ============================

print("=" * 50)
print("测试7: 手动字节解析（无 Scapy 兼容）")
print("=" * 50)

from module1_capture.packet_parser import _parse_bytes_manually

ip_hdr = bytes([0x45, 0, 0, 0x28, 0, 1, 0, 0, 64, 6, 0, 0,
                192, 168, 1, 100, 10, 0, 0, 1])
tcp_hdr = bytes([0xD4, 0x31, 0, 0x50, 0, 0, 0, 1, 0, 0, 0, 0,
                 0x50, 0x02, 0xFF, 0xFF, 0, 0, 0, 0])
raw_pkt = ip_hdr + tcp_hdr
rec_raw = _parse_bytes_manually(raw_pkt)

check("raw_src_ip",    rec_raw.src.ip, "192.168.1.100")
check("raw_src_port",  rec_raw.src.port, 54321)
check("raw_dst_ip",    rec_raw.dst.ip, "10.0.0.1")
check("raw_dst_port",  rec_raw.dst.port, 80)
check("raw_proto",     rec_raw.protocol, ProtocolType.TCP)
check("raw_is_syn",    rec_raw.is_syn(), True)
print()

# ============================

print("=" * 50)
print("测试8: IPEndpoint 内网判断")
print("=" * 50)

check("192.168.x",  IPEndpoint(ip="192.168.1.1").is_internal, True)
check("10.x",       IPEndpoint(ip="10.0.0.5").is_internal, True)
check("172.16.x",   IPEndpoint(ip="172.16.5.5").is_internal, True)
check("127.x",      IPEndpoint(ip="127.0.0.1").is_internal, True)
check("8.8.8.8",    IPEndpoint(ip="8.8.8.8").is_internal, False)
check("1.1.1.1",    IPEndpoint(ip="1.1.1.1").is_internal, False)
print()

# ============================

print("=" * 50)
print("测试9: all_http_text 属性")
print("=" * 50)

text = rec.all_http_text
check("has_uri",  "/index.php" in text, True)
check("has_body", "<body>test</body>" in text, True)
check("has_ua",   "Mozilla/5.0" in text, True)
check("has_ref",  "http://evil.com" in text, True)
print()

# ============================

print("=" * 50)
print("测试10: http_query_params 属性")
print("=" * 50)

params = rec.http_query_params
check("param_id", params.get("id"), "1%27%20OR%201=1")
print()

# ============================

print("=" * 50)
print("测试11: to_dict / to_json 序列化")
print("=" * 50)

d = rec.to_dict()
check("dict_proto",    d["protocol"], "HTTP")
check("dict_src_ip",   d["src"]["ip"], "192.168.1.100")
check("no_payload_raw", "payload_raw" in d, False)
j = rec.to_json()
check("json_is_str",   isinstance(j, str), True)
check("json_has_http", '"http_method": "GET"' in j, True)
print()

# ============================

print("=" * 50)
print("测试12: CaptureEngine 基本生命周期")
print("=" * 50)

engine = CaptureEngine(bpf_filter="tcp", packet_count=0, publish_to_bus=False)
check("init_running", engine._running, False)
check("init_pkts",    engine.get_statistics()["packet_count"], 0)

engine.start()
import time
time.sleep(0.3)

# 在没有 Npcap 的 Windows 上实时抓包可能无法启动，这是环境限制
if not engine._running:
    print("  [SKIP] 实时抓包需要 Npcap/WinPcap 驱动，跳过此测试")
else:
    check("after_start",  engine._running, True)

engine.stop()
time.sleep(0.3)
check("after_stop",   engine._running, False)

stats = engine.get_statistics()
check("stats_running", stats["running"], False)
print()

# ============================

print("=" * 50)
print("测试13: CaptureEngine 回调机制")
print("=" * 50)

from scapy.all import sniff as scapy_sniff

test_engine = CaptureEngine(
    bpf_filter="",
    packet_count=0,
    publish_to_bus=False,
)

received = []
test_engine.set_on_traffic_callback(lambda r: received.append(r))
test_engine._running = True  # 手动设为运行

# 直接调用 _on_packet 模拟收包
test_engine._on_packet(pkt)
test_engine._on_packet(pkt3)

check("callback_count", len(received), 2)
check("cb1_src_ip",     received[0].src.ip, "192.168.1.100")
check("cb2_dst_port",   received[1].dst.port, 22)

stats2 = test_engine.get_statistics()
check("stats_pkts_2",   stats2["packet_count"], 2)
print()

# ============================

print("=" * 60)
print(f"结果: {passed}/{total} 通过", end="")
if errors:
    print(f"  ({len(errors)} 失败)")
else:
    print("  全部通过!")
print("=" * 60)
