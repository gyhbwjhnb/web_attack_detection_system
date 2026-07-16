"""
模块1 自测脚本 —— 用 Scapy 构造模拟包，验证 parse_packet 输出正确性。

运行: python tests/test_module1.py
"""

import sys
sys.path.insert(0, ".")

from scapy.all import Ether, IP, TCP, UDP, Raw, DNS, DNSQR, ICMP, ARP, DNSRR
from module1_capture.packet_parser import parse_packet
from module1_capture import CaptureEngine
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
# 修复后：protocol 保留传输层 TCP，不覆盖为 HTTP
check("protocol_tcp", rec.protocol, ProtocolType.TCP)
check("proto_detail", "HTTP" in rec.protocol_detail, True)
check("http_method", rec.http_method, "GET")
check("http_host",   rec.http_host, "10.0.0.1")
check("http_uri",    rec.http_uri, "/index.php?id=1' OR 1=1")  # URL 已解码
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

check("proto_tcp",    rec3.protocol, ProtocolType.TCP)  # 保留传输层 TCP
check("detail_ssh",   rec3.protocol_detail, "SSH")   # 应用层标记存入 protocol_detail
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

check("proto_udp",    rec_udp.protocol, ProtocolType.UDP)  # 保留传输层 UDP
check("detail_dns",   rec_udp.protocol_detail, "DNS")
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
check("dns_proto_udp", rec4.protocol, ProtocolType.UDP)  # 保留传输层 UDP
check("dns_detail",    "DNS" in rec4.protocol_detail, True)
check("dns_query",     rec4.dns_query, "evil.malware.com")
check("dns_qtype",     rec4.dns_query_type, "A")
print()

# ============================

print("=" * 50)
print("测试7: ICMP Echo Request/Reply 解析")
print("=" * 50)

# ICMP Echo Request (type=8, code=0)
pkt_icmp_req = (
    IP(src="10.0.0.1", dst="192.168.1.1")
    / ICMP(type=8, code=0)
    / Raw(load=b"ping data payload")
)
rec_icmp = parse_packet(pkt_icmp_req)

check("icmp_proto",    rec_icmp.protocol, ProtocolType.ICMP)
check("icmp_type",     rec_icmp.icmp_type, 8)
check("icmp_code",     rec_icmp.icmp_code, 0)
check("icmp_detail",   rec_icmp.protocol_detail, "Echo Request")
check("icmp_payload",  "ping" in rec_icmp.payload, True)

# ICMP Echo Reply (type=0, code=0)
pkt_icmp_rep = (
    IP(src="192.168.1.1", dst="10.0.0.1")
    / ICMP(type=0, code=0)
)
rec_icmp2 = parse_packet(pkt_icmp_rep)
check("icmp_reply_type", rec_icmp2.icmp_type, 0)
check("icmp_reply_detail", rec_icmp2.protocol_detail, "Echo Reply")
print()

# ============================

print("=" * 50)
print("测试8: ARP 请求/响应解析")
print("=" * 50)

arp_req = Ether(src="aa:bb:cc:dd:ee:01", dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc="aa:bb:cc:dd:ee:01", psrc="192.168.1.100", hwdst="00:00:00:00:00:00", pdst="192.168.1.1")
rec_arp = parse_packet(arp_req)
check("arp_proto",    rec_arp.protocol, ProtocolType.ARP)
check("arp_src_ip",   rec_arp.src.ip, "192.168.1.100")
check("arp_dst_ip",   rec_arp.dst.ip, "192.168.1.1")
check("arp_detail",   rec_arp.protocol_detail, "ARP Request")
check("arp_flow_id",  "ARP:" in rec_arp.flow_id, True)

arp_rep = Ether(src="11:22:33:44:55:66", dst="aa:bb:cc:dd:ee:01") / ARP(op=2, hwsrc="11:22:33:44:55:66", psrc="192.168.1.1", hwdst="aa:bb:cc:dd:ee:01", pdst="192.168.1.100")
rec_arp2 = parse_packet(arp_rep)
check("arp_reply",     rec_arp2.protocol_detail, "ARP Reply")
print()

# ============================

print("=" * 50)
print("测试9: DNS 响应解析（含 A 记录答案）")
print("=" * 50)

from scapy.all import DNSRR, DNSRROPT

dns_resp = (
    IP(src="8.8.8.8", dst="192.168.1.100")
    / UDP(sport=53, dport=12345)
    / DNS(
        id=0x1234, qr=1, rd=1, ra=1,
        qd=DNSQR(qname="example.com", qtype="A"),
        an=DNSRR(rrname="example.com", type="A", rdata="93.184.216.34", ttl=300),
    )
)
rec_dns = parse_packet(dns_resp)
check("dns_resp_proto_udp", rec_dns.protocol, ProtocolType.UDP)  # 保留传输层 UDP
check("dns_resp_detail",    "DNS" in rec_dns.protocol_detail, True)
check("dns_query_example",  rec_dns.dns_query, "example.com")
check("dns_has_answers",    len(rec_dns.dns_answers) > 0, True)
check("dns_answer_ip",      "93.184.216.34" in rec_dns.dns_answers, True)
print()

# ============================

print("=" * 50)
print("测试10: IPEndpoint 内网判断")
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
print("测试11: all_http_text 属性")
print("=" * 50)

text = rec.all_http_text
check("has_uri",  "/index.php" in text, True)
check("has_body", "<body>test</body>" in text, True)
check("has_ua",   "Mozilla/5.0" in text, True)
check("has_ref",  "http://evil.com" in text, True)
print()

# ============================

print("=" * 50)
print("测试12: http_query_params 属性")
print("=" * 50)

params = rec.http_query_params
check("param_id", params.get("id"), "1' OR 1=1")  # URL 解码后
print()

# ============================

print("=" * 50)
print("测试13: to_dict / to_json 序列化")
print("=" * 50)

d = rec.to_dict()
check("dict_proto_tcp", d["protocol"], "TCP")  # 修复后：序列化传输层协议
check("dict_proto_detail", "HTTP" in d.get("protocol_detail", ""), True)
check("dict_src_ip",   d["src"]["ip"], "192.168.1.100")
check("no_payload_raw", "payload_raw" in d, False)
j = rec.to_json()
check("json_is_str",   isinstance(j, str), True)
check("json_has_http", '"http_method": "GET"' in j, True)
print()

# ============================

print("=" * 50)
print("测试14: CaptureEngine 基本生命周期")
print("=" * 50)

from module1_capture import CaptureEngine

engine = CaptureEngine(use_message_bus=False)
check("init_running", engine.is_running(), False)
check("init_pkts",    engine.get_statistics()["packet_count"], 0)

# 离线模式：用构建好的 scapy 包模拟
import time

# 测试 _dispatch 回调
received_life = []
engine.set_on_traffic_callback(lambda r: received_life.append(r))

from module1_capture.packet_parser import create_fake_http_record
fake_rec = create_fake_http_record()
engine._dispatch(fake_rec)
check("dispatch_works", len(received_life), 1)
check("dispatch_data",  received_life[0].http_method, "GET")

# 测试 stop idle 不抛异常
engine.stop()
check("stop_idle_ok",  True, True)

stats = engine.get_statistics()
check("stats_dict",    "packet_count" in stats, True)
print()

# ============================

print("=" * 50)
print("测试15: 端口协议标记（SMB / RDP / MySQL / Redis）")
print("=" * 50)

# SMB (port 445)
pkt_smb = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=49152, dport=445, flags="S")
rec_smb = parse_packet(pkt_smb)
check("smb_proto_tcp",  rec_smb.protocol, ProtocolType.TCP)  # 保留传输层
check("smb_detail",     "SMB" in rec_smb.protocol_detail, True)

# RDP (port 3389)
pkt_rdp = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=49153, dport=3389, flags="S")
rec_rdp = parse_packet(pkt_rdp)
check("rdp_proto_tcp",  rec_rdp.protocol, ProtocolType.TCP)

# MySQL (port 3306)
pkt_mysql = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=49154, dport=3306, flags="S")
rec_mysql = parse_packet(pkt_mysql)
check("mysql_proto_tcp", rec_mysql.protocol, ProtocolType.TCP)

# Redis (port 6379)
pkt_redis = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=49155, dport=6379, flags="S")
rec_redis = parse_packet(pkt_redis)
check("redis_proto_tcp", rec_redis.protocol, ProtocolType.TCP)

print()

# ============================

print("=" * 60)
print(f"结果: {passed}/{total} 通过", end="")
if errors:
    print(f"  ({len(errors)} 失败)")
else:
    print("  全部通过!")
print("=" * 60)
