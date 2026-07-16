"""
跨模块协议修复验证测试 —— 验证真实 HTTP/DNS 流量能被模块二正确检测。

问题是：模块一将应用层协议（HTTP/DNS）覆盖了传输层协议（TCP/UDP），
而模块二的规则全部使用 "protocol": "TCP"/"UDP" 做过滤，
导致真实 HTTP/DNS 流量被跳过 → SQL注入/XSS/DNS隧道 漏检。

修复后：
  - record.protocol 保留传输层协议（TCP/UDP）
  - record.protocol_detail 记录应用层协议名（"HTTP"/"DNS"）
  - 模块二规则匹配正常

运行: python tests/test_protocol_fix.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import Ether, IP, TCP, UDP, Raw, DNS, DNSQR
from module1_capture.packet_parser import parse_packet, create_fake_http_record, create_fake_dns_record
from module2_signature.signature_engine import SignatureEngine
from common import ProtocolType, TrafficRecord

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

def check_true(name, condition):
    global total, passed
    total += 1
    if condition:
        passed += 1
        print(f"  [PASS] {name}")
    else:
        errors.append(f"  [FAIL] {name}: condition is False")
        print(f"  [FAIL] {name}: condition is False")


RULES_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "data", "signatures.json")


print("=" * 60)
print("验证1: 真实HTTP流量解析 — protocol保留TCP")
print("=" * 60)

# 用 Scapy 构造一个真实 HTTP GET 包（含 SQL 注入）
pkt = (
    Ether(dst="00:11:22:33:44:55", src="aa:bb:cc:dd:ee:ff")
    / IP(src="192.168.1.100", dst="10.0.0.1")
    / TCP(sport=54321, dport=80, flags="PA", seq=1000, ack=2000)
    / Raw(load=b"GET /login.php?user=admin%27%20OR%201=1-- HTTP/1.1\r\n"
          b"Host: target.com\r\n"
          b"User-Agent: Mozilla/5.0\r\n"
          b"\r\n")
)

rec = parse_packet(pkt)
check_true("record_not_none", rec is not None)
check("protocol_is_TCP", rec.protocol, ProtocolType.TCP)       # ← 修复核心：保留TCP
check("protocol_is_not_HTTP", rec.protocol != ProtocolType.HTTP, True)  # ← 不再被覆盖为HTTP
check_true("detail_has_HTTP", "HTTP" in (rec.protocol_detail or ""))    # 应用层信息在detail中
check("http_uri_decoded", "/login.php?user=admin' OR 1=1--" in rec.http_uri, True)
check("http_method", rec.http_method, "GET")

print()


print("=" * 60)
print("验证2: 真实DNS查询解析 — protocol保留UDP")
print("=" * 60)

pkt_dns = (
    IP(src="192.168.1.100", dst="8.8.8.8")
    / UDP(sport=12345, dport=53)
    / DNS(rd=1, qd=DNSQR(qname="evil.c2.malware.com", qtype="A"))
)
rec_dns = parse_packet(pkt_dns)
check_true("dns_record_not_none", rec_dns is not None)
check("dns_protocol_is_UDP", rec_dns.protocol, ProtocolType.UDP)  # ← 保留传输层UDP
check("dns_protocol_is_not_DNS", rec_dns.protocol != ProtocolType.DNS, True)
check_true("dns_detail_has_DNS", "DNS" in (rec_dns.protocol_detail or ""))
check("dns_query", rec_dns.dns_query, "evil.c2.malware.com")

print()


print("=" * 60)
print("验证3: 真实HTTP流量 → 模块二检测SQL注入")
print("=" * 60)
print("  (这是核心验证：修复前因protocol=HTTP被跳过，修复后应检出)")
print()

# 用 Scapy 构造 HTTP 包 → parse_packet → SignatureEngine
pkt_sql = (
    Ether(dst="00:11:22:33:44:55", src="aa:bb:cc:dd:ee:ff")
    / IP(src="10.0.0.5", dst="192.168.1.1")
    / TCP(sport=40000, dport=80, flags="PA")
    / Raw(load=b"GET /search?q=1%27%20OR%201=1 HTTP/1.1\r\n"
          b"Host: shop.example.com\r\n"
          b"\r\n")
)
rec_sql = parse_packet(pkt_sql)

engine3 = SignatureEngine()
engine3.load_rules(RULES_FILE)
alerts = engine3.process_traffic(rec_sql)

sql_alerts = [a for a in alerts if a.attack_type == "sql_injection"]
check_true("sql_injection_detected", len(sql_alerts) >= 1)
if sql_alerts:
    # 确认告警信息正确
    check("alert_has_rule_id", sql_alerts[0].rule_id, "SQL-001")
    check("alert_src_ip", sql_alerts[0].src_ip, "10.0.0.5")
    check_true("alert_has_title", len(sql_alerts[0].title) > 0)
    # 确认 protocol 在 Alert 中也被正确记录
    print(f"  -> Alert protocol: {sql_alerts[0].protocol}")
    check("alert_protocol_tcp", sql_alerts[0].protocol, "TCP")

print()


print("=" * 60)
print("验证4: 真实HTTP流量 → 模块二检测XSS")
print("=" * 60)

pkt_xss = (
    IP(src="10.0.0.5", dst="192.168.1.1")
    / TCP(sport=40001, dport=80, flags="PA")
    / Raw(load=b"POST /comment HTTP/1.1\r\n"
          b"Host: forum.example.com\r\n"
          b"\r\n"
          b"message=<script>alert('xss')</script>")
)
rec_xss = parse_packet(pkt_xss)

engine4 = SignatureEngine()
engine4.load_rules(RULES_FILE)
alerts_xss = engine4.process_traffic(rec_xss)
xss_alerts = [a for a in alerts_xss if a.attack_type == "xss"]
check_true("xss_detected", len(xss_alerts) >= 1)
if xss_alerts:
    check("alert_protocol_tcp", xss_alerts[0].protocol, "TCP")

print()


print("=" * 60)
print("验证5: 真实DNS流量 → 模块二端口/协议过滤正常")
print("=" * 60)

pkt_dns_test = (
    IP(src="192.168.1.100", dst="8.8.8.8")
    / UDP(sport=54321, dport=53)
    / DNS(rd=1, qd=DNSQR(qname="test.example.com", qtype="A"))
)
rec_dns_test = parse_packet(pkt_dns_test)

check("dns_protocol_UDP", rec_dns_test.protocol, ProtocolType.UDP)

# DNS-001 规则在 signatures.json 中 protocol: "UDP" → 应匹配
# 传一个含 DNS 隧道特征的 payload 到模块二
engine5 = SignatureEngine()
engine5.load_rules(RULES_FILE)

# 直接构造 TrafficRecord 模拟 DNS 隧道（有载荷文本的情况）
rec_dns_tunnel = TrafficRecord()
rec_dns_tunnel.src.ip = "192.168.1.100"
rec_dns_tunnel.src.port = 54321
rec_dns_tunnel.dst.ip = "8.8.8.8"
rec_dns_tunnel.dst.port = 53
rec_dns_tunnel.protocol = ProtocolType.UDP
rec_dns_tunnel.payload = "subdomain.nip.io dns tunnel exfiltration"
rec_dns_tunnel.payload_raw = rec_dns_tunnel.payload.encode()
rec_dns_tunnel.payload_size = len(rec_dns_tunnel.payload)

alerts_dns = engine5.process_traffic(rec_dns_tunnel)
dns_tunnel = [a for a in alerts_dns if a.attack_type == "dns_tunnel"]
check_true("dns_tunnel_detected", len(dns_tunnel) >= 1)

# 确认协议为UDP的记录不会被TCP规则误匹配
rec_tcp_payload = TrafficRecord()
rec_tcp_payload.src.ip = "192.168.1.100"
rec_tcp_payload.src.port = 54321
rec_tcp_payload.dst.ip = "10.0.0.1"
rec_tcp_payload.dst.port = 80
rec_tcp_payload.protocol = ProtocolType.TCP
rec_tcp_payload.payload = "clean tcp traffic without patterns"
rec_tcp_payload.payload_raw = rec_tcp_payload.payload.encode()
rec_tcp_payload.payload_size = len(rec_tcp_payload.payload)

alerts_clean = engine5.process_traffic(rec_tcp_payload)
check("no_false_positive_on_clean", len(alerts_clean), 0)

print()


print("=" * 60)
print("验证6: create_fake_* 辅助函数仍正常工作")
print("=" * 60)

# 这些函数本来就设置 protocol=TCP/UDP，应保持向后兼容
fake_http = create_fake_http_record(uri="/test?q=1' OR 1=1 --")
engine6 = SignatureEngine()
engine6.load_rules(RULES_FILE)
alerts_fake = engine6.process_traffic(fake_http)
check_true("fake_http_sql_detected", len([a for a in alerts_fake if a.attack_type == "sql_injection"]) >= 1)

fake_dns = create_fake_dns_record(query="evil.paylaod.top")
check("fake_dns_protocol_UDP", fake_dns.protocol, ProtocolType.UDP)
check("fake_dns_query", fake_dns.dns_query, "evil.paylaod.top")

print()


print("=" * 60)
print("结果汇总")
print("=" * 60)
print(f"测试: {passed}/{total} 通过", end="")
if errors:
    print(f"  ({len(errors)} 失败)")
    print("\n失败详情:")
    for e in errors:
        print(f"  {e}")
    sys.exit(1)
else:
    print("  ✅ 全部通过！")
    print()
    print("结论: 跨模块协议修复已生效")
    print("  - HTTP流量: protocol=TCP, protocol_detail=HTTP ✓")
    print("  - DNS流量:  protocol=UDP, protocol_detail=DNS ✓")
    print("  - 模块二SQL注入检测: 从真实HTTP流量中检出 ✓")
    print("  - 模块二XSS检测:     从真实HTTP流量中检出 ✓")
    print("  - 模块二DNS隧道检测: 协议匹配正常 ✓")
    print("=" * 60)
