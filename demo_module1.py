"""
============================================================================
模块一 完整功能演示脚本
============================================================================

一步步展示模块一的全部功能，让你清楚看到：
  - 模拟数据长什么样
  - PCAP 文件怎么生成和解析
  - 解析后的 TrafficRecord 完整对象数据
  - 消息总线怎么工作
  - 批量解析性能

运行方式:
    cd web_attack_detection_system
    python demo_module1.py

如果想看特定部分，可以注释掉 skip_* 变量。
============================================================================
"""

import sys
import time
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from tests.test_module1 import MockScapyPacket, MockIP, MockTCP, MockRaw

# ========================= 控制开关 =========================
# 把 True 改成 False 可以跳过某一部分
skip_section1 = False   # 模拟数据
skip_section2 = False   # PCAP 生成 + 离线解析
skip_section3 = False   # 消息总线
skip_section4 = False   # 解析原始 scapy 包
skip_section5 = False   # 批量解析性能


# ========================= 辅助函数 =========================

SEP = "=" * 72


def section(title):
    print(f"\n{SEP}")
    print(f"  {title}")
    print(SEP)


def show(record, label="记录"):
    """打印 TrafficRecord 的完整字段"""
    print(f"\n>> {label} <<")
    print(f"  对象类型:      TrafficRecord")
    print(f"  __repr__:      {repr(record)}")
    print(f"  .id:           {record.id}")
    print(f"  .timestamp:    {record.timestamp}")
    print(f"  .protocol:     {record.protocol.value}  ({record.protocol_detail or '无'})")
    print(f"  .src.ip:       {record.src.ip}")
    print(f"  .src.port:     {record.src.port}")
    print(f"  .dst.ip:       {record.dst.ip}")
    print(f"  .dst.port:     {record.dst.port}")
    print(f"  .src.mac:      {record.src.mac or '(未捕获)'}")
    print(f"  .dst.mac:      {record.dst.mac or '(未捕获)'}")
    print(f"  .flow_id:      {record.flow_id or '(无)'}")
    try:
        flags_int = int(record.flags) if record.flags else 0
        print(f"  .flags:        {flags_int:#05x}")
    except (ValueError, TypeError):
        print(f"  .flags:        {record.flags!r}")
    print(f"  .seq_num:      {record.seq_num}")
    print(f"  .ack_num:      {record.ack_num}")
    print(f"  .payload_size: {record.payload_size}")

    if record.http_method:
        print(f"  .http_method:  {record.http_method}")
        print(f"  .http_uri:     {record.http_uri}")
        print(f"  .http_host:    {record.http_host}")
        if record.http_user_agent:
            print(f"  .http_ua:      {record.http_user_agent[:50]}...")
        if record.http_referer:
            print(f"  .http_referer: {record.http_referer}")
        if record.http_status_code:
            print(f"  .http_status:  {record.http_status_code}")
        if record.http_body:
            print(f"  .http_body:    {record.http_body[:80]}")
    if record.dns_query:
        print(f"  .dns_query:    {record.dns_query}")
        print(f"  .dns_qtype:    {record.dns_query_type}")
    if record.tls_version:
        print(f"  .tls_version:  {record.tls_version}")

    # 打印载荷预览
    if record.payload:
        print(f"  .payload[:120]: {repr(record.payload[:120])}")

    # 展示序列化
    d = record.to_dict()
    print(f"  .to_dict() keys: {list(d.keys())}")
    print(f"  .to_json()[:150]: {record.to_json()[:150]}...")

    print()


# ========================= 第一部分：模拟数据 =========================


if not skip_section1:
    section("第一部分：模拟数据 (无需 scapy / 网卡 / 管理员权限)")

    print("""\
说明: 直接用 create_fake_http_record() 和 create_fake_dns_record()
生成 TrafficRecord 对象。这是最快、最简单的测试方式——完全不需要
安装 scapy、不需要网卡、不需要管理员权限、甚至不需要 PCAP 文件。
模块二/三/四也可以直接用这些函数提前联调。
""")

    from module1_capture.packet_parser import (
        create_fake_http_record,
        create_fake_dns_record,
    )

    print(">>> 1a. 模拟 HTTP GET 请求")
    r1 = create_fake_http_record(
        method="GET",
        uri="/search?q=test&page=1",
        host="example.com",
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        src_port=54321,
        dst_port=80,
    )
    show(r1, "模拟 HTTP GET 请求")

    print(">>> 1b. 模拟 HTTP POST 请求（含登录数据）")
    r2 = create_fake_http_record(
        method="POST",
        uri="/login.php",
        host="bank.example.com",
        body="username=admin&password=123456",
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        src_port=54322,
        dst_port=80,
    )
    show(r2, "模拟 HTTP POST 登录请求")

    print(">>> 1c. 模拟 DNS 查询")
    r3 = create_fake_dns_record(
        query="evil-c2.malware.com",
        query_type="A",
        src_ip="192.168.1.100",
        dst_ip="8.8.8.8",
    )
    show(r3, "模拟 DNS 查询")

    print(">>> 1d. 模拟恶意请求（含 SQL 注入特征，供后续模块二检测）")
    r4 = create_fake_http_record(
        method="GET",
        uri="/index.php?id=1'+OR+'1'='1'--",
        host="vuln-site.com",
        src_ip="10.0.0.5",
        dst_ip="192.168.1.1",
        src_port=44444,
        dst_port=80,
    )
    show(r4, "模拟 SQL 注入攻击请求")

else:
    print("[跳过] 第一部分")


# ========================= 第二部分：PCAP 生成 + 离线解析 =========================


if not skip_section2:
    section("第二部分：生成 PCAP 文件 + 离线解析")

    print("""\
说明: 这部分会:
  1. 用 scapy 手动构造数据包
  2. 保存为 PCAP 文件
  3. 用 CaptureEngine 离线读取这个 PCAP 文件
  4. 展示解析后的 TrafficRecord 完整对象

PCAP 文件保存位置: data/test/demo_test.pcap
你可以用 Wireshark 打开它对比查看。
""")

    # ---- 步骤1: 生成 PCAP ----
    print(">>> 步骤1: 构造数据包，保存为 PCAP 文件")

    pcap_path = Path("data/test/demo_test.pcap")
    pcap_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        from scapy.all import IP, TCP, UDP, Ether, Raw, DNS, DNSQR, wrpcap

        packets = []

        # HTTP GET 请求
        p1 = (
            Ether(src="aa:bb:cc:dd:ee:01", dst="11:22:33:44:55:01")
            / IP(src="192.168.1.100", dst="93.184.216.34")
            / TCP(sport=54321, dport=80, flags="PA")
            / Raw(b"GET /index.php?id=1 HTTP/1.1\r\n"
                  b"Host: example.com\r\n"
                  b"User-Agent: Mozilla/5.0\r\n"
                  b"\r\n")
        )
        packets.append(p1)

        # HTTP 200 响应
        p2 = (
            Ether(src="11:22:33:44:55:01", dst="aa:bb:cc:dd:ee:01")
            / IP(src="93.184.216.34", dst="192.168.1.100")
            / TCP(sport=80, dport=54321, flags="PA")
            / Raw(b"HTTP/1.1 200 OK\r\n"
                  b"Content-Type: text/html\r\n"
                  b"Content-Length: 27\r\n"
                  b"\r\n<html>Hello World</html>")
        )
        packets.append(p2)

        # HTTP POST 含 SQL 注入
        p3 = (
            Ether(src="aa:bb:cc:dd:ee:02", dst="11:22:33:44:55:02")
            / IP(src="10.0.0.5", dst="192.168.1.1")
            / TCP(sport=44444, dport=80, flags="PA")
            / Raw(b"POST /login.php HTTP/1.1\r\n"
                  b"Host: vuln-site.com\r\n"
                  b"Content-Type: application/x-www-form-urlencoded\r\n"
                  b"\r\n"
                  b"username=admin' OR 1=1 --&password=123")
        )
        packets.append(p3)

        # SYN 扫描包 x 3
        for port in [22, 80, 443]:
            p = (Ether(src="aa:bb:cc:dd:ee:03", dst="11:22:33:44:55:03")
                 / IP(src="10.0.0.100", dst="192.168.1.1")
                 / TCP(sport=10000 + port, dport=port, flags="S"))
            packets.append(p)

        # DNS 查询
        p7 = (
            Ether(src="aa:bb:cc:dd:ee:04", dst="11:22:33:44:55:04")
            / IP(src="192.168.1.100", dst="8.8.8.8")
            / UDP(sport=54321, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="evil-c2.malware.com", qtype="A"))
        )
        packets.append(p7)

        wrpcap(str(pcap_path), packets)
        print(f"  已生成 PCAP 文件: {pcap_path} ({len(packets)} 个包)")
        print(f"    - HTTP GET 请求")
        print(f"    - HTTP 200 响应")
        print(f"    - HTTP POST (含SQL注入)")
        print(f"    - SYN 扫描包 x 3 (端口 22, 80, 443)")
        print(f"    - DNS 查询")

    except ImportError:
        print("  [警告] scapy 未安装，无法生成 PCAP 文件")
        print("  请运行: pip install scapy")
        print("  或使用已有的 PCAP 文件")

    # ---- 步骤2: 离线解析 ----
    print(f"\n>>> 步骤2: CaptureEngine 离线解析 PCAP 文件")

    if pcap_path.exists():
        from module1_capture import CaptureEngine

        engine = CaptureEngine(use_message_bus=False)
        records = []

        engine.set_on_traffic_callback(lambda r: records.append(r))
        engine.start(offline_pcap=str(pcap_path))

        print(f"  解析完成! 共 {len(records)} 个数据包\n")

        for i, record in enumerate(records):
            show(record, f"PCAP 数据包 #{i+1}")

        # 统计信息
        stats = engine.get_statistics()
        print(">>> CaptureEngine.get_statistics():")
        print(f"  packet_count:  {stats['packet_count']}")
        print(f"  bytes_total:   {stats['bytes_total']}")
        print(f"  tcp_flows:     {stats['tcp_flows']}")
        print(f"  udp_flows:     {stats['udp_flows']}")
        print(f"  protocols:     {stats['protocols']}")
        print(f"  errors:        {stats['errors']}")
        print(f"  running:       {stats['running']}")
    else:
        print("  [跳过] PCAP 文件不存在")

else:
    print("[跳过] 第二部分")


# ========================= 第三部分：MessageBus 数据流 =========================


if not skip_section3:
    section("第三部分：MessageBus 消息总线数据流")

    print("""\
说明: 在完整系统中，模块一通过 MessageBus 发布流量数据。
这里我们展示订阅总线、发布消息、查看统计的完整流程。
""")

    from common.message_bus import message_bus
    from module1_capture.packet_parser import create_fake_http_record

    # 重置统计
    message_bus.reset_statistics()

    # 注册两个订阅者
    def sub1(record):
        print(f"  [订阅者1] 收到: {record.src.ip}:{record.src.port} -> {record.dst.ip}:{record.dst.port}  [{record.protocol.value}]")

    def sub2(record):
        if record.http_uri:
            print(f"  [订阅者2] URI: {record.http_uri}")
        if record.dns_query:
            print(f"  [订阅者2] DNS: {record.dns_query} ({record.dns_query_type})")

    message_bus.subscribe("traffic_record", sub1)
    message_bus.subscribe("traffic_record", sub2)

    print(">>> 订阅者注册完毕:")
    print(f"  traffic_record 订阅者数: {message_bus.subscriber_count('traffic_record')}")

    print("\n>>> 发布 3 条消息到总线:")
    for i in range(3):
        r = create_fake_http_record(
            method="GET" if i % 2 == 0 else "POST",
            uri=f"/page{i}",
            host=f"site{i}.com",
        )
        message_bus.publish("traffic_record", r)
        print(f"  已发布第 {i+1} 条消息")

    print("\n>>> MessageBus 统计:")
    bus_stats = message_bus.get_statistics()
    print(f"  各事件消息数: {bus_stats['message_counts']}")
    print(f"  总订阅者数:   {bus_stats['total_subscribers']}")
    print(f"  事件类型:     {bus_stats['event_types']}")

else:
    print("[跳过] 第三部分")


# ========================= 第四部分：原始 scapy 包解析 =========================


if not skip_section4:
    section("第四部分：直接解析 scapy 数据包")

    print("""\
说明: parse_packet() 是模块一最底层的函数。
直接输入 scapy 包对象，输出 TrafficRecord。
这里我们手动构造一个包，展示逐层解析的结果。
""")

    print(">>> 构造 HTTP 请求包 (带 Cookie 和 Referer)")
    http_bytes = (
        b"GET /admin/config.php?debug=true&cmd=whoami HTTP/1.1\r\n"
        b"Host: internal-admin.local\r\n"
        b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
        b"Referer: http://internal-admin.local/login.php\r\n"
        b"Cookie: session_id=abc123\r\n"
        b"\r\n"
    )

    # 用模拟 scapy 包
    pkt = MockScapyPacket({
        "IP": MockIP(),
        "TCP": MockTCP(),
        "Raw": MockRaw(http_bytes),
    })

    from module1_capture.packet_parser import parse_packet

    parsed = parse_packet(pkt)
    if parsed:
        show(parsed, "parse_packet() 解析结果")

        print(">>> HTTP query 参数自动解析 (.http_query_params):")
        print(f"  {parsed.http_query_params}")

        print("\n>>> .all_http_text (HTTP 所有文本合并，方便一次性特征匹配):")
        print(f"  {parsed.all_http_text[:200]}...")

    print("\n>>> 非 IP 包测试 (ARP 应返回 None):")
    from module1_capture import parse_packet
    none_pkt = MockScapyPacket({})
    result = parse_packet(none_pkt)
    print(f"  parse_packet(非IP包): {result}")
    assert result is None, "非 IP 包应返回 None"

else:
    print("[跳过] 第四部分")


# ========================= 第五部分：批量解析性能 =========================


if not skip_section5:
    section("第五部分：批量解析性能测试")

    print("""\
说明: 批量解析 1000 个 HTTP 包，测试 parse_packets() 性能。
""")

    from module1_capture.packet_parser import parse_packets

    print(">>> 构造 1000 个模拟 HTTP 包...")
    packets = []
    for i in range(1000):
        http = f"GET /page?n={i} HTTP/1.1\r\nHost: site{i}.com\r\n\r\n"
        packets.append(MockScapyPacket({
            "IP": MockIP(),
            "TCP": MockTCP(),
            "Raw": MockRaw(http.encode()),
        }))

    print(f"  共 {len(packets)} 个包")

    start = time.time()
    records = parse_packets(packets)
    elapsed = time.time() - start

    print(f"\n>>> 解析结果:")
    print(f"  总包数:       {len(packets)}")
    print(f"  成功解析:     {len(records)}")
    print(f"  耗时:         {elapsed:.4f} 秒")
    print(f"  速率:         {len(records)/elapsed:.0f} 包/秒")
    print(f"  每包平均:     {elapsed/len(records)*1000:.3f} 毫秒")

    if elapsed < 0.5:
        print("  ==> 性能达标 (1000包 < 0.5秒)")
    else:
        print(f"  ==> 性能注意: {elapsed:.2f}s")

else:
    print("[跳过] 第五部分")


# ========================= 总结 =========================


section("总结：模块一完整功能一览")

print("""\
  1. 模拟数据生成 (无需网卡/权限/scapy)
     [OK] create_fake_http_record()  -- 生成 HTTP 流量
     [OK] create_fake_dns_record()   -- 生成 DNS 查询

  2. PCAP 文件处理
     [OK] scapy.wrpcap()  -- 生成测试用 PCAP 文件
     [OK] CaptureEngine 离线读取 PCAP 并解析
     [OK] 生成 PCAP 保存到 data/test/demo_test.pcap

  3. 协议解析
     [OK] HTTP: 方法/URI/Header/Body/状态码/Referer
     [OK] DNS:  域名/查询类型
     [OK] TCP:  端口/标志位/SYN检测
     [OK] 非 IP 包跳过

  4. 数据输出
     [OK] 回调函数 (set_on_traffic_callback)
     [OK] MessageBus 发布-订阅
     [OK] to_dict() / to_json() 序列化

  5. 统计信息
     [OK] get_statistics() -> 包数/字节数/流数/协议分布

  6. 性能
     [OK] 1000 包批量解析 (查看上面的耗时)

  7. 测试
     [OK] 32 项自动化单元测试: pytest tests/test_module1.py -v
""")

# 打印生成的 PCAP 文件路径信息
demo_pcap = Path("data/test/demo_test.pcap")
if demo_pcap.exists():
    print(f"\n生成的 PCAP 文件路径: {demo_pcap.resolve()}")
    print("用 Wireshark 打开这个文件，可以看到原始的二进制包数据。")
    print("然后对比上面打印的 TrafficRecord 结构化数据，就能理解")
    print("\"原始包 -> 解析 -> 结构化数据\" 的完整过程。")
