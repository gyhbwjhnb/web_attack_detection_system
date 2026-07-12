"""
============================================================================
模块一 · 在线抓包演示脚本
============================================================================

展示如何从真实网卡抓取数据包，让 NIDS 系统"看见"真实网络流量。

运行前提:
  - Npcap (Windows) 或 LibPcap (Linux) 已安装
  - 管理员权限（Windows: 以管理员身份运行终端；Linux: sudo）
  - pip install scapy

运行方式:
  cd web_attack_detection_system
  python module1_capture/demo_live_capture.py

控制台会实时打印抓到的数据包，按 Enter 停止。

网卡选择说明:
  - 不指定网卡 → 自动选择最优物理网卡（推荐）
  - 手动指定网卡 → 通过 --interface 参数传入（如有多网卡需测特定接口）

  关于多网卡场景：
    本脚本默认只选一块最优网卡抓包，而不是全量抓取所有网卡。
    原因：全量抓取在高流量环境下 CPU/磁盘开销很大，且产生大量重复/
    无关流量，影响检测效率。生产部署时，建议在关键网段入口（如
    连接外网的网关、DMZ 区域）分别部署抓包点，而不是单机全量抓取。

    如需同时在多块网卡抓包，可启动多个 CaptureEngine 实例
    （见本脚本第 4 部分示例）。

示例输出:
  TrafficRecord(id=a1b2c3d4e5f6, 192.168.1.100:54321 -> 93.184.216.34:80, HTTP)
    ├── GET /index.php HTTP/1.1
    ├── Host: example.com
    └── User-Agent: Mozilla/5.0 ...
============================================================================
"""

import sys
from pathlib import Path

# 确保项目根目录在 sys.path 中
sys.path.insert(0, str(Path(__file__).parent.parent))


SEP = "=" * 72


def section(title):
    print(f"\n{SEP}")
    print(f"  {title}")
    print(SEP)


def show(record, label="在线抓包"):
    """完整打印 TrafficRecord 的所有字段"""
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
        flags_desc = []
        if flags_int & 0x02: flags_desc.append('SYN')
        if flags_int & 0x04: flags_desc.append('RST')
        if flags_int & 0x08: flags_desc.append('PSH')
        if flags_int & 0x10: flags_desc.append('ACK')
        if flags_int & 0x01: flags_desc.append('FIN')
        flag_str = f"{flags_int:#05x} ({'+'.join(flags_desc)})" if flags_desc else f"{flags_int:#05x}"
        print(f"  .flags:        {flag_str}")
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
            print(f"  .http_ua:      {record.http_user_agent[:60]}...")
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

    # 载荷预览
    if record.payload:
        print(f"  .payload[:120]: {repr(record.payload[:120])}")

    # 序列化展示（模块二/三将接收这个字典）
    d = record.to_dict()
    print(f"  .to_dict() keys: {list(d.keys())}")


# ====================================================================
# 第 1 部分：列出所有可用网卡（辅助用户选择）
# ====================================================================

section("第 1 部分：列出所有可用网卡")

print("""\
说明: 这里调用 scapy 列出系统中的所有网络接口。
每个接口的 GUID、IP 地址和描述都会被打印出来。
如果你需要手动指定网卡，从这里复制 GUID 即可。
""")

try:
    # 尝试两种方式获取网卡列表
    ifaces = []
    try:
        from scapy.all import get_working_ifaces
        ifaces = get_working_ifaces()
    except ImportError:
        print("  [错误] scapy 未安装，请执行: pip install scapy")
        sys.exit(1)

    if not ifaces:
        try:
            from scapy.all import IFACES
            ifaces = IFACES
        except (ImportError, AttributeError):
            pass

    if not ifaces:
        print("  未检测到任何网卡，请确认 Npcap/LibPcap 已安装且以管理员权限运行。")
        sys.exit(1)

    virtual_keywords = [
        'virtual', 'vmware', 'vbox', 'virtualbox',
        'hyper-v', 'hyperv', 'docker', 'wsl',
        'npcap loopback', 'loopback adapter',
        'bluetooth', 'vmxnet', 'pbl', 'nfl',
    ]

    print(f"  共发现 {len(ifaces)} 个网络接口:\n")
    for idx, iface in enumerate(ifaces):
        name = iface.name if hasattr(iface, 'name') else str(iface)
        ip = iface.ip if hasattr(iface, 'ip') else ''
        desc = iface.description if hasattr(iface, 'description') else '(无描述)'
        win_name = iface.win_name if hasattr(iface, 'win_name') else ''

        # 判断类型标记
        text = (name + ' ' + desc + ' ' + win_name).lower()
        is_virtual = any(k in text for k in virtual_keywords)
        is_loopback = (ip == '127.0.0.1' or name in ('lo', 'loopback'))
        is_apipa = ip.startswith('169.254.') if ip else False

        tags = []
        if is_loopback:
            tags.append('回环')
        elif is_virtual:
            tags.append('虚拟')
        elif 'ethernet' in text or '以太网' in text:
            tags.append('有线')
        elif 'wi-fi' in text or 'wlan' in text or '无线' in text:
            tags.append('无线')
        if is_apipa:
            tags.append('APIPA')
        if ip:
            tags.append(f'IP={ip}')

        tag_str = f"[{'/'.join(tags)}]" if tags else ''
        display_name = win_name or desc or name
        print(f"  [{idx}] {name}")
        print(f"       {display_name}  {tag_str}")

    print()

    # 提示接口选择建议
    print("  网卡选择建议:")
    print("    - 上网方式为有线 → 选含「以太网」标记的接口")
    print("    - 上网方式为Wi-Fi → 选含「无线」标记的接口")
    print("    - 不确定 → 直接运行本脚本，会自动选择最优接口")

except ImportError:
    print("  [错误] scapy 未安装，请执行: pip install scapy")
    sys.exit(1)


# ====================================================================
# 第 2 部分：自动选择网卡抓包
# ====================================================================

section("第 2 部分：自动选择网卡抓包")

print("""\
说明: 使用 CaptureEngine 的自动选网卡功能（interface=None）。
系统会按优先级自动选择最优物理网卡：
  物理有线 → 物理无线 → 其他物理网卡 → 虚拟网卡(备用)

自动过滤的虚拟适配器：
  VMware / VirtualBox / Hyper-V / Docker / WSL / Npcap Loopback / Bluetooth
""")

auto_count = 5  # 自动抓 5 个包

try:
    from module1_capture import CaptureEngine

    engine = CaptureEngine(use_message_bus=False)
    records_auto = []
    engine.set_on_traffic_callback(lambda r: records_auto.append(r))

    print(f"  正在自动选择网卡并抓取 {auto_count} 个 TCP 包...")
    print(f"  (按 Enter 键提前停止)\n")

    success = engine.start(
        interface=None,
        filter_expr="tcp",
        packet_count=auto_count,
    )

    if not success:
        print("  [失败] 自动选择网卡未能启动抓包。")
        print("  请尝试手动指定网卡（见第 3 部分）。")
    else:
        input("  抓包中，按 Enter 停止...\n")
        engine.stop()

        if records_auto:
            print(f"\n  抓到 {len(records_auto)} 个数据包:")
            for i, record in enumerate(records_auto):
                show(record, f"包 #{i + 1}")
        else:
            print("  未抓到数据包（可能过滤条件太严格或无流量经过）")

        stats = engine.get_statistics()
        print(f"\n  统计: {stats['packet_count']} 包, "
              f"{stats['tcp_flows']} TCP 流, "
              f"{stats['udp_flows']} UDP 流")
        print(f"  协议分布: {stats['protocols']}")

except ImportError as e:
    print(f"  [错误] 模块导入失败: {e}")


# ====================================================================
# 第 3 部分：手动指定网卡抓包（可选）
# ====================================================================

section("第 3 部分：手动指定网卡抓包（可选）")

print("""\
说明: 如果自动选择不满足需求，可以手动指定网卡 GUID。
从第 1 部分的列表中找到目标网卡的 GUID（如 \\Device\\NPF_{...}），
填入下面的 interface 参数即可。

取消下方 skip_section3 = True 的注释即可运行。
""")

skip_section3 = True  # ← 改成 False 并填入你的网卡 GUID
MANUAL_INTERFACE = r"\Device\NPF_{54F34B6D-E210-4309-A889-CC1B2FABADC9}"
manual_count = 5

if not skip_section3:
    try:
        engine2 = CaptureEngine(use_message_bus=False)
        records_manual = []
        engine2.set_on_traffic_callback(lambda r: records_manual.append(r))

        print(f"  使用网卡: {MANUAL_INTERFACE}")
        print(f"  抓取 {manual_count} 个 TCP 包...\n")

        success = engine2.start(
            interface=MANUAL_INTERFACE,
            filter_expr="tcp",
            packet_count=manual_count,
        )

        if success:
            input("  抓包中，按 Enter 停止...\n")
            engine2.stop()

            print(f"\n  抓到 {len(records_manual)} 个数据包:")
            for i, record in enumerate(records_manual):
                show(record, f"包 #{i + 1}")
        else:
            print("  [失败] 指定网卡未能启动抓包，请检查 GUID 是否正确。")

    except Exception as e:
        print(f"  [错误] {e}")
else:
    print("  [跳过] 请修改 skip_section3 = False 并填入你的网卡 GUID 来运行此部分")
    print(f"  示例 GUID: {MANUAL_INTERFACE}")


# ====================================================================
# 第 4 部分：多网卡综合抓包（高级功能 / 参考）
# ====================================================================

section("第 4 部分：多网卡综合抓包（高级功能 / 参考）")

print("""\
说明: NIDS 生产部署时，经常需要在多个网段入口同时抓包。
这里展示如何在一个脚本中启动多个 CaptureEngine 实例。

注意：多网卡抓包会显著增加 CPU 和内存开销，请根据实际
流量规模决定是否启用。建议只在以下场景使用：
  1. 检测内部横向移动攻击（内网多段监听）
  2. 蜜罐 / 诱捕网络的多入口流量采集
  3. 临时排障需要对比多路径流量

如果只是日常检测互联网出口流量，单网卡自动选择就足够了。
""")

skip_section4 = True  # ← 改成 False 启用多网卡抓包

if not skip_section4:
    # 在此填入你想同时抓包的多块网卡 GUID
    multi_interfaces = [
        r"\Device\NPF_{54F34B6D-E210-4309-A889-CC1B2FABADC9}",
        # r"\Device\NPF_{另一个网卡的 GUID}",
    ]

    engines = []
    all_records = []

    for idx, iface in enumerate(multi_interfaces):
        eng = CaptureEngine(use_message_bus=False)
        records = []
        eng.set_on_traffic_callback(lambda r, rec=records: rec.append(r))
        ok = eng.start(interface=iface, filter_expr="tcp", packet_count=3)
        if ok:
            engines.append(eng)
            all_records.append((iface, records))
            print(f"  [引擎 {idx + 1}] {iface} → 启动成功")
        else:
            print(f"  [引擎 {idx + 1}] {iface} → 启动失败")

    if engines:
        input("\n  多引擎抓包中，按 Enter 停止...\n")
        for eng in engines:
            eng.stop()

        for iface, records in all_records:
            print(f"\n  --- {iface} ({len(records)} 包) ---")
            for r in records:
                print(f"    {r}")
    else:
        print("  所有引擎均启动失败，请检查网卡 GUID。")
else:
    print("  [跳过] 多网卡抓包默认关闭，如需启用请修改 skip_section4 = False")


# ====================================================================
# 总结
# ====================================================================

section("总结")

print("""\
在线抓包要点:

  1. 单网卡自动选择（推荐日常使用）
     - 调用 engine.start(interface=None) 即可
     - 系统自动选最优网卡，过滤虚拟适配器

  2. 手动指定网卡
     - 从网卡列表中复制 GUID
     - 调用 engine.start(interface="\\Device\\NPF_{...}")

  3. 多网卡综合抓包（高级）
     - 启动多个 CaptureEngine 实例
     - 用于内网横向移动检测等场景
     - 注意 CPU/内存开销

  4. 网卡选择原则（针对 NIDS 攻击检测）
     - 物理网卡（非虚拟）是必须的
     - 优先选连接互联网的网卡（能检测外部攻击）
     - 如需检测内网横向移动，再增加内网段监听
     - 不建议全量抓取所有网卡 —— 流量大、干扰多

  5. 通过 filter_expr 参数过滤流量
     - "tcp" 或 "udp" — 仅抓 TCP/UDP 包
     - "port 80" — 仅抓 HTTP 流量
     - "host 10.0.0.1" — 仅抓特定 IP
     - 空字符串 "" — 抓所有流量（最全面，但数据量大）
""")
