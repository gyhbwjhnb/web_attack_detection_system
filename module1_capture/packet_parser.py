"""
============================================================================
协议解析模块 —— 将原始 scapy 数据包解析为 TrafficRecord
============================================================================

职责:
  1. 解析以太网帧 → Ether
  2. 解析网络层 → IP / IPv6
  3. 解析传输层 → TCP / UDP / ICMP
  4. 解析应用层 → HTTP / DNS / TLS（浅解析）
  5. 生成统一 TrafficRecord 结构

设计原则:
  - 每个解析函数只关注自己那一层的字段，不跨层
  - 解析失败时不抛异常，返回默认值
  - 与 scapy 解耦：外部传入 scapy 包对象，内部只读

用法:
    from module1_capture.packet_parser import parse_packet

    packet = scapy_packet  # 从 sniff() 或 rdpcap() 得到
    record = parse_packet(packet)
    if record:
        print(record.to_json())
============================================================================
"""

import logging
from typing import Optional, List
from urllib.parse import unquote

from common.data_structures import (
    TrafficRecord, IPEndpoint, ProtocolType,
)

logger = logging.getLogger("packet_parser")


# ==================== 主解析入口 ====================

def parse_packet(packet) -> Optional[TrafficRecord]:
    """
    解析一个 scapy 数据包，返回 TrafficRecord。

    Args:
        packet: scapy 包对象（Packet 或其子类）

    Returns:
        TrafficRecord 实例，解析失败返回 None

    流程:
        1. 先检查 ARP（二层协议，独立处理）
        2. 再检查 IP 层（无 IP 层的包跳过）
        3. 初始化 TrafficRecord
        4. 逐层解析: Ether → IP → TCP/UDP/ICMP → HTTP/DNS/TLS
        5. 提取载荷
    """
    try:
        # ---- 先检查 ARP（独立于 IP 的链路层协议） ----
        if packet.haslayer("ARP"):
            return _parse_arp(packet)

        # ---- 必须有 IP 层 ----
        if packet.haslayer("IP"):
            ip_layer = packet["IP"]
        elif packet.haslayer("IPv6"):
            ip_layer = packet["IPv6"]
        else:
            # 非 IP 包（PPPoE 等），跳过
            return None

        record = TrafficRecord()

        # ---- 解析各层 ----
        _parse_ethernet(packet, record)
        _parse_ip(ip_layer, record)
        _parse_transport(packet, record)
        _parse_payload(packet, record)

        # 在检测应用层协议前，记录传输层协议（用于流ID）
        transport_layer_protocol = record.protocol

        _detect_application_protocol(record, packet)

        # ---- 包长度 ----
        record.payload_size = len(record.payload_raw)

        # ---- 流 ID（五元组 hash，基于传输层协议） ----
        if transport_layer_protocol in (ProtocolType.TCP, ProtocolType.UDP):
            record.flow_id = f"{record.src.ip}:{record.src.port}-{record.dst.ip}:{record.dst.port}-{transport_layer_protocol.value}"
            record.flow_packet_count = 1

        return record

    except Exception as e:
        logger.debug(f"解析数据包异常: {e}", exc_info=True)
        return None


# ==================== 各层解析函数 ====================


def _parse_arp(packet) -> Optional[TrafficRecord]:
    """解析 ARP 协议（请求/响应），用于 ARP 欺骗/扫描检测"""
    try:
        arp = packet["ARP"]
        record = TrafficRecord()
        record.protocol = ProtocolType.ARP

        # MAC
        if packet.haslayer("Ether"):
            record.src.mac = packet["Ether"].src
            record.dst.mac = packet["Ether"].dst

        # ARP 字段
        record.src.ip = arp.psrc
        record.dst.ip = arp.pdst
        record.src.mac = arp.hwsrc if hasattr(arp, 'hwsrc') and arp.hwsrc else record.src.mac
        record.dst.mac = arp.hwdst if hasattr(arp, 'hwdst') and arp.hwdst else record.dst.mac

        op = int(arp.op) if hasattr(arp.op, '__int__') else arp.op
        if op == 1:
            record.protocol_detail = "ARP Request"
            record.flags = 1  # request
        elif op == 2:
            record.protocol_detail = "ARP Reply"
            record.flags = 2  # reply

        record.flow_id = f"ARP:{record.src.ip}->{record.dst.ip}"
        record.payload_size = 28  # ARP 固定头长度

        # tags: 标记可疑 ARP
        record.tags.append("arp")

        return record
    except Exception as e:
        logger.debug(f"ARP 解析异常: {e}")
        return None


def _parse_ethernet(packet, record: TrafficRecord):
    """解析以太网层，提取 MAC 地址"""
    try:
        if packet.haslayer("Ether"):
            record.src.mac = packet["Ether"].src
            record.dst.mac = packet["Ether"].dst
    except Exception:
        pass  # MAC 不是必须字段


def _parse_ip(ip_layer, record: TrafficRecord):
    """解析 IP 层，提取 IP 地址和协议类型"""
    try:
        # IP 版本检测
        if hasattr(ip_layer, "version"):
            if ip_layer.version == 6:
                record.src.ip = ip_layer.src
                record.dst.ip = ip_layer.dst
                record.protocol = _map_ip_protocol(ip_layer.nh)  # IPv6 next header
                return
            elif ip_layer.version == 4:
                record.src.ip = ip_layer.src
                record.dst.ip = ip_layer.dst
                # IP 头的协议字段: 6=TCP, 17=UDP, 1=ICMP
                proto_map = {6: ProtocolType.TCP, 17: ProtocolType.UDP, 1: ProtocolType.ICMP}
                record.protocol = proto_map.get(ip_layer.proto, ProtocolType.UNKNOWN)
                return

        # 兜底：直接读字段
        if hasattr(ip_layer, "src"):
            record.src.ip = ip_layer.src
        if hasattr(ip_layer, "dst"):
            record.dst.ip = ip_layer.dst

    except Exception as e:
        logger.debug(f"IP 层解析异常: {e}")


def _map_ip_protocol(proto_num: int) -> ProtocolType:
    """IPv6 下一头部号 → ProtocolType"""
    proto_map = {6: ProtocolType.TCP, 17: ProtocolType.UDP, 58: ProtocolType.ICMP}
    return proto_map.get(proto_num, ProtocolType.UNKNOWN)


def _parse_transport(packet, record: TrafficRecord):
    """解析传输层（TCP/UDP/ICMP），提取端口和标志位"""
    try:
        if packet.haslayer("TCP"):
            tcp = packet["TCP"]
            record.src.port = tcp.sport
            record.dst.port = tcp.dport
            record.protocol = ProtocolType.TCP
            record.flags = int(tcp.flags) if not isinstance(tcp.flags, int) else tcp.flags
            record.seq_num = tcp.seq
            record.ack_num = tcp.ack

        elif packet.haslayer("UDP"):
            udp = packet["UDP"]
            record.src.port = udp.sport
            record.dst.port = udp.dport
            record.protocol = ProtocolType.UDP

        elif packet.haslayer("ICMP"):
            record.protocol = ProtocolType.ICMP
            try:
                icmp = packet["ICMP"]
                record.icmp_type = int(icmp.type) if hasattr(icmp.type, '__int__') else icmp.type
                record.icmp_code = int(icmp.code) if hasattr(icmp.code, '__int__') else icmp.code
                # 添加可读的 ICMP 类型描述
                type_desc = {
                    0: "Echo Reply", 3: "Dest Unreachable", 4: "Source Quench",
                    5: "Redirect", 8: "Echo Request", 11: "Time Exceeded",
                }
                record.protocol_detail = type_desc.get(record.icmp_type, f"Type{record.icmp_type}")
            except Exception:
                pass

    except Exception as e:
        logger.debug(f"传输层解析异常: {e}")


def _parse_payload(packet, record: TrafficRecord):
    """
    提取应用层载荷。

    策略:
      1. TCP/UDP: 取 Raw 层（如果有）
      2. ICMP: 取 ICMP 载荷（用于检测 ICMP 隧道）
      3. 限制最大载荷长度，防止内存溢出
    """
    MAX_PAYLOAD = 65536  # 64KB 上限

    try:
        # ---- TCP/UDP Raw 载荷 ----
        if packet.haslayer("Raw"):
            raw = packet["Raw"].load
            if isinstance(raw, (bytes, bytearray)):
                record.payload_raw = raw[:MAX_PAYLOAD]
                try:
                    record.payload = raw.decode("utf-8", errors="replace")
                except Exception:
                    record.payload = raw.decode("latin-1", errors="replace")
            else:
                record.payload = str(raw)[:MAX_PAYLOAD]
                record.payload_raw = record.payload.encode("utf-8", errors="replace")

        # ---- ICMP 载荷（ICMP 隧道检测用） ----
        if record.protocol == ProtocolType.ICMP and packet.haslayer("ICMP"):
            try:
                icmp = packet["ICMP"]
                if hasattr(icmp, 'payload') and icmp.payload:
                    raw = bytes(icmp.payload)
                    if raw and len(raw) > 0:
                        record.payload_raw = raw[:MAX_PAYLOAD]
                        record.payload = raw.decode("utf-8", errors="replace")
            except Exception:
                pass

    except Exception as e:
        logger.debug(f"载荷提取异常: {e}")


# ==================== 应用层协议检测 ====================


def _detect_application_protocol(record: TrafficRecord, packet=None):
    """检测应用层协议（HTTP / DNS / TLS / SMB / SSH 等）

    Args:
        record: TrafficRecord 实例
        packet: 原始 scapy 包（可选，用于直接从 scapy 层提取信息如 DNS）
    """
    payload = record.payload
    payload_upper = payload[:1024].upper() if payload else ""

    # ---- DNS 检测（优先于端口标记，支持无 Raw 层的 scapy DNS） ----
    if record.dst.port == 53 or record.src.port == 53:
        # 尝试从 scapy DNS 层提取（IP/UDP/DNS 结构无 Raw 层的情况）
        if packet and packet.haslayer("DNS"):
            _parse_dns_from_scapy(packet["DNS"], record)
        else:
            _parse_dns(record)
        return  # DNS 检测到后直接返回，不走端口标记

    # ---- HTTP 检测（基于内容） ----
    if payload and _is_http(payload, payload_upper):
        _parse_http(record)
        return

    # ---- 基于端口的协议标记（SSH/FTP/SMTP/攻击服务等） ----
    _mark_port_protocol(record)

    # ---- TLS 检测（基于内容，优先级高于端口标记） ----
    if payload and _detect_tls(record):
        return

    # 端口 443/80 回退标记（仅在 TLS 内容检测未命中时使用）
    if record.dst.port == 443 or record.src.port == 443:
        if not record.protocol_detail:
            record.protocol_detail = "HTTPS/TLS"
    elif record.dst.port == 80 or record.src.port == 80:
        if not record.protocol_detail:
            record.protocol_detail = "HTTP"


def _mark_port_protocol(record: TrafficRecord):
    """基于端口的协议标记（适用于无载荷或无法内容识别的包）

    注意：只设置 protocol_detail，不覆盖 record.protocol（保留传输层协议）。
    """
    port = record.dst.port or record.src.port

    # 远程管理/漏洞利用类
    if port in (22,):
        record.protocol_detail = "SSH"
    elif port in (21,):
        record.protocol_detail = "FTP"
    elif port in (25,):
        record.protocol_detail = "SMTP"
    elif port in (3389,):
        record.protocol_detail = "RDP"
    elif port in (445, 139):
        record.protocol_detail = f"SMB (port {port})"
    # 数据库类
    elif port in (3306, 3307):
        record.protocol_detail = "MySQL"
    elif port in (6379, 6380):
        record.protocol_detail = "Redis"
    elif port in (27017, 27018):
        record.protocol_detail = "MongoDB"


# ==================== HTTP 解析 ====================


HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD",
                "OPTIONS", "CONNECT", "TRACE"}


def _is_http(payload: str, payload_upper: str) -> bool:
    """
    判断是否为 HTTP 协议。

    增强校验防止二进制载荷误判为 HTTP（TLS 加密数据解码为 latin-1
    后可能随机包含 "GET"、"POST" 等字节序列）。

    校验规则:
      请求: "METHOD /uri HTTP/1.x" 格式
      响应: "HTTP/1.x 200 OK" 格式
    """
    first_line = payload_upper.split("\r\n")[0].split("\n")[0].strip()
    if not first_line:
        return False

    # ---- 响应检测: "HTTP/" 开头 ----
    if first_line.startswith("HTTP/"):
        # 必须包含协议版本和状态码，如 "HTTP/1.1 200"
        parts = first_line.split()
        return len(parts) >= 2 and ("/1." in parts[0] or "/2" in parts[0])

    # ---- 请求检测: METHOD 开头 ----
    for method in HTTP_METHODS:
        if first_line.startswith(method):
            # 增强校验：确保格式为 "METHOD /uri HTTP/version"
            parts = first_line.split()
            if len(parts) < 2:
                return False
            uri = parts[1]
            # URI 必须以 '/' 开头（排除二进制数据恰好以 GET 开头的情况）
            # 例外: CONNECT 方法的 URI 为 "host:port" 格式（代理隧道）
            if method == "CONNECT":
                # CONNECT 格式: "CONNECT host:port HTTP/version"
                if ":" not in uri:
                    return False
            elif not uri.startswith("/"):
                # HTTP/1.1 允许代理请求的绝对 URI: "GET http://host/path HTTP/1.1"
                if not (uri.startswith("http://") or uri.startswith("https://")):
                    return False
            # 如果有第三部分，必须是 HTTP/ 版本
            if len(parts) >= 3 and not parts[2].startswith("HTTP/"):
                return False
            return True

    return False


def _parse_http(record: TrafficRecord):
    """
    解析 HTTP 请求/响应的关键字段。

    请求示例:  GET /index.php?id=1 HTTP/1.1
    响应示例:  HTTP/1.1 200 OK

    注意：不覆盖 record.protocol（保留传输层协议 TCP），
    应用层协议信息通过 protocol_detail 和各 HTTP 字段传递。
    """
    record.protocol_detail = record.protocol_detail or "HTTP"
    lines = record.payload.split("\r\n")
    if not lines:
        lines = record.payload.split("\n")

    if not lines:
        return

    # ---- 解析请求行或响应行 ----
    first_line = lines[0].strip()
    first_line_upper = first_line.upper()

    # 尝试匹配: METHOD URI HTTP/version
    parts = first_line.split(" ")
    if len(parts) >= 2 and parts[0].upper() in HTTP_METHODS:
        record.http_method = parts[0]  # 保留原始大小写
        record.http_uri = unquote(parts[1]) if len(parts) > 1 else ""
        # 处理绝对 URI（代理请求）: "GET http://host/path HTTP/1.1"
        if record.http_uri.startswith("http://") or record.http_uri.startswith("https://"):
            # 从绝对 URI 中提取 host（如果 Headers 中没有 Host 字段）
            if "://" in record.http_uri:
                rest = record.http_uri.split("://", 1)[1]
                if "/" in rest:
                    host_part = rest.split("/", 1)[0]
                    if not record.http_host:
                        record.http_host = host_part
        if len(parts) >= 3:
            record.protocol_detail = parts[2]
    elif first_line_upper.startswith("HTTP/"):
        # 响应行
        record.http_method = "RESPONSE"
        if len(parts) >= 2:
            try:
                record.http_status_code = int(parts[1])
            except ValueError:
                pass
        record.protocol_detail = parts[0] if parts else ""

    # ---- 解析请求头 ----
    header_end = -1
    for i, line in enumerate(lines[1:], start=1):
        stripped = line.strip()
        if not stripped:
            header_end = i
            break
        if ":" in stripped:
            key, value = stripped.split(":", 1)
            key = key.strip().lower()
            value = value.strip()
            record.http_headers[key] = value

            # 提取常用头字段
            if key == "host":
                record.http_host = value
            elif key == "user-agent":
                record.http_user_agent = value
            elif key == "referer":
                record.http_referer = unquote(value)

    # ---- 提取请求体 ----
    if header_end >= 0 and header_end + 1 < len(lines):
        body = "\r\n".join(lines[header_end + 1:])
        record.http_body = body.strip()


# ==================== DNS 解析 ====================


def _parse_dns(record: TrafficRecord):
    """解析 DNS 协议，提取查询域名和响应资源记录

    注意：不覆盖 record.protocol（保留传输层协议 UDP），
    应用层协议名称存入 protocol_detail。
    """
    record.protocol_detail = record.protocol_detail or "DNS"
    try:
        raw = record.payload_raw
        if len(raw) < 12:
            return

        # DNS header: ID(2) + flags(2) + qdcount(2) + ancount(2) + nscount(2) + arcount(2)
        dns_id = (raw[0] << 8) | raw[1]
        dns_flags = (raw[2] << 8) | raw[3]
        qdcount = (raw[4] << 8) | raw[5]
        ancount = (raw[6] << 8) | raw[7]
        is_response = bool(dns_flags & 0x8000)

        if qdcount == 0:
            return

        # ---- 解析查询部分：提取域名 ----
        offset = 12
        domain_parts = []
        while offset < len(raw):
            length = raw[offset]
            if length == 0:
                offset += 1
                break
            if length & 0xC0:  # 压缩指针
                # 处理压缩指针: 2 字节指向包内其他位置
                ptr = ((length & 0x3F) << 8) | raw[offset + 1]
                # 从指针位置展开域名
                _expand_dns_name(raw, ptr, domain_parts)
                offset += 2
                break
            offset += 1
            if offset + length > len(raw):
                break
            try:
                part = raw[offset:offset + length].decode("ascii", errors="replace")
                domain_parts.append(part)
            except Exception:
                break
            offset += length

        if domain_parts:
            record.dns_query = ".".join(domain_parts)

        # 查询类型 (在域名结束后的 2 字节)
        if offset + 2 <= len(raw):
            qtype = (raw[offset] << 8) | raw[offset + 1]
            type_map = {1: "A", 28: "AAAA", 15: "MX", 16: "TXT",
                        5: "CNAME", 2: "NS", 255: "ANY"}
            record.dns_query_type = type_map.get(qtype, f"TYPE{qtype}")
            offset += 4  # 跳过 QTYPE + QCLASS

        # ---- 解析响应部分：提取答案 (ancount 个资源记录) ----
        if is_response and ancount > 0:
            _parse_dns_answers(raw, offset, ancount, record)

    except Exception as e:
        logger.debug(f"DNS 解析异常: {e}")


def _parse_dns_from_scapy(dns_layer, record: TrafficRecord):
    """从 scapy 的 DNS 层提取信息（用于 IP/UDP/DNS 结构）

    注意：不覆盖 record.protocol（保留传输层协议 UDP），
    应用层协议名称存入 protocol_detail。
    """
    try:
        record.protocol_detail = record.protocol_detail or "DNS"
        # 查询域名
        if hasattr(dns_layer, 'qd') and dns_layer.qd:
            qd = dns_layer.qd
            if hasattr(qd, 'qname'):
                qname = qd.qname
                if isinstance(qname, bytes):
                    record.dns_query = qname.decode("ascii", errors="replace").rstrip(".")
                else:
                    record.dns_query = str(qname).rstrip(".")
            # 查询类型
            if hasattr(qd, 'qtype'):
                type_map = {1: "A", 28: "AAAA", 15: "MX", 16: "TXT",
                            5: "CNAME", 2: "NS", 255: "ANY"}
                record.dns_query_type = type_map.get(qd.qtype, f"TYPE{qd.qtype}")
        # 响应答案
        is_response = bool(dns_layer.qr) if hasattr(dns_layer, 'qr') else False
        if is_response and hasattr(dns_layer, 'an') and dns_layer.an:
            for ans in dns_layer.an:
                if hasattr(ans, 'rdata'):
                    rdata = ans.rdata
                    if isinstance(rdata, bytes):
                        try:
                            rdata = rdata.decode("ascii", errors="replace")
                        except Exception:
                            rdata = str(rdata)
                    record.dns_answers.append(str(rdata))
    except Exception as e:
        logger.debug(f"scapy DNS 解析异常: {e}")


def _expand_dns_name(raw: bytes, offset: int, parts: list):
    """展开 DNS 压缩域名，最多追踪 255 跳防循环指针链"""
    max_hops = 255
    visited = set()
    while offset < len(raw) and max_hops > 0:
        if offset in visited:  # 循环指针链检测
            break
        visited.add(offset)
        max_hops -= 1
        length = raw[offset]
        if length == 0:
            break
        if length & 0xC0:  # 压缩指针
            ptr = ((length & 0x3F) << 8) | raw[offset + 1]
            offset = ptr
            continue
        offset += 1
        if offset + length > len(raw):
            break
        try:
            part = raw[offset:offset + length].decode("ascii", errors="replace")
            parts.append(part)
        except Exception:
            break
        offset += length


def _parse_dns_answers(raw: bytes, offset: int, ancount: int, record: TrafficRecord):
    """解析 DNS 响应中的 A/AAAA/CNAME 资源记录"""
    for _ in range(ancount):
        if offset >= len(raw):
            break
        # 域名 (可能是指针)
        if raw[offset] & 0xC0:
            offset += 2  # 跳过压缩指针
        else:
            while offset < len(raw) and raw[offset] != 0:
                # 域名中的压缩指针标记（多标签名内嵌指针）
                if raw[offset] & 0xC0:
                    offset += 2
                    break
                offset += raw[offset] + 1
                if offset > len(raw):
                    break
            if offset < len(raw) and raw[offset] == 0:
                offset += 1  # 跳过结束符
        if offset + 10 > len(raw):
            break
        # TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
        rtype = (raw[offset] << 8) | raw[offset + 1]
        rdlength = (raw[offset + 8] << 8) | raw[offset + 9]
        offset += 10
        if offset + rdlength > len(raw):
            break
        # 解析 A / AAAA / CNAME 记录
        if rtype == 1 and rdlength == 4:  # A 记录
            ip = ".".join(str(raw[offset + i]) for i in range(4))
            record.dns_answers.append(ip)
        elif rtype == 28 and rdlength == 16:  # AAAA 记录
            ip = ":".join(f"{raw[offset + i * 2]:02x}{raw[offset + i * 2 + 1]:02x}" for i in range(8))
            record.dns_answers.append(ip)
        elif rtype == 5:  # CNAME
            cname_parts = []
            _expand_dns_name(raw, offset, cname_parts)
            if cname_parts:
                record.dns_answers.append(".".join(cname_parts))
        elif rtype == 16:  # TXT
            txt_len = raw[offset] if rdlength > 0 else 0
            if txt_len > 0:
                txt = raw[offset + 1:offset + 1 + min(txt_len, rdlength - 1)].decode("ascii", errors="replace")
                record.dns_answers.append(txt)
        offset += rdlength


# ==================== TLS 检测 ====================


def _detect_tls(record: TrafficRecord) -> bool:
    """
    检测 TLS 记录层协议，提取版本号和 SNI。

    支持以下 TLS 记录类型:
      0x14 = ChangeCipherSpec (20)
      0x15 = Alert (21)
      0x16 = Handshake (22) —— 含 ClientHello/ServerHello
      0x17 = Application Data (23, 加密数据)

    Returns:
        True 如果检测到 TLS 内容
    """
    raw = record.payload_raw
    if len(raw) < 5:
        return False

    # TLS 记录层: ContentType(1) + Version(2) + Length(2)
    content_type = raw[0]

    # ---- 统一版本提取 ----
    ver_str = ""
    if len(raw) >= 3:
        ver_map = {
            (0x03, 0x01): "TLS 1.0",
            (0x03, 0x02): "TLS 1.1",
            (0x03, 0x03): "TLS 1.2",
            (0x03, 0x04): "TLS 1.3",
        }
        ver = (raw[1], raw[2])
        ver_str = ver_map.get(ver, f"TLS 0x{raw[1]:02x}{raw[2]:02x}")

    if content_type == 0x16:  # 22 = Handshake
        record.tls_version = ver_str or "TLS (handshake)"
        record.protocol_detail = record.tls_version

        # 从 ClientHello (HandshakeType=0x01) 提取 SNI
        if len(raw) >= 6 and raw[5] == 0x01:
            _extract_tls_sni(raw, record)

        return True

    elif content_type == 0x17:  # 23 = Application Data (加密数据)
        record.tls_version = ver_str or "TLS (encrypted)"
        record.protocol_detail = "TLS Application Data"
        return True

    elif content_type == 0x14:  # 20 = ChangeCipherSpec
        record.tls_version = ver_str or "TLS"
        record.protocol_detail = "TLS ChangeCipherSpec"
        return True

    elif content_type == 0x15:  # 21 = Alert
        record.tls_version = ver_str or "TLS"
        record.protocol_detail = "TLS Alert"
        return True

    return False


def _extract_tls_sni(raw: bytes, record: TrafficRecord):
    """
    从 TLS ClientHello 中提取 SNI (Server Name Indication)。

    ClientHello 结构（跳过固定字段后，在 extensions 中找 server_name）:
      HandshakeType(1) + Length(3) + Version(2) + Random(32) + SessionID(1+var)
      + CipherSuites(2+var) + Compression(1+var) + Extensions(2+var)
    """
    try:
        offset = 6   # ContentType(1) + Version(2) + Length(2) + HandshakeType(1)
        if offset + 3 > len(raw):
            return
        hs_len = (raw[offset] << 16) | (raw[offset + 1] << 8) | raw[offset + 2]
        offset += 3
        if offset + hs_len > len(raw):
            return

        offset += 2  # 跳过 Version(2)
        offset += 32  # 跳过 Random(32)

        # Session ID
        if offset >= len(raw):
            return
        sid_len = raw[offset]
        offset += 1 + sid_len

        # Cipher Suites
        if offset + 1 >= len(raw):
            return
        cs_len = (raw[offset] << 8) | raw[offset + 1]
        offset += 2 + cs_len

        # Compression Methods
        if offset >= len(raw):
            return
        cm_len = raw[offset]
        offset += 1 + cm_len

        # Extensions
        if offset + 1 >= len(raw):
            return
        ext_total_len = (raw[offset] << 8) | raw[offset + 1]
        offset += 2

        ext_end = offset + ext_total_len
        while offset + 4 <= ext_end and offset + 4 <= len(raw):
            ext_type = (raw[offset] << 8) | raw[offset + 1]
            ext_len = (raw[offset + 2] << 8) | raw[offset + 3]
            offset += 4
            ext_data_end = offset + ext_len

            if ext_type == 0x0000:  # server_name extension
                # server_name list: length(2) + name_type(1) + name_len(2) + name
                if offset + 2 > ext_data_end:
                    break
                # sni_len 跳过 list 长度
                list_len = (raw[offset] << 8) | raw[offset + 1]
                _ = list_len
                offset += 2
                if offset + 3 > ext_data_end:
                    break
                name_type = raw[offset]  # 0 = host_name
                name_len = (raw[offset + 1] << 8) | raw[offset + 2]
                offset += 3
                if name_type == 0 and offset + name_len <= ext_data_end:
                    record.tls_sni = raw[offset:offset + name_len].decode("ascii", errors="replace")
                    break
            offset = ext_data_end

    except Exception:
        pass  # SNI 解析失败不影响主流程


# ==================== 批量解析 ====================


def parse_packets(packets, max_packets: int = 0) -> List[TrafficRecord]:
    """
    批量解析数据包列表。

    Args:
        packets: scapy 包列表（来自 rdpcap 或 sniff）
        max_packets: 最大解析数，0 表示全部

    Returns:
        TrafficRecord 列表（解析失败的包跳过）
    """
    records = []
    count = 0
    for packet in packets:
        if max_packets > 0 and count >= max_packets:
            break
        record = parse_packet(packet)
        if record is not None:
            records.append(record)
            count += 1
    return records


# ==================== 单元测试辅助工具 ====================


def create_fake_http_record(
    method: str = "GET",
    uri: str = "/index.php?id=1",
    host: str = "example.com",
    body: str = "",
    src_ip: str = "192.168.1.100",
    dst_ip: str = "10.0.0.1",
    src_port: int = 54321,
    dst_port: int = 80,
) -> TrafficRecord:
    """
    创建模拟 HTTP 请求的 TrafficRecord（用于单元测试和模块二/三调试）。

    无需 scapy，纯构造 TrafficRecord 实例。
    """
    headers = f"Host: {host}\r\nUser-Agent: Mozilla/5.0\r\n"
    payload_str = f"{method} {uri} HTTP/1.1\r\n{headers}\r\n{body}"

    record = TrafficRecord()
    record.src = IPEndpoint(ip=src_ip, port=src_port)
    record.dst = IPEndpoint(ip=dst_ip, port=dst_port)
    record.protocol = ProtocolType.TCP

    record.payload = payload_str
    record.payload_raw = payload_str.encode("utf-8")
    record.payload_size = len(payload_str)

    record.http_method = method
    record.http_uri = uri
    record.http_host = host
    record.http_body = body

    record.flow_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-TCP"
    record.flags = 0x18  # PSH + ACK

    return record


def create_fake_dns_record(
    query: str = "evil.c2.com",
    query_type: str = "A",
    src_ip: str = "192.168.1.100",
    dst_ip: str = "8.8.8.8",
) -> TrafficRecord:
    """创建模拟 DNS 查询的 TrafficRecord（用于单元测试）"""
    record = TrafficRecord()
    record.src = IPEndpoint(ip=src_ip, port=54321)
    record.dst = IPEndpoint(ip=dst_ip, port=53)
    record.protocol = ProtocolType.UDP

    record.dns_query = query
    record.dns_query_type = query_type

    # 构造模拟 DNS 载荷
    qname_bytes = b"".join(bytes([len(p)]) + p.encode() for p in query.split(".")) + b"\x00"
    dns_header = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    dns_query = dns_header + qname_bytes + b"\x00\x01\x00\x01"
    record.payload_raw = dns_query
    record.payload = query

    record.flow_id = f"{src_ip}:54321-{dst_ip}:53-UDP"

    return record
