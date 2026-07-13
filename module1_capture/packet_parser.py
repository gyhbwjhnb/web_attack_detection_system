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
        1. 检查是否有 IP 层（无 IP 层的包跳过，如 ARP）
        2. 初始化 TrafficRecord
        3. 逐层解析: Ether → IP → TCP/UDP/ICMP → HTTP/DNS/TLS
        4. 提取载荷
    """
    try:
        # ---- 必须有 IP 层 ----
        if packet.haslayer("IP"):
            ip_layer = packet["IP"]
        elif packet.haslayer("IPv6"):
            ip_layer = packet["IPv6"]
        else:
            # 非 IP 包（ARP、PPPoE 等），跳过
            return None

        record = TrafficRecord()

        # ---- 解析各层 ----
        _parse_ethernet(packet, record)
        _parse_ip(ip_layer, record)
        _parse_transport(packet, record)
        _parse_payload(packet, record)

        # 在检测应用层协议前，记录传输层协议（用于流ID）
        transport_layer_protocol = record.protocol

        _detect_application_protocol(record)

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

    except Exception as e:
        logger.debug(f"传输层解析异常: {e}")


def _parse_payload(packet, record: TrafficRecord):
    """
    提取应用层载荷。

    策略:
      1. TCP: 取 Raw 层（如果有）
      2. UDP: 取 Raw 层
      3. 限制最大载荷长度，防止内存溢出
    """
    MAX_PAYLOAD = 65536  # 64KB 上限

    try:
        if packet.haslayer("Raw"):
            raw = packet["Raw"].load
            if isinstance(raw, (bytes, bytearray)):
                record.payload_raw = raw[:MAX_PAYLOAD]
                # 尝试 UTF-8 解码
                try:
                    record.payload = raw.decode("utf-8", errors="replace")
                except Exception:
                    record.payload = raw.decode("latin-1", errors="replace")
            else:
                record.payload = str(raw)[:MAX_PAYLOAD]
                record.payload_raw = record.payload.encode("utf-8", errors="replace")
    except Exception as e:
        logger.debug(f"载荷提取异常: {e}")


# ==================== 应用层协议检测 ====================


def _detect_application_protocol(record: TrafficRecord):
    """检测应用层协议（HTTP / DNS / TLS / SSH / FTP 等）"""
    if not record.payload:
        return

    payload = record.payload
    payload_upper = payload[:1024].upper()

    # ---- HTTP 检测（基于请求行或响应行） ----
    if _is_http(payload, payload_upper):
        _parse_http(record)
        return

    # ---- DNS 检测 ----
    if record.dst.port == 53 or record.src.port == 53:
        _parse_dns(record)

    # ---- SSH / FTP / SMTP / HTTPS 端口标记 ----
    # （先做端口标记，TLS 内容检测可覆盖为更精确的协议类型）
    if record.dst.port == 22 or record.src.port == 22:
        record.protocol = ProtocolType.SSH
        record.protocol_detail = "SSH"
    elif record.dst.port == 21 or record.src.port == 21:
        record.protocol = ProtocolType.FTP
        record.protocol_detail = "FTP"
    elif record.dst.port == 25 or record.src.port == 25:
        record.protocol = ProtocolType.SMTP
        record.protocol_detail = "SMTP"

    # ---- TLS 检测（基于内容，优先级高于端口标记） ----
    if _detect_tls(record):
        return

    # 端口的 HTTPS 猜测（仅在 TLS 内容检测未命中时使用）
    if record.dst.port == 443 or record.src.port == 443:
        record.protocol = ProtocolType.HTTPS
        record.protocol_detail = "HTTPS/TLS"


# ==================== HTTP 解析 ====================


HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD",
                "OPTIONS", "CONNECT", "TRACE"}


def _is_http(payload: str, payload_upper: str) -> bool:
    """判断是否为 HTTP 协议"""
    # 请求: 以 HTTP 方法开头
    first_line = payload_upper.split("\r\n")[0].split("\n")[0].strip()
    for method in HTTP_METHODS:
        if first_line.startswith(method):
            return True
    # 响应: 以 HTTP/ 开头
    if first_line.startswith("HTTP/"):
        return True
    return False


def _parse_http(record: TrafficRecord):
    """
    解析 HTTP 请求/响应的关键字段。

    请求示例:  GET /index.php?id=1 HTTP/1.1
    响应示例:  HTTP/1.1 200 OK
    """
    record.protocol = ProtocolType.HTTP
    lines = record.payload.split("\r\n")
    if not lines:
        lines = record.payload.split("\n")

    if not lines:
        return

    # ---- 解析请求行或响应行 ----
    first_line = lines[0].strip()

    # 尝试匹配: METHOD URI HTTP/version
    parts = first_line.split(" ")
    if len(parts) >= 2 and parts[0] in HTTP_METHODS:
        record.http_method = parts[0]
        record.http_uri = unquote(parts[1]) if len(parts) > 1 else ""
        if len(parts) >= 3:
            record.protocol_detail = parts[2]
    elif first_line.startswith("HTTP/"):
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
    """浅解析 DNS 协议，提取查询域名"""
    record.protocol = ProtocolType.DNS
    try:
        # 从原始字节中提取 DNS 查询名
        raw = record.payload_raw
        if len(raw) < 12:
            return

        # DNS header: ID(2) + flags(2) + qdcount(2) + ancount(2) + nscount(2) + arcount(2)
        qdcount = (raw[4] << 8) | raw[5]
        if qdcount == 0:
            return

        # 跳过 DNS 头部（12 字节）解析查询
        offset = 12
        domain_parts = []
        while offset < len(raw):
            length = raw[offset]
            if length == 0:
                offset += 1
                break
            if length & 0xC0:  # 压缩指针
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

        # DNS 查询类型
        if offset + 2 <= len(raw):
            qtype = (raw[offset] << 8) | raw[offset + 1]
            type_map = {1: "A", 28: "AAAA", 15: "MX", 16: "TXT",
                        5: "CNAME", 2: "NS", 255: "ANY"}
            record.dns_query_type = type_map.get(qtype, f"TYPE{qtype}")

    except Exception as e:
        logger.debug(f"DNS 解析异常: {e}")


# ==================== TLS 检测 ====================


def _detect_tls(record: TrafficRecord) -> bool:
    """
    检测 TLS ClientHello / ServerHello 握手。

    Returns:
        True 如果检测到 TLS 内容
    """
    raw = record.payload_raw
    if len(raw) < 5:
        return False

    # TLS 记录层: ContentType(1) + Version(2) + Length(2)
    content_type = raw[0]
    if content_type in (0x16, 0x17):  # 22=Handshake, 23=Application Data
        record.protocol = ProtocolType.TLS
        # TLS 版本
        if len(raw) >= 3:
            ver_map = {
                (0x03, 0x01): "TLS 1.0",
                (0x03, 0x02): "TLS 1.1",
                (0x03, 0x03): "TLS 1.2",
                (0x03, 0x04): "TLS 1.3",
            }
            ver = (raw[1], raw[2])
            record.tls_version = ver_map.get(ver, f"TLS 0x{raw[1]:02x}{raw[2]:02x}")
            record.protocol_detail = record.tls_version
        return True

    return False


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
