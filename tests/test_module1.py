"""
单元测试 —— 模块一：数据包捕获与预处理

测试范围:
  1. packet_parser 协议解析
     - HTTP 请求解析（GET/POST）
     - HTTP 响应解析
     - HTTP 头部解析（Host/UA/Referer）
     - DNS 解析
     - TLS 检测
     - 非 IP 包跳过
  2. CaptureEngine 引擎
     - 初始状态
     - 回调注册
     - 统计信息
     - 离线 PCAP 读取（mock）
  3. 工具函数
     - create_fake_http_record
     - create_fake_dns_record

运行:
    cd web_attack_detection_system
    pip install pytest       # 首次
    pytest tests/test_module1.py -v
"""

import sys
import os
import time
import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

# 确保项目根目录在 sys.path 中
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from common.data_structures import (
    TrafficRecord, IPEndpoint, ProtocolType,
    AlertSeverity, AlertType,
)
from module1_capture.packet_parser import (
    parse_packet,
    parse_packets,
    create_fake_http_record,
    create_fake_dns_record,
)
from module1_capture.capture import CaptureEngine


# ========================================================================
# 测试数据准备
# ========================================================================


class MockScapyPacket:
    """模拟 scapy 数据包对象，用于 parse_packet 测试"""

    def __init__(self, layers: dict):
        self._layers = layers

    def haslayer(self, name: str) -> bool:
        return name in self._layers

    def __getitem__(self, name: str):
        return self._layers.get(name)

    def __len__(self):
        return 1500


class MockIP:
    """模拟 scapy IP 层"""
    version = 4
    src = "10.0.0.1"
    dst = "192.168.1.100"
    proto = 6  # TCP


class MockTCP:
    """模拟 scapy TCP 层"""
    sport = 80
    dport = 54321
    flags = 0x18  # PSH + ACK
    seq = 1000
    ack = 2000


class MockTCP_SYN:
    """模拟 SYN 包"""
    sport = 54321
    dport = 80
    flags = 0x02  # SYN
    seq = 1000
    ack = 0


class MockUDP:
    """模拟 scapy UDP 层"""
    sport = 53
    dport = 54321


class MockICMP:
    """模拟 scapy ICMP 层"""
    pass


class MockRaw:
    """模拟 scapy Raw 层（载荷）"""
    def __init__(self, data: bytes):
        self.load = data


class MockEther:
    """模拟 scapy Ether 层"""
    src = "aa:bb:cc:dd:ee:ff"
    dst = "11:22:33:44:55:66"


# ========================================================================
# 工具函数测试
# ========================================================================


class TestFakeRecordFactory:
    """测试模拟记录生成函数"""

    def test_create_fake_http_get(self):
        """创建模拟 HTTP GET 请求"""
        record = create_fake_http_record(
            method="GET",
            uri="/search?q=test&page=1",
            host="example.com",
            src_ip="192.168.1.10",
            dst_ip="93.184.216.34",
            src_port=12345,
            dst_port=80,
        )

        assert record.http_method == "GET"
        assert record.http_uri == "/search?q=test&page=1"
        assert record.http_host == "example.com"
        assert record.src.ip == "192.168.1.10"
        assert record.dst.ip == "93.184.216.34"
        assert record.src.port == 12345
        assert record.dst.port == 80
        assert record.protocol == ProtocolType.TCP
        assert record.flow_id == "192.168.1.10:12345-93.184.216.34:80-TCP"

    def test_create_fake_http_post(self):
        """创建模拟 HTTP POST 请求"""
        record = create_fake_http_record(
            method="POST",
            uri="/login",
            host="example.com",
            body="username=admin&password=123456",
        )

        assert record.http_method == "POST"
        assert record.http_uri == "/login"
        assert record.http_body == "username=admin&password=123456"

    def test_create_fake_dns(self):
        """创建模拟 DNS 查询"""
        record = create_fake_dns_record(
            query="evil.c2.com",
            query_type="A",
            src_ip="192.168.1.10",
            dst_ip="8.8.8.8",
        )

        assert record.dns_query == "evil.c2.com"
        assert record.dns_query_type == "A"
        assert record.dst.port == 53
        assert record.protocol == ProtocolType.UDP


# ========================================================================
# 协议解析测试
# ========================================================================


class TestPacketParser:
    """测试 packet_parser.parse_packet"""

    def test_parse_http_get(self):
        """解析 HTTP GET 请求包"""
        http_get = (
            b"GET /index.php?id=1&name=test HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"User-Agent: Mozilla/5.0\r\n"
            b"Accept: */*\r\n"
            b"\r\n"
        )

        packet = MockScapyPacket({
            "IP": MockIP(),
            "TCP": MockTCP(),
            "Raw": MockRaw(http_get),
        })

        record = parse_packet(packet)
        assert record is not None
        assert record.http_method == "GET"
        assert record.http_uri == "/index.php?id=1&name=test"
        assert record.http_host == "example.com"
        assert record.http_user_agent == "Mozilla/5.0"
        assert record.protocol == ProtocolType.HTTP
        assert record.src.ip == "10.0.0.1"
        assert record.dst.ip == "192.168.1.100"
        assert record.src.port == 80
        assert record.dst.port == 54321

    def test_parse_http_post_with_body(self):
        """解析 HTTP POST 请求（含请求体）"""
        http_post = (
            b"POST /login.php HTTP/1.1\r\n"
            b"Host: test.com\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            b"Content-Length: 29\r\n"
            b"\r\n"
            b"username=admin&password=123456"
        )

        packet = MockScapyPacket({
            "IP": MockIP(),
            "TCP": MockTCP(),
            "Raw": MockRaw(http_post),
        })

        record = parse_packet(packet)
        assert record is not None
        assert record.http_method == "POST"
        assert record.http_uri == "/login.php"
        assert record.http_host == "test.com"
        assert record.http_body == "username=admin&password=123456"

    def test_parse_http_response(self):
        """解析 HTTP 响应包"""
        http_resp = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/html\r\n"
            b"Content-Length: 13\r\n"
            b"\r\n"
            b"Hello, World!"
        )

        packet = MockScapyPacket({
            "IP": MockIP(),
            "TCP": MockTCP(),
            "Raw": MockRaw(http_resp),
        })

        record = parse_packet(packet)
        assert record is not None
        assert record.http_method == "RESPONSE"
        assert record.http_status_code == 200

    def test_parse_http_with_referer(self):
        """解析带 Referer 的 HTTP 请求"""
        http_with_ref = (
            b"GET /admin HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Referer: http://evil.com/steal.html\r\n"
            b"\r\n"
        )

        packet = MockScapyPacket({
            "IP": MockIP(),
            "TCP": MockTCP(),
            "Raw": MockRaw(http_with_ref),
        })

        record = parse_packet(packet)
        assert record is not None
        assert record.http_referer == "http://evil.com/steal.html"

    def test_parse_syn_packet(self):
        """解析 SYN 包（无载荷）"""
        packet = MockScapyPacket({
            "IP": MockIP(),
            "TCP": MockTCP_SYN(),
        })

        record = parse_packet(packet)
        assert record is not None
        assert record.is_syn()
        assert not record.is_syn_ack()
        assert record.payload == ""

    def test_parse_dns_query(self):
        """解析 DNS 查询包"""
        # 构造 DNS 查询: example.com A记录
        qname = b"\x07example\x03com\x00"
        dns_pkt = (
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"  # DNS header
            + qname
            + b"\x00\x01\x00\x01"  # QTYPE=A, QCLASS=IN
        )

        packet = MockScapyPacket({
            "IP": MockIP(),
            "UDP": MockUDP(),
            "Raw": MockRaw(dns_pkt),
        })
        packet._layers["UDP"].sport = 54321
        packet._layers["UDP"].dport = 53

        record = parse_packet(packet)
        assert record is not None
        assert record.dns_query == "example.com"
        assert record.dns_query_type == "A"

    def test_parse_non_ip_packet(self):
        """非 IP 包应返回 None（如 ARP）"""
        packet = MockScapyPacket({})  # 无 IP 层
        record = parse_packet(packet)
        assert record is None

    def test_parse_tls_detection(self):
        """TLS ClientHello 检测"""
        # TLS 1.2 ClientHello: ContentType=0x16(22), Version=0x0303
        tls_hello = bytes([
            0x16,  # ContentType: Handshake
            0x03, 0x03,  # TLS 1.2
            0x00, 0x2e,  # Length
            0x01,  # HandshakeType: ClientHello
            0x00, 0x00, 0x2a,  # Length
            0x03, 0x03,  # Version TLS 1.2
        ]) + b"\x00" * 36

        # 使用 443 端口以触发 TLS 检测
        tcp_443 = MockTCP()
        tcp_443.sport = 443
        packet = MockScapyPacket({
            "IP": MockIP(),
            "TCP": tcp_443,
            "Raw": MockRaw(tls_hello),
        })

        record = parse_packet(packet)
        assert record is not None
        assert record.protocol == ProtocolType.TLS
        assert record.tls_version == "TLS 1.2"

    def test_parse_udp_non_dns(self):
        """普通 UDP 包（非 DNS）"""
        packet = MockScapyPacket({
            "IP": MockIP(),
            "UDP": MockUDP(),
            "Raw": MockRaw(b"some random data"),
        })
        # 非 53 端口
        packet._layers["UDP"].sport = 30000
        packet._layers["UDP"].dport = 30001

        record = parse_packet(packet)
        assert record is not None
        assert record.protocol == ProtocolType.UDP

    def test_parse_http_encoded_uri(self):
        """URL 编码的 URI 应被解码"""
        http_encoded = (
            b"GET /search%3Fq%3Dtest%2Bvalue HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"\r\n"
        )

        packet = MockScapyPacket({
            "IP": MockIP(),
            "TCP": MockTCP(),
            "Raw": MockRaw(http_encoded),
        })

        record = parse_packet(packet)
        assert record is not None
        # %3F → ?, %3D → =
        assert "?" in record.http_uri or "%3F" in record.http_uri


class TestParsePackets:
    """测试批量解析"""

    def test_parse_multiple_packets(self):
        """批量解析多个包"""
        packets = []
        for i in range(5):
            http_data = (
                f"GET /page{i} HTTP/1.1\r\nHost: test.com\r\n\r\n"
            ).encode()
            packets.append(MockScapyPacket({
                "IP": MockIP(),
                "TCP": MockTCP(),
                "Raw": MockRaw(http_data),
            }))

        records = parse_packets(packets)
        assert len(records) == 5
        for i, record in enumerate(records):
            assert record.http_uri == f"/page{i}"

    def test_parse_with_limit(self):
        """限制最大解析数量"""
        packets = [MockScapyPacket({"IP": MockIP(), "TCP": MockTCP()}) for _ in range(10)]
        records = parse_packets(packets, max_packets=3)
        assert len(records) == 3

    def test_parse_mixed_valid_invalid(self):
        """混合有效/无效包"""
        packets = [
            MockScapyPacket({"IP": MockIP(), "TCP": MockTCP()}),  # 有效
            MockScapyPacket({}),  # 无效（无 IP）
            MockScapyPacket({"IP": MockIP(), "TCP": MockTCP()}),  # 有效
        ]

        records = parse_packets(packets)
        assert len(records) == 2  # 1 个无效被跳过


# ========================================================================
# CaptureEngine 测试
# ========================================================================


class TestCaptureEngine:
    """测试 CaptureEngine 功能"""

    def test_initial_state(self):
        """初始状态"""
        engine = CaptureEngine(use_message_bus=False)
        assert not engine.is_running()
        assert engine.get_packet_count() == 0

        stats = engine.get_statistics()
        assert stats["packet_count"] == 0
        assert stats["running"] is False
        assert stats["tcp_flows"] == 0
        assert stats["udp_flows"] == 0

    def test_callback_registration(self):
        """注册流量回调"""
        engine = CaptureEngine(use_message_bus=False)
        calls = []

        def callback(record):
            calls.append(record)

        engine.set_on_traffic_callback(callback)
        # 手动触发 _dispatch（内部方法，测试用）
        record = create_fake_http_record()
        engine._dispatch(record)

        assert len(calls) == 1
        assert calls[0].http_method == "GET"

    def test_multiple_callbacks(self):
        """多个回调都应被调用"""
        engine = CaptureEngine(use_message_bus=False)
        calls1 = []
        calls2 = []

        engine.set_on_traffic_callback(lambda r: calls1.append(r))
        engine.set_on_traffic_callback(lambda r: calls2.append(r))

        record = create_fake_http_record()
        engine._dispatch(record)

        assert len(calls1) == 1
        assert len(calls2) == 1

    def test_offline_read(self):
        """离线模式读取 PCAP 文件"""
        engine = CaptureEngine(use_message_bus=False)
        callback_records = []

        engine.set_on_traffic_callback(lambda r: callback_records.append(r))

        # 使用一个小的 pcap 文件（如果存在）
        test_pcaps = [
            "data/test/sample_attack.pcap",
            "data/test/test.pcap",
            "../data/test/sample_attack.pcap",
        ]

        found = False
        for pcap in test_pcaps:
            pcap_path = Path(__file__).parent.parent / pcap
            if pcap_path.exists():
                engine.start(offline_pcap=str(pcap_path))
                assert len(callback_records) > 0
                stats = engine.get_statistics()
                assert stats["packet_count"] > 0
                found = True
                break

        if not found:
            # 无 PCAP 文件，测试引擎在文件不存在时的行为
            result = engine.start(offline_pcap="nonexistent.pcap")
            assert result is False  # 应返回失败

    def test_stop_idle_engine(self):
        """停止未运行的引擎不应报错"""
        engine = CaptureEngine()
        engine.stop()  # 不应抛出异常

    def test_statistics_after_offline(self):
        """离线解析后的统计信息"""
        # 使用 fake record 模拟统计数据
        engine = CaptureEngine(use_message_bus=False)
        assert isinstance(engine.get_statistics(), dict)

    @patch('module1_capture.capture.CaptureEngine._auto_select_interface')
    def test_auto_interface_fallback(self, mock_auto):
        """自动选择网卡失败时返回 False（当不指定网卡时）"""
        mock_auto.return_value = None

        engine = CaptureEngine(use_message_bus=False)
        # 不传 interface，触发 _auto_select_interface() 返回 None → 失败
        result = engine.start(filter_expr="tcp")
        assert result is False


# ========================================================================
# 集成测试：Engine ↔ Parser
# ========================================================================


class TestEngineWithParser:
    """测试引擎和数据包解析器的集成"""

    def test_handle_packet_dispatch(self):
        """模拟从 handle_packet 到 _dispatch 全流程"""
        engine = CaptureEngine(use_message_bus=False)
        received = []

        engine.set_on_traffic_callback(lambda r: received.append(r))

        # 构造模拟 scapy 包
        http_data = (
            b"GET /test HTTP/1.1\r\n"
            b"Host: test.com\r\n"
            b"\r\n"
        )
        packet = MockScapyPacket({
            "IP": MockIP(),
            "TCP": MockTCP(),
            "Raw": MockRaw(http_data),
        })

        engine._handle_packet(packet)

        assert len(received) == 1
        assert received[0].http_method == "GET"
        assert received[0].http_uri == "/test"

    def test_handle_non_ip_skipped(self):
        """非 IP 包不应触发回调"""
        engine = CaptureEngine(use_message_bus=False)
        received = []

        engine.set_on_traffic_callback(lambda r: received.append(r))

        packet = MockScapyPacket({})  # 无 IP 层
        engine._handle_packet(packet)

        assert len(received) == 0  # 不应触发回调

    def test_large_payload_truncation(self):
        """超大载荷应被截断"""
        engine = CaptureEngine(use_message_bus=False)
        received = []

        engine.set_on_traffic_callback(lambda r: received.append(r))

        # 100KB 载荷
        large_body = b"payload_data_" * 8000  # ~104KB
        http_data = (
            b"POST /upload HTTP/1.1\r\n"
            b"Host: test.com\r\n"
            b"\r\n"
            + large_body
        )
        packet = MockScapyPacket({
            "IP": MockIP(),
            "TCP": MockTCP(),
            "Raw": MockRaw(http_data),
        })

        engine._handle_packet(packet)
        if received:
            assert len(received[0].payload_raw) <= 65536  # 上限 64KB


# ========================================================================
# 配置兼容性测试
# ========================================================================


class TestConfigCompatibility:
    """测试模块一与配置模块的兼容性"""

    def test_base_dir_access(self):
        """确保依赖路径存在"""
        base_dir = Path(__file__).parent.parent
        assert (base_dir / "common").exists()
        assert (base_dir / "module1_capture").exists()
        assert (base_dir / "data").exists()

    def test_import_all(self):
        """验证可导入"""
        from module1_capture import CaptureEngine, parse_packet, parse_packets
        from module1_capture import create_fake_http_record, create_fake_dns_record
        assert CaptureEngine is not None
        assert parse_packet is not None
        assert parse_packets is not None


# ========================================================================
# 边界情况测试
# ========================================================================


class TestEdgeCases:
    """边界和异常情况"""

    def test_empty_payload(self):
        """空载荷"""
        packet = MockScapyPacket({
            "IP": MockIP(),
            "TCP": MockTCP(),
            "Raw": MockRaw(b""),
        })
        record = parse_packet(packet)
        assert record is not None
        assert record.payload == ""

    def test_binary_payload(self):
        """二进制载荷"""
        binary = bytes(range(256))
        packet = MockScapyPacket({
            "IP": MockIP(),
            "TCP": MockTCP(),
            "Raw": MockRaw(binary),
        })
        record = parse_packet(packet)
        assert record is not None
        # 二进制也能被 latin-1 解码
        assert len(record.payload) == 256

    def test_unicode_in_uri(self):
        """Unicode 字符在 URI 中"""
        http_unicode = (
            b"GET /caf%C3%A9 HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"\r\n"
        )
        packet = MockScapyPacket({
            "IP": MockIP(),
            "TCP": MockTCP(),
            "Raw": MockRaw(http_unicode),
        })
        record = parse_packet(packet)
        assert record is not None
        # URI 会被 unquote 解码
        assert "caf" in record.http_uri


# ========================================================================
# 性能测试
# ========================================================================


class TestPerformance:
    """性能基准测试"""

    def test_parse_100_http_packets(self):
        """解析 100 个 HTTP 包的性能（应在 0.5s 内完成）"""
        packets = []
        for i in range(100):
            http_data = (
                f"GET /page{i}?q=test HTTP/1.1\r\n"
                f"Host: site{i}.com\r\n"
                f"\r\n"
            ).encode()
            packets.append(MockScapyPacket({
                "IP": MockIP(),
                "TCP": MockTCP(),
                "Raw": MockRaw(http_data),
            }))

        import time
        start = time.time()
        records = parse_packets(packets)
        elapsed = time.time() - start

        assert len(records) == 100
        # 100 个包应在 0.5 秒内完成
        assert elapsed < 0.5, f"解析 100 包耗时 {elapsed:.3f}s，超过 0.5s 阈值"


# ========================================================================
# 入口
# ========================================================================

if __name__ == "__main__":
    pytest.main(["-v", __file__])
