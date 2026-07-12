"""
模块一：数据包捕获与预处理

提供网卡实时抓包和 PCAP 文件离线读取能力，
并将原始数据包解析为统一的 TrafficRecord 结构。

核心组件:
    CaptureEngine     — 抓包引擎（实现 ICaptureEngine 接口）
    parse_packet      — 单包解析函数
    parse_packets     — 批量解析函数
    create_fake_http_record — 模拟 HTTP 流量（测试/调试用）
    create_fake_dns_record  — 模拟 DNS 流量（测试/调试用）

用法:
    # 方式1: 通过 MessageBus 自动发布流量
    from module1_capture import CaptureEngine

    engine = CaptureEngine(use_message_bus=True)
    engine.start(interface="eth0", filter_expr="tcp port 80")

    # 方式2: 离线分析 PCAP 文件
    engine = CaptureEngine()
    engine.start(offline_pcap="data/test/sample.pcap")

    # 方式3: 直接解析单个数据包
    from module1_capture import parse_packet
    record = parse_packet(scapy_packet)
"""

from module1_capture.capture import CaptureEngine
from module1_capture.packet_parser import (
    parse_packet,
    parse_packets,
    create_fake_http_record,
    create_fake_dns_record,
)

__all__ = [
    "CaptureEngine",
    "parse_packet",
    "parse_packets",
    "create_fake_http_record",
    "create_fake_dns_record",
]
