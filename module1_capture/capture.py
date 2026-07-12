"""
============================================================================
数据包捕获引擎 —— 模块一核心
============================================================================

职责:
  1. 从物理网卡实时抓包（scapy.sniff）
  2. 从离线 PCAP 文件读取数据包（scapy.rdpcap）
  3. 支持 BPF 过滤表达式
  4. 将捕获的包通过 packet_parser 解析为 TrafficRecord
  5. 通过回调函数 / MessageBus 发布流量记录

两种工作模式:
  - 在线模式 (live):  从网卡实时抓包，需 Npcap（Windows）或 LibPcap（Linux）
  - 离线模式 (offline): 从 PCAP 文件读取，无需管理员权限

用法:
    # 方式1: 通过回调接收流量
    engine = CaptureEngine()
    engine.set_on_traffic_callback(lambda record: print(record))
    engine.start(interface="eth0", filter_expr="tcp port 80")

    # 方式2: 离线分析
    engine = CaptureEngine()
    engine.start(offline_pcap="data/test/sample.pcap")
    # 所有记录会通过回调输出

    # 方式3: 通过 MessageBus 发布
    # 在 main.py 中:
    from common.message_bus import message_bus
    engine.set_on_traffic_callback(
        lambda record: message_bus.publish("traffic_record", record)
    )

    停止:
    engine.stop()
============================================================================
"""

import time
import logging
import threading
from pathlib import Path
from typing import Callable, Optional, List

from common.data_structures import TrafficRecord
from common.engine import ICaptureEngine
from common.message_bus import message_bus

from module1_capture.packet_parser import parse_packet

logger = logging.getLogger("CaptureEngine")


class CaptureEngine(ICaptureEngine):
    """
    数据包捕获引擎 —— 实现 ICaptureEngine 接口。

    支持两种数据源：
      1. 实时抓包（scapy.sniff）
      2. PCAP 文件离线读取（scapy.rdpcap）

    线程安全：抓包在独立线程运行，不阻塞主流程。
    """

    def __init__(self, use_message_bus: bool = True):
        """
        初始化捕获引擎。

        Args:
            use_message_bus: 是否自动通过 MessageBus 发布流量记录
                             （为 True 则无需再调 set_on_traffic_callback，
                               但两种方式不冲突，都会触发）
        """
        self._running = False
        self._sniff_thread: Optional[threading.Thread] = None
        self._stop_sniff = threading.Event()

        # ---- 统计 ----
        self._packet_count = 0
        self._byte_total = 0
        self._start_time = 0.0
        self._protocol_count = {}
        self._tcp_flows = set()
        self._udp_flows = set()
        self._error_count = 0

        # ---- 回调 ----
        self._on_traffic_callbacks: List[Callable[[TrafficRecord], None]] = []
        self._use_message_bus = use_message_bus

    # ==================== ICaptureEngine 接口实现 ====================

    def start(
        self,
        interface: Optional[str] = None,
        filter_expr: str = "",
        offline_pcap: Optional[str] = None,
        packet_count: int = 0,
        promiscuous: bool = True,
        timeout_ms: int = 1000,
    ) -> bool:
        """
        启动数据包捕获。

        Args:
            interface:    网卡名称（如 "eth0", "Wi-Fi"），None 自动选择
            filter_expr:  BPF 过滤表达式，如 "tcp port 80"
            offline_pcap: PCAP 文件路径，非 None 时开启离线模式
            packet_count: 捕获包数，0 表示持续捕获
            promiscuous:  是否启用混杂模式
            timeout_ms:   超时(毫秒)

        Returns:
            True 启动成功，False 失败
        """
        if self._running:
            logger.warning("捕获引擎已在运行中")
            return False

        # 更新配置
        if offline_pcap:
            pcap_path = Path(offline_pcap)
            if not pcap_path.exists():
                logger.error(f"PCAP 文件不存在: {offline_pcap}")
                return False
            logger.info(f"离线模式: {offline_pcap}")
            self._start_offline(str(pcap_path), packet_count)
            return True

        # 在线模式：需要 scapy
        try:
            from scapy.config import conf
            from scapy.all import sniff
        except ImportError:
            logger.error("scapy 未安装，无法在线抓包。pip install scapy")
            return False

        self._running = True
        self._stop_sniff.clear()
        self._start_time = time.time()
        self._packet_count = 0

        # 确定网卡
        if not interface:
            interface = self._auto_select_interface()
            if not interface:
                logger.error("未找到可用网卡")
                self._running = False
                return False

        logger.info(
            f"启动抓包: interface={interface}, filter={filter_expr or '(无)'}, "
            f"promisc={promiscuous}"
        )

        # 在独立线程中运行 sniff（sniff 是阻塞的）
        self._sniff_thread = threading.Thread(
            target=self._sniff_worker,
            args=(interface, filter_expr, packet_count, promiscuous, timeout_ms),
            daemon=True,
            name="CaptureEngine-sniff",
        )
        self._sniff_thread.start()
        return True

    def stop(self):
        """停止数据包捕获，清理资源"""
        if not self._running:
            return

        logger.info("正在停止捕获引擎...")
        self._stop_sniff.set()
        self._running = False

        # 等待抓包线程结束（最多等 3 秒）
        if self._sniff_thread and self._sniff_thread.is_alive():
            self._sniff_thread.join(timeout=3.0)

        duration = time.time() - self._start_time
        logger.info(
            f"捕获已停止: 共 {self._packet_count} 包, "
            f"耗时 {duration:.1f}s, "
            f"错误 {self._error_count} 个"
        )

    def set_on_traffic_callback(self, callback: Callable[[TrafficRecord], None]):
        """
        注册流量记录回调函数。
        每解析完一条流量，调用 callback(record)。

        可注册多个回调，按注册顺序依次调用。
        """
        if callback not in self._on_traffic_callbacks:
            self._on_traffic_callbacks.append(callback)

    def get_statistics(self) -> dict:
        """获取捕获统计信息"""
        return {
            "packet_count": self._packet_count,
            "bytes_total": self._byte_total,
            "tcp_flows": len(self._tcp_flows),
            "udp_flows": len(self._udp_flows),
            "protocols": dict(self._protocol_count),
            "start_time": self._start_time,
            "running": self._running,
            "errors": self._error_count,
        }

    # ==================== 内部方法 ====================

    def _sniff_worker(
        self,
        interface: str,
        filter_expr: str,
        packet_count: int,
        promiscuous: bool,
        timeout_ms: int,
    ):
        """抓包工作线程"""
        try:
            from scapy.all import sniff

            sniff(
                iface=interface,
                filter=filter_expr or None,
                prn=self._handle_packet,
                store=False,
                count=packet_count if packet_count > 0 else 0,
                promisc=promiscuous,
                timeout=None if packet_count == 0 else 10,
                stop_filter=lambda p: self._stop_sniff.is_set(),
            )
        except PermissionError:
            logger.error(
                "权限不足！请以管理员身份运行（Windows）或使用 sudo（Linux）"
            )
        except Exception as e:
            logger.error(f"抓包异常: {e}", exc_info=True)
        finally:
            self._running = False

    def _handle_packet(self, packet):
        """回调: 处理每个捕获的数据包"""
        if self._stop_sniff.is_set():
            # 返回 None 让 sniff 停止（需要 stop_filter 配合）
            return

        try:
            # 解析包
            record = parse_packet(packet)
            if record is None:
                return  # 非 IP 包跳过

            # ---- 更新统计 ----
            self._packet_count += 1
            self._byte_total += len(packet) if hasattr(packet, "__len__") else 0

            proto = record.protocol.value
            self._protocol_count[proto] = self._protocol_count.get(proto, 0) + 1

            if record.protocol.value == "TCP" and record.flow_id:
                self._tcp_flows.add(record.flow_id)
            elif record.protocol.value == "UDP" and record.flow_id:
                self._udp_flows.add(record.flow_id)

            # ---- 分发 ----
            self._dispatch(record)

        except Exception as e:
            self._error_count += 1
            logger.debug(f"处理数据包异常: {e}")

    def _dispatch(self, record: TrafficRecord):
        """将 TrafficRecord 分发给所有注册的回调和 MessageBus"""
        for callback in self._on_traffic_callbacks:
            try:
                callback(record)
            except Exception as e:
                logger.error(f"流量回调异常: {e}")

        if self._use_message_bus:
            try:
                message_bus.publish(message_bus.EVENT_TRAFFIC_RECORD, record)
            except Exception as e:
                logger.error(f"消息总线发布异常: {e}")

    def _start_offline(self, pcap_path: str, max_packets: int = 0):
        """
        离线模式：从 PCAP 文件读取所有数据包。

        这是一个同步操作，所有包解析完后自动停止。
        """
        try:
            from scapy.utils import rdpcap
        except ImportError:
            logger.error("scapy 未安装，无法读取 PCAP 文件。pip install scapy")
            return

        logger.info(f"正在读取 PCAP 文件: {pcap_path}")
        self._start_time = time.time()
        self._running = True

        try:
            packets = rdpcap(pcap_path)
            logger.info(f"PCAP 文件共 {len(packets)} 个数据包")

            count = 0
            for packet in packets:
                if max_packets > 0 and count >= max_packets:
                    break
                self._handle_packet(packet)
                count += 1

            duration = time.time() - self._start_time
            logger.info(
                f"离线解析完成: {count} 包, "
                f"耗时 {duration:.2f}s, "
                f"速率 {count / max(duration, 0.001):.0f} pps"
            )

        except Exception as e:
            logger.error(f"读取 PCAP 文件失败: {e}", exc_info=True)
        finally:
            self._running = False

    def _auto_select_interface(self) -> Optional[str]:
        """自动选择可用网卡，优先物理网卡

        选择策略（优先级降序）：
          1. 物理有线网卡（Ethernet / 以太网）且有有效 IP
          2. 物理无线网卡（Wi-Fi / WLAN）且有有效 IP
          3. 其他非虚拟、非回环网卡且有有效 IP
          4. 任意有 IP 的网卡（含虚拟适配器，降级选择）
          5. 任意非回环网卡（无 IP 兜底）

        自动过滤的虚拟适配器：
          VMware / VirtualBox / Hyper-V / Docker / WSL /
          Npcap Loopback / Bluetooth 等
        """
        try:
            from scapy.all import get_working_ifaces

            ifaces = get_working_ifaces()
            if not ifaces:
                # 兜底：尝试 scapy IFACES 全局列表
                try:
                    from scapy.all import IFACES
                    ifaces = IFACES
                except (ImportError, AttributeError):
                    pass

            if not ifaces:
                logger.error("未发现可用网卡（get_working_ifaces 返回空）")
                logger.info("请检查：① Npcap(Windows) / LibPcap(Linux) 是否安装；"
                            "② 是否有管理员权限；③ 网卡是否启用")
                return None

            # ── 虚拟/回环网卡关键词 ──
            virtual_keywords = [
                'virtual', 'vmware', 'vbox', 'virtualbox',
                'hyper-v', 'hyperv', 'docker', 'wsl',
                'npcap loopback', 'loopback adapter',
                'bluetooth', 'vmxnet', 'pbl', 'nfl',
            ]

            def _iface_text(iface) -> str:
                """提取接口所有可读文本用于关键词匹配"""
                parts = [
                    iface.name if hasattr(iface, 'name') else str(iface),
                    iface.description if hasattr(iface, 'description') else '',
                    iface.win_name if hasattr(iface, 'win_name') else '',
                ]
                return ' '.join(parts).lower()

            def _iface_ip(iface) -> str:
                return iface.ip if hasattr(iface, 'ip') else ''

            def _iface_name(iface) -> str:
                return iface.name if hasattr(iface, 'name') else str(iface)

            def _iface_desc(iface) -> str:
                return iface.description if hasattr(iface, 'description') else _iface_name(iface)

            # ── 分级 ──
            buckets = {0: [], 1: [], 2: [], 3: [], 4: []}
            # 0=有线 1=无线 2=其他物理 3=虚拟(有IP) 4=无IP/回环

            for iface in ifaces:
                name = _iface_name(iface)
                ip = _iface_ip(iface)
                text = _iface_text(iface)

                is_loopback = (ip == '127.0.0.1' or name in ('lo', 'loopback'))
                is_virtual = any(k in text for k in virtual_keywords)
                has_valid_ip = bool(ip) and ip != '0.0.0.0' and not ip.startswith('169.254.')
                has_any_ip = bool(ip) and ip != '0.0.0.0'

                if is_loopback:
                    buckets[4].append(iface)
                elif has_valid_ip and not is_virtual:
                    if 'ethernet' in text or '以太网' in text:
                        buckets[0].append(iface)       # 有线
                    elif 'wi-fi' in text or 'wlan' in text or '无线' in text:
                        buckets[1].append(iface)       # 无线
                    else:
                        buckets[2].append(iface)       # 其他物理
                elif has_any_ip and is_virtual:
                    buckets[3].append(iface)           # 虚拟但有 IP
                else:
                    buckets[4].append(iface)           # 无 IP 或回环

            # ── 按桶优选取第一个 ──
            for level in range(4):  # 0→1→2→3
                if buckets[level]:
                    iface = buckets[level][0]
                    name = _iface_name(iface)
                    ip = _iface_ip(iface) or '(无 IP)'
                    desc = _iface_desc(iface)
                    labels = ['物理有线', '物理无线', '物理网卡', '虚拟网卡(降级)']
                    logger.info(f"自动选择网卡[{labels[level]}]: {name} — {desc} ({ip})")
                    return name

            # ── 彻底兜底：第一个非空桶 ──
            for level in [4, 3, 2, 1, 0]:
                if buckets[level]:
                    iface = buckets[level][0]
                    name = _iface_name(iface)
                    ip = _iface_ip(iface) or '(无 IP)'
                    desc = _iface_desc(iface)
                    logger.warning(f"自动选择网卡(兜底): {name} — {desc} ({ip})")
                    return name

            # ── 全部失败：列出可用接口帮助用户 ──
            logger.error("未找到可用网卡。可用接口列表：")
            for iface in ifaces:
                n = _iface_name(iface)
                ip = _iface_ip(iface) or '(空)'
                d = _iface_desc(iface)
                logger.error(f"  {n:30s}  IP={ip:15s}  {d}")
            return None

        except Exception as e:
            logger.error(f"自动选择网卡异常: {e}", exc_info=True)
            return None

    # ==================== 便捷方法 ====================

    def read_pcap(
        self,
        pcap_path: str,
        callback: Optional[Callable[[TrafficRecord], None]] = None,
        max_packets: int = 0,
    ) -> List[TrafficRecord]:
        """
        从 PCAP 文件读取数据包（同步方式，不启动抓包线程）。

        Args:
            pcap_path:   PCAP 文件路径
            callback:    可选，每个包解析后调用
            max_packets: 最大解析包数，0=全部

        Returns:
            解析后的 TrafficRecord 列表

        Usage:
            engine = CaptureEngine()
            records = engine.read_pcap("sample.pcap", max_packets=100)
            print(f"解析了 {len(records)} 条记录")
        """
        if callback:
            self.set_on_traffic_callback(callback)

        self._start_offline(pcap_path, max_packets)
        return []

    def get_packet_count(self) -> int:
        """获取当前已捕获的数据包数量"""
        return self._packet_count

    def is_running(self) -> bool:
        """捕获引擎是否正在运行"""
        return self._running
