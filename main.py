"""
网络攻击检测系统 —— 集成入口。

用法:
    python main.py                              # GUI 模式
    python main.py --auto                       # 自动选网卡 + 自动启动
    python main.py --pcap sample.pcap           # 离线 PCAP
    python main.py --pcap sample.pcap --auto    # 自动跑 PCAP

数据流（通过 MessageBus）:
    [模块1] CaptureEngine ──EVENT_TRAFFIC_RECORD──> [模块2] SignatureEngine (特征匹配)
                              │                    [模块3] AnomalyEngine  (异常检测)
                              │                          │
                              │              EVENT_SIGNATURE_ALERT
                              │              EVENT_ANOMALY_ALERT
                              │                          │
                              └──────────────────────────┼── [模块4] GUI
                               EVENT_TRAFFIC_RECORD      │    (告警 + 流量展示)
                                                         │
                               EVENT_STATISTICS ─────────┘
"""

import os
import sys
import time
import argparse
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common import message_bus
from common.utils import setup_logger

logger = setup_logger("main", "logs/main.log")


class NIDSApp:
    """系统集成器：模块1(抓包) → 模块2(特征) + 模块3(异常检测) → 模块4(GUI)"""

    def __init__(self):
        self._capture = None
        self._signature = None
        self._anomaly = None
        self._gui = None

    def setup(self, interface: str = None, pcap_file: str = None,
              bpf_filter: str = "", auto_start: bool = False):
        """串联三个模块"""

        # ---- 模块4: GUI（先创建，确保消息总线订阅就绪） ----
        from module4_gui import MainWindow
        self._gui = MainWindow()
        self._gui.set_on_start(lambda: self._start_capture(interface, pcap_file, bpf_filter))
        self._gui.set_on_stop(lambda: self._stop_capture())
        self._gui.set_on_import_rules(lambda path: self._import_rules(path))
        self._gui.set_on_alert_ignored(lambda data: self._on_alert_ignored(data))

        # ---- 模块2: 特征匹配检测（独立于模块3，并行处理） ----
        from module2_signature import SignatureEngine, connect as sig_connect
        self._signature = SignatureEngine()
        loaded = self._signature.load_rules("data/signatures.json")
        logger.info(f"模块2 加载 {loaded} 条特征规则")
        print(f"[系统] 模块2 特征引擎已就绪，加载 {loaded} 条规则")
        sig_connect(self._signature)

        # ---- 模块3: 异常检测（订阅 TrafficRecord） ----
        from module3_anomaly import AnomalyEngine
        from common.config import REALTIME_ANOMALY_CONFIG
        self._anomaly = AnomalyEngine(config=REALTIME_ANOMALY_CONFIG)
        self._anomaly.start_baseline_learning(duration=60)

        # 订阅模块1发布的 TrafficRecord
        message_bus.subscribe(message_bus.EVENT_TRAFFIC_RECORD, self._on_traffic_record)

        logger.info("四个模块已串联: 模块1(抓包) → 模块2(特征) + 模块3(异常) → 模块4(GUI)")
        print("[系统] 四个模块已串联，学习模式开启（60秒后建立基线）")

        if auto_start:
            self._gui._running = True
            self._gui._start_time = time.time()
            self._gui._btn_start.config(state="disabled")
            self._gui._btn_stop.config(state="normal")
            self._gui._lbl_status.config(text="● 运行中", foreground="green")
            self._start_capture(interface, pcap_file, bpf_filter)

    # ==================== 核心逻辑 ====================

    def _on_traffic_record(self, record):
        """收到模块1的 TrafficRecord → 送入模块3检测 → 告警自动推到模块4"""
        if not self._anomaly:
            return
        try:
            alerts = self._anomaly.process_traffic(record)
            for alert in alerts:
                # 发布到消息总线，GUI 已订阅 EVENT_ANOMALY_ALERT
                message_bus.publish(message_bus.EVENT_ANOMALY_ALERT, alert)

            # 更新统计
            if self._capture:
                stats = self._capture.get_statistics()
                message_bus.publish(message_bus.EVENT_STATISTICS, stats)
        except Exception as e:
            logger.debug(f"检测异常: {e}")

    def _start_capture(self, interface=None, pcap_file=None, bpf_filter=""):
        """启动模块1：抓包"""
        from module1_capture import CaptureEngine

        self._capture = CaptureEngine(use_message_bus=True)
        success = self._capture.start(
            interface=interface,
            filter_expr=bpf_filter,
            offline_pcap=pcap_file,
        )

        if success:
            mode = f"PCAP文件 {pcap_file}" if pcap_file else f"网卡 {interface or '自动'}"
            print(f"[系统] 抓包已启动: {mode}")
        else:
            print("[系统] 抓包启动失败！检查网卡/PCAP/Npcap")
            self._gui._status_text.set("启动失败")

    def _stop_capture(self):
        """停止模块1"""
        if self._capture:
            self._capture.stop()
        print("[系统] 抓包已停止")

    def _import_rules(self, file_path: str):
        """导入自定义规则文件到 data/rules/ 并触发重载"""
        import shutil
        rules_dir = os.path.join(os.path.dirname(__file__), "data", "rules")
        os.makedirs(rules_dir, exist_ok=True)

        # 复制到 rules 目录
        basename = os.path.basename(file_path)
        dest = os.path.join(rules_dir, basename)
        shutil.copy2(file_path, dest)

        # 立即重载所有规则
        if self._signature:
            count = self._signature._load_all_rules_from_dir(rules_dir)
            print(f"[系统] 导入规则成功: {basename}，当前共 {count} 条规则")
            logger.info(f"导入规则 {basename}，当前共 {count} 条规则")
        else:
            print(f"[系统] 规则文件已复制到 {dest}（下次启动生效）")

    def _on_alert_ignored(self, alert_data: dict):
        """用户标记告警为误报 → 通知自学习抑制器"""
        if not self._anomaly:
            return
        try:
            learner = self._anomaly.get_detector("suppression_learner")
            if learner:
                learner.on_user_ignore(alert_data)
                logger.info(f"抑制学习: {alert_data.get('src_ip')} {alert_data.get('attack_type')}")
        except Exception as e:
            logger.debug(f"抑制学习通知异常: {e}")

    def run(self):
        """启动 GUI 主循环（阻塞）"""
        if self._gui:
            self._gui.run()


def main():
    parser = argparse.ArgumentParser(description="网络攻击检测系统 (NIDS)")
    parser.add_argument("--interface", "-i", help="抓包网卡名称")
    parser.add_argument("--pcap", "-p",   help="PCAP 文件路径（离线模式）")
    parser.add_argument("--filter", "-f", help="BPF 过滤表达式", default="")
    parser.add_argument("--auto", action="store_true", help="自动启动抓包")
    args = parser.parse_args()

    app = NIDSApp()
    app.setup(
        interface=args.interface,
        pcap_file=args.pcap,
        bpf_filter=args.filter,
        auto_start=args.auto,
    )
    app.run()


if __name__ == "__main__":
    main()
