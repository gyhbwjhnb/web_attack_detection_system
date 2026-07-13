"""
告警输出与图形界面 —— 基于 Tkinter 实现。

功能:
  - 实时告警列表（表格）
  - 统计面板（按攻击类型/严重度统计）
  - 控制面板（启动/停止/重置）
  - 状态栏（总告警数、运行时间）
  - 配置管理
  - 告警日志导出（CSV/TXT）

依赖: 仅内置 tkinter，无需额外安装。
"""

import os
import sys
import csv
import time
import json
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import Optional, Callable, Dict, List

# 允许直接运行此文件时也能找到 common 模块
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import message_bus
from common.data_structures import Alert, AlertSeverity, AttackChain, TrafficRecord
from common.config import UI_CONFIG, SEVERITY_LEVELS, ATTACK_TYPES, ANOMALY_CONFIG, CAPTURE_CONFIG
from common.utils import setup_logger

logger = setup_logger("module4_gui", "logs/module4.log")

# 危险等级显示颜色映射
SEVERITY_COLORS = {
    1: "#1890ff",  # 信息 - 蓝
    2: "#52c41a",  # 低危 - 绿
    3: "#faad14",  # 中危 - 黄
    4: "#fa8c16",  # 高危 - 橙
    5: "#f5222d",  # 严重 - 红
}

SEVERITY_TAGS = {
    1: "info",
    2: "low",
    3: "medium",
    4: "high",
    5: "critical",
}


class MainWindow:
    """
    主窗口 —— 网络攻击检测系统 GUI。

    用法:
        from module4_gui import MainWindow
        gui = MainWindow()
        gui.run()
    """

    def __init__(self):
        self._root = tk.Tk()
        self._root.title(UI_CONFIG.get("window_title", "网络攻击检测系统"))
        self._root.geometry(
            f"{UI_CONFIG.get('window_width', 1200)}x{UI_CONFIG.get('window_height', 800)}"
        )
        self._root.minsize(900, 600)

        # ---- 状态 ----
        self._running = False
        self._alerts: List[Alert] = []
        self._max_alerts = UI_CONFIG.get("max_alerts_display", 1000)
        self._records: List[TrafficRecord] = []
        self._max_records = 500
        self._start_time: Optional[float] = None
        self._stats: dict = {}

        # ---- 筛选状态 ----
        self._alert_filter_ip = ""
        self._alert_filter_type = ""
        self._alert_filter_port = ""
        self._traffic_filter_ip = ""
        self._traffic_filter_proto = ""
        self._traffic_filter_port = ""

        # ---- IP/端口建议 ----
        self._known_ips: set = set()
        self._known_ports: set = set()

        # ---- 回调 ----
        self._on_start: Optional[Callable[[], None]] = None
        self._on_stop: Optional[Callable[[], None]] = None

        # ---- 构建界面 ----
        self._build_menu()
        self._build_ui()
        self._build_status_bar()

        # ---- 订阅消息总线 ----
        self._subscribe_bus()

        # ---- 定时刷新 ----
        self._refresh_interval = UI_CONFIG.get("refresh_interval", 2) * 1000  # ms
        self._schedule_refresh()

        # ---- 关闭处理 ----
        self._root.protocol("WM_DELETE_WINDOW", self._on_close)

        logger.info("GUI 主窗口初始化完成")

    # ==================== 界面构建 ====================

    def _build_menu(self):
        menubar = tk.Menu(self._root)
        self._root.config(menu=menubar)

        # 文件菜单
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="导出告警 CSV...", command=self._export_csv)
        file_menu.add_command(label="导出告警 TXT...", command=self._export_txt)
        file_menu.add_separator()
        file_menu.add_command(label="清空告警列表", command=self._clear_alerts)
        file_menu.add_command(label="清空流量列表", command=self._clear_traffic)
        file_menu.add_separator()
        file_menu.add_command(label="退出", command=self._on_close)
        menubar.add_cascade(label="文件", menu=file_menu)

        # 配置菜单
        config_menu = tk.Menu(menubar, tearoff=0)
        config_menu.add_command(label="检测阈值设置...", command=self._open_config_dialog)
        menubar.add_cascade(label="配置", menu=config_menu)

        # 帮助菜单
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="关于", command=self._show_about)
        menubar.add_cascade(label="帮助", menu=help_menu)

    def _build_ui(self):
        """构建主界面三栏布局"""
        # ---- 顶部控制面板 ----
        control_frame = ttk.Frame(self._root, padding=8)
        control_frame.pack(fill=tk.X)

        self._btn_start = ttk.Button(control_frame, text="▶ 开始检测", command=self._on_btn_start)
        self._btn_start.pack(side=tk.LEFT, padx=4)

        self._btn_stop = ttk.Button(control_frame, text="■ 停止检测", command=self._on_btn_stop, state=tk.DISABLED)
        self._btn_stop.pack(side=tk.LEFT, padx=4)

        self._btn_reset = ttk.Button(control_frame, text="↺ 重置统计", command=self._on_btn_reset)
        self._btn_reset.pack(side=tk.LEFT, padx=4)

        self._lbl_status = ttk.Label(control_frame, text="● 已停止", foreground="red")
        self._lbl_status.pack(side=tk.LEFT, padx=16)

        self._lbl_total = ttk.Label(control_frame, text="告警: 0")
        self._lbl_total.pack(side=tk.LEFT, padx=4)

        # ---- 主内容区（左右分栏） ----
        main_paned = ttk.PanedWindow(self._root, orient=tk.HORIZONTAL)
        main_paned.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # 左侧：标签页（告警 + 流量）
        self._notebook = ttk.Notebook(main_paned)
        main_paned.add(self._notebook, weight=3)

        # 标签1：告警列表
        alert_tab = ttk.Frame(self._notebook)
        self._notebook.add(alert_tab, text=" 告警列表 ")
        self._build_alert_table(alert_tab)

        # 标签2：正常流量
        traffic_tab = ttk.Frame(self._notebook)
        self._notebook.add(traffic_tab, text=" 正常流量 ")
        self._build_traffic_table(traffic_tab)

        # 右侧：统计面板
        right_frame = ttk.Frame(main_paned)
        main_paned.add(right_frame, weight=1)

        self._build_stats_panel(right_frame)

    def _build_alert_table(self, parent: ttk.Frame):
        """告警表格"""
        ttk.Label(parent, text="实时告警列表", font=("", 10, "bold")).pack(anchor=tk.W, pady=2)

        # ---- 筛选栏 ----
        filter_bar = ttk.Frame(parent)
        filter_bar.pack(fill=tk.X, pady=(0, 4))

        ttk.Label(filter_bar, text="IP:").pack(side=tk.LEFT, padx=(0, 2))
        self._alert_ip_cb = ttk.Combobox(filter_bar, width=17)
        self._alert_ip_cb.pack(side=tk.LEFT, padx=(0, 8))

        ttk.Label(filter_bar, text="类型:").pack(side=tk.LEFT, padx=(0, 2))
        self._alert_type_var = tk.StringVar(value="全部")
        self._alert_type_combo = ttk.Combobox(filter_bar, textvariable=self._alert_type_var,
            values=["全部", "端口扫描", "暴力破解", "异常外联", "横向扩散", "SYN Flood", "带宽异常", "行为突变", "DNS隧道", "未知"],
            width=10, state="readonly")
        self._alert_type_combo.pack(side=tk.LEFT, padx=(0, 8))

        ttk.Label(filter_bar, text="端口:").pack(side=tk.LEFT, padx=(0, 2))
        self._alert_port_cb = ttk.Combobox(filter_bar, width=8)
        self._alert_port_cb.pack(side=tk.LEFT, padx=(0, 8))

        ttk.Button(filter_bar, text="筛选", command=self._apply_alert_filter, width=5).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(filter_bar, text="清除", command=self._clear_alert_filter, width=5).pack(side=tk.LEFT)

        # 表格容器
        table_frame = ttk.Frame(parent)
        table_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("id", "time", "type", "severity", "src", "dst", "description")
        self._tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")

        self._tree.heading("id", text="ID")
        self._tree.heading("time", text="时间")
        self._tree.heading("type", text="攻击类型")
        self._tree.heading("severity", text="等级")
        self._tree.heading("src", text="来源")
        self._tree.heading("dst", text="目标")
        self._tree.heading("description", text="描述")

        self._tree.column("id", width=80, minwidth=60)
        self._tree.column("time", width=140, minwidth=100)
        self._tree.column("type", width=100, minwidth=80)
        self._tree.column("severity", width=50, minwidth=40)
        self._tree.column("src", width=140, minwidth=100)
        self._tree.column("dst", width=140, minwidth=100)
        self._tree.column("description", width=300, minwidth=150)

        # 滚动条
        scrollbar_y = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self._tree.yview)
        scrollbar_x = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self._tree.xview)
        self._tree.configure(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)

        self._tree.grid(row=0, column=0, sticky="nsew")
        scrollbar_y.grid(row=0, column=1, sticky="ns")
        scrollbar_x.grid(row=1, column=0, sticky="ew")
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

        # 严重度颜色标签
        for sev_val, tag_name in SEVERITY_TAGS.items():
            color = SEVERITY_COLORS.get(sev_val, "#000000")
            self._tree.tag_configure(tag_name, foreground=color)

        # 双击查看详情
        self._tree.bind("<Double-1>", self._on_alert_double_click)

    def _build_traffic_table(self, parent: ttk.Frame):
        """正常流量表格"""
        ttk.Label(parent, text="实时正常流量", font=("", 10, "bold")).pack(anchor=tk.W, pady=2)

        # ---- 筛选栏 ----
        filter_bar = ttk.Frame(parent)
        filter_bar.pack(fill=tk.X, pady=(0, 4))

        ttk.Label(filter_bar, text="IP:").pack(side=tk.LEFT, padx=(0, 2))
        self._traffic_ip_cb = ttk.Combobox(filter_bar, width=17)
        self._traffic_ip_cb.pack(side=tk.LEFT, padx=(0, 8))

        ttk.Label(filter_bar, text="协议:").pack(side=tk.LEFT, padx=(0, 2))
        self._traffic_proto_var = tk.StringVar(value="全部")
        self._traffic_proto_combo = ttk.Combobox(filter_bar, textvariable=self._traffic_proto_var,
            values=["全部", "TCP", "UDP", "HTTP", "DNS", "TLS", "ICMP", "HTTPS", "OTHER"],
            width=8, state="readonly")
        self._traffic_proto_combo.pack(side=tk.LEFT, padx=(0, 8))

        ttk.Label(filter_bar, text="端口:").pack(side=tk.LEFT, padx=(0, 2))
        self._traffic_port_cb = ttk.Combobox(filter_bar, width=8)
        self._traffic_port_cb.pack(side=tk.LEFT, padx=(0, 8))

        ttk.Button(filter_bar, text="筛选", command=self._apply_traffic_filter, width=5).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(filter_bar, text="清除", command=self._clear_traffic_filter, width=5).pack(side=tk.LEFT)

        table_frame = ttk.Frame(parent)
        table_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("id", "time", "protocol", "src", "dst", "info")
        self._traffic_tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")

        self._traffic_tree.heading("id", text="#")
        self._traffic_tree.heading("time", text="时间")
        self._traffic_tree.heading("protocol", text="协议")
        self._traffic_tree.heading("src", text="来源")
        self._traffic_tree.heading("dst", text="目标")
        self._traffic_tree.heading("info", text="信息")

        self._traffic_tree.column("id", width=40, minwidth=30)
        self._traffic_tree.column("time", width=130, minwidth=90)
        self._traffic_tree.column("protocol", width=70, minwidth=50)
        self._traffic_tree.column("src", width=160, minwidth=100)
        self._traffic_tree.column("dst", width=160, minwidth=100)
        self._traffic_tree.column("info", width=270, minwidth=120)

        scrollbar_y = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self._traffic_tree.yview)
        scrollbar_x = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self._traffic_tree.xview)
        self._traffic_tree.configure(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)

        self._traffic_tree.grid(row=0, column=0, sticky="nsew")
        scrollbar_y.grid(row=0, column=1, sticky="ns")
        scrollbar_x.grid(row=1, column=0, sticky="ew")
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

        # 协议颜色
        self._traffic_tree.tag_configure("tcp", foreground="#1890ff")
        self._traffic_tree.tag_configure("udp", foreground="#52c41a")
        self._traffic_tree.tag_configure("http", foreground="#fa8c16")
        self._traffic_tree.tag_configure("dns", foreground="#722ed1")
        self._traffic_tree.tag_configure("tls", foreground="#eb2f96")
        self._traffic_tree.tag_configure("other", foreground="#8c8c8c")

        # 双击查看流量详情
        self._traffic_tree.bind("<Double-1>", self._on_traffic_double_click)

    def _build_stats_panel(self, parent: ttk.Frame):
        """右侧统计面板"""
        ttk.Label(parent, text="统计面板", font=("", 10, "bold")).pack(anchor=tk.W, pady=2)

        # 按攻击类型统计
        type_frame = ttk.LabelFrame(parent, text="按攻击类型", padding=4)
        type_frame.pack(fill=tk.X, pady=2)

        self._stats_text = tk.Text(type_frame, height=12, width=24, state=tk.DISABLED, font=("Consolas", 9))
        self._stats_text.pack(fill=tk.BOTH, expand=True)

        # 按严重度统计
        sev_frame = ttk.LabelFrame(parent, text="按严重等级", padding=4)
        sev_frame.pack(fill=tk.X, pady=2)

        self._sev_text = tk.Text(sev_frame, height=6, width=24, state=tk.DISABLED, font=("Consolas", 9))
        self._sev_text.pack(fill=tk.BOTH, expand=True)

        # 捕获统计
        cap_frame = ttk.LabelFrame(parent, text="捕获统计", padding=4)
        cap_frame.pack(fill=tk.X, pady=2)

        self._cap_text = tk.Text(cap_frame, height=6, width=24, state=tk.DISABLED, font=("Consolas", 9))
        self._cap_text.pack(fill=tk.BOTH, expand=True)

    def _build_status_bar(self):
        """底部状态栏"""
        status_frame = ttk.Frame(self._root, relief=tk.SUNKEN)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)

        self._status_text = tk.StringVar(value="就绪")
        ttk.Label(status_frame, textvariable=self._status_text, padding=(8, 2)).pack(side=tk.LEFT)

        self._runtime_text = tk.StringVar(value="运行时间: 00:00:00")
        ttk.Label(status_frame, textvariable=self._runtime_text, padding=(8, 2)).pack(side=tk.RIGHT)

    # ==================== 消息总线订阅 ====================

    def _subscribe_bus(self):
        message_bus.subscribe(message_bus.EVENT_SIGNATURE_ALERT, self.add_alert)
        message_bus.subscribe(message_bus.EVENT_ANOMALY_ALERT, self.add_alert)
        message_bus.subscribe(message_bus.EVENT_TRAFFIC_RECORD, self.add_traffic_record)
        message_bus.subscribe(message_bus.EVENT_STATISTICS, self.update_statistics)

    # ==================== 数据输入 ====================

    def _track_ip(self, *ips: str):
        """收集见过的 IP，更新两个 Combobox 的建议列表"""
        new_ips = False
        for ip in ips:
            if ip and ip not in self._known_ips:
                self._known_ips.add(ip)
                new_ips = True
        if new_ips:
            sorted_ips = sorted(self._known_ips)
            self._alert_ip_cb["values"] = sorted_ips
            self._traffic_ip_cb["values"] = sorted_ips

    def _track_port(self, *ports):
        """收集见过的端口，更新两个 Combobox 的建议列表"""
        new_ports = False
        for port in ports:
            p = str(port) if port else ""
            if p and p not in self._known_ports:
                self._known_ports.add(p)
                new_ports = True
        if new_ports:
            sorted_ports = sorted(self._known_ports, key=lambda x: int(x) if x.isdigit() else 99999)
            self._alert_port_cb["values"] = sorted_ports
            self._traffic_port_cb["values"] = sorted_ports

    def add_alert(self, alert: Alert):
        """接收 Alert 对象并添加到列表"""
        self._alerts.append(alert)

        # 追踪 IP
        self._track_ip(alert.src_ip, alert.dst_ip or "")
        self._track_port(alert.src_port, alert.dst_port)

        # 限制最大条数
        while len(self._alerts) > self._max_alerts:
            self._alerts.pop(0)

        # 检查筛选条件
        if not self._alert_matches_filter(alert):
            return

        self._insert_alert_row(alert)
        logger.debug(f"告警: {alert.title}")

    def _alert_matches_filter(self, alert: Alert) -> bool:
        """检查告警是否满足当前筛选条件"""
        filter_ip = self._alert_filter_ip.strip()
        filter_type = self._alert_filter_type.strip()
        filter_port = self._alert_filter_port.strip()
        if not filter_ip and not filter_type and not filter_port:
            return True

        if filter_ip:
            if filter_ip not in alert.src_ip and filter_ip not in (alert.dst_ip or ""):
                return False

        if filter_type:
            attack_type = alert.attack_name or alert.attack_type or "未知"
            if filter_type != attack_type:
                return False

        if filter_port:
            src_p = str(alert.src_port) if alert.src_port else ""
            dst_p = str(alert.dst_port) if alert.dst_port else ""
            if filter_port != src_p and filter_port != dst_p:
                return False

        return True

    def _insert_alert_row(self, alert: Alert):
        """将一条告警插入树表格"""
        ts = time.strftime("%H:%M:%S", time.localtime(alert.timestamp))
        severity_name = SEVERITY_LEVELS.get(alert.severity.value, {}).get("name", str(alert.severity.value))
        tag = SEVERITY_TAGS.get(alert.severity.value, "")

        src = f"{alert.src_ip}:{alert.src_port}" if alert.src_port else alert.src_ip
        dst = f"{alert.dst_ip}:{alert.dst_port}" if alert.dst_port else alert.dst_ip

        self._tree.insert("", 0, values=(
            alert.alert_id[:8],
            ts,
            alert.attack_name or alert.attack_type,
            severity_name,
            src,
            dst,
            alert.title or alert.description[:60],
        ), tags=(tag,))

        # 限制表格行数
        children = self._tree.get_children()
        if len(children) > self._max_alerts:
            self._tree.delete(children[-1])

    def add_traffic_record(self, record: TrafficRecord):
        """接收 TrafficRecord 并添加到流量列表"""
        self._records.append(record)

        # 追踪 IP
        src_ip = record.src.ip if hasattr(record.src, 'ip') else ""
        dst_ip = record.dst.ip if hasattr(record.dst, 'ip') else ""
        self._track_ip(src_ip, dst_ip)
        src_port = record.src.port if hasattr(record.src, 'port') else ""
        dst_port = record.dst.port if hasattr(record.dst, 'port') else ""
        self._track_port(src_port, dst_port)
        while len(self._records) > self._max_records:
            self._records.pop(0)

        # 检查筛选条件
        if not self._traffic_matches_filter(record):
            return

        self._insert_traffic_row(record)

    def _traffic_matches_filter(self, record: TrafficRecord) -> bool:
        """检查流量记录是否满足当前筛选条件"""
        filter_ip = self._traffic_filter_ip.strip()
        filter_proto = self._traffic_filter_proto.strip()
        filter_port = self._traffic_filter_port.strip()
        if not filter_ip and not filter_proto and not filter_port:
            return True

        if filter_ip:
            src_ip = record.src.ip if hasattr(record.src, 'ip') else ""
            dst_ip = record.dst.ip if hasattr(record.dst, 'ip') else ""
            if filter_ip not in src_ip and filter_ip not in dst_ip:
                return False

        if filter_proto:
            proto = (record.protocol or {}).value if hasattr(record.protocol, 'value') else str(record.protocol or "")
            if filter_proto.upper() != proto.upper():
                return False

        if filter_port:
            src_p = str(record.src.port) if hasattr(record.src, 'port') else ""
            dst_p = str(record.dst.port) if hasattr(record.dst, 'port') else ""
            if filter_port != src_p and filter_port != dst_p:
                return False

        return True

    def _insert_traffic_row(self, record: TrafficRecord):
        """将一条流量记录插入树表格"""
        ts = time.strftime("%H:%M:%S", time.localtime(record.timestamp)) if record.timestamp else "--:--:--"
        proto = (record.protocol or {}).value if hasattr(record.protocol, 'value') else str(record.protocol or "?")

        src = record.src.to_str() if hasattr(record.src, 'to_str') else f"{record.src.ip}:{record.src.port}"
        dst = record.dst.to_str() if hasattr(record.dst, 'to_str') else f"{record.dst.ip}:{record.dst.port}"

        # 构造信息列
        info = record.protocol_detail or ""
        if not info:
            if record.http_method and record.http_uri:
                info = f"{record.http_method} {record.http_uri[:60]}"
            elif record.dns_query:
                info = f"DNS: {record.dns_query[:60]}"

        # 协议颜色标签
        proto_lower = proto.lower()
        tag = "other"
        if proto_lower == "tcp" or proto_lower == "https":
            tag = "tcp"
        elif proto_lower == "udp":
            tag = "udp"
        elif proto_lower == "http":
            tag = "http"
        elif proto_lower == "dns":
            tag = "dns"
        elif proto_lower == "tls":
            tag = "tls"

        idx = len(self._records)
        self._traffic_tree.insert("", 0, values=(
            idx, ts, proto, src, dst, info,
        ), tags=(tag,))

        # 限制表格行数
        children = self._traffic_tree.get_children()
        if len(children) > self._max_records:
            self._traffic_tree.delete(children[-1])

    def update_statistics(self, stats: dict):
        """更新统计面板"""
        self._stats = stats

    def set_on_start(self, callback: Callable[[], None]):
        """注册启动回调"""
        self._on_start = callback

    def set_on_stop(self, callback: Callable[[], None]):
        """注册停止回调"""
        self._on_stop = callback

    def run(self):
        """启动 GUI 主循环（阻塞）"""
        self._root.mainloop()

    # ==================== 按钮事件 ====================

    def _on_btn_start(self):
        self._running = True
        self._start_time = time.time()
        self._btn_start.config(state=tk.DISABLED)
        self._btn_stop.config(state=tk.NORMAL)
        self._lbl_status.config(text="● 运行中", foreground="green")
        self._status_text.set("检测运行中...")

        if self._on_start:
            self._on_start()

        logger.info("检测已启动")

    def _on_btn_stop(self):
        self._running = False
        self._btn_start.config(state=tk.NORMAL)
        self._btn_stop.config(state=tk.DISABLED)
        self._lbl_status.config(text="● 已停止", foreground="red")
        self._status_text.set("已停止")

        if self._on_stop:
            self._on_stop()

        logger.info("检测已停止")

    def _on_btn_reset(self):
        """重置统计"""
        if messagebox.askyesno("确认", "确定要清空所有告警、流量并重置统计吗？"):
            self._clear_alerts()
            self._clear_traffic()
            self._alerts.clear()
            self._records.clear()
            self._stats = {}
            # 通知后台引擎一起重置
            message_bus.publish(message_bus.EVENT_CONFIG_CHANGE, {"action": "reset"})
            # 立刻刷新界面，不等下一轮定时器
            self._refresh_stats()
            self._status_text.set("统计已重置")
            logger.info("统计已重置")

    # ==================== 菜单事件 ====================

    def _export_csv(self):
        if not self._alerts:
            messagebox.showinfo("提示", "无告警可导出")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV 文件", "*.csv")],
            initialfile="alerts_export.csv",
        )
        if not path:
            return

        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)
                writer.writerow(["告警ID", "时间", "攻击类型", "等级", "来源IP", "来源端口",
                                 "目标IP", "目标端口", "描述", "建议"])
                for a in self._alerts:
                    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(a.timestamp))
                    writer.writerow([
                        a.alert_id, ts, a.attack_name or a.attack_type,
                        a.severity.value, a.src_ip, a.src_port,
                        a.dst_ip, a.dst_port, a.title, a.suggestion,
                    ])
            self._status_text.set(f"已导出 {len(self._alerts)} 条告警到 {os.path.basename(path)}")
            messagebox.showinfo("成功", f"已导出 {len(self._alerts)} 条告警")
            logger.info(f"告警导出: {path}")
        except Exception as e:
            messagebox.showerror("错误", f"导出失败: {e}")

    def _export_txt(self):
        if not self._alerts:
            messagebox.showinfo("提示", "无告警可导出")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("文本文件", "*.txt")],
            initialfile="alerts_export.txt",
        )
        if not path:
            return

        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("=" * 70 + "\n")
                f.write("网络攻击检测系统 - 告警日志\n")
                f.write(f"导出时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"告警总数: {len(self._alerts)}\n")
                f.write("=" * 70 + "\n\n")

                for i, a in enumerate(self._alerts, 1):
                    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(a.timestamp))
                    sev = SEVERITY_LEVELS.get(a.severity.value, {}).get("name", "未知")
                    f.write(f"[{i}] {ts} | {sev} | {a.attack_name or a.attack_type}\n")
                    f.write(f"    来源: {a.src_ip}:{a.src_port} -> {a.dst_ip}:{a.dst_port}\n")
                    f.write(f"    描述: {a.title}\n")
                    if a.suggestion:
                        f.write(f"    建议: {a.suggestion}\n")
                    if a.payload_snippet:
                        f.write(f"    载荷: {a.payload_snippet[:100]}\n")
                    f.write("\n")

            self._status_text.set(f"已导出 {len(self._alerts)} 条告警到 {os.path.basename(path)}")
            messagebox.showinfo("成功", f"已导出 {len(self._alerts)} 条告警")
            logger.info(f"告警导出: {path}")
        except Exception as e:
            messagebox.showerror("错误", f"导出失败: {e}")

    def _clear_alerts(self):
        for item in self._tree.get_children():
            self._tree.delete(item)
        self._alerts.clear()
        self._alert_filter_ip = ""
        self._alert_filter_type = ""
        self._alert_filter_port = ""
        self._alert_ip_cb.set("")
        self._alert_type_var.set("全部")
        self._alert_port_cb.set("")
        self._status_text.set("告警列表已清空")

    def _clear_traffic(self):
        for item in self._traffic_tree.get_children():
            self._traffic_tree.delete(item)
        self._records.clear()
        self._traffic_filter_ip = ""
        self._traffic_filter_proto = ""
        self._traffic_filter_port = ""
        self._traffic_ip_cb.set("")
        self._traffic_proto_var.set("全部")
        self._traffic_port_cb.set("")

    # ==================== 筛选功能 ====================

    def _apply_alert_filter(self):
        """应用告警筛选"""
        self._alert_filter_ip = self._alert_ip_cb.get().strip()
        self._alert_filter_type = self._alert_type_var.get().strip()
        self._alert_filter_port = self._alert_port_cb.get().strip()
        if self._alert_filter_type == "全部":
            self._alert_filter_type = ""

        # 清空树，用现有数据重建
        self._tree.delete(*self._tree.get_children())
        for alert in self._alerts:
            if self._alert_matches_filter(alert):
                self._insert_alert_row(alert)
        logger.info(f"告警筛选: IP={self._alert_filter_ip or '*'} 类型={self._alert_filter_type or '*'} 端口={self._alert_filter_port or '*'}")

    def _clear_alert_filter(self):
        """清除告警筛选"""
        self._alert_filter_ip = ""
        self._alert_filter_type = ""
        self._alert_filter_port = ""
        self._alert_ip_cb.set("")
        self._alert_type_var.set("全部")
        self._alert_port_cb.set("")

        self._tree.delete(*self._tree.get_children())
        for alert in self._alerts:
            self._insert_alert_row(alert)
        logger.info("告警筛选已清除")

    def _apply_traffic_filter(self):
        """应用流量筛选"""
        self._traffic_filter_ip = self._traffic_ip_cb.get().strip()
        self._traffic_filter_proto = self._traffic_proto_var.get().strip()
        self._traffic_filter_port = self._traffic_port_cb.get().strip()
        if self._traffic_filter_proto == "全部":
            self._traffic_filter_proto = ""

        self._traffic_tree.delete(*self._traffic_tree.get_children())
        for record in self._records:
            if self._traffic_matches_filter(record):
                self._insert_traffic_row(record)
        logger.info(f"流量筛选: IP={self._traffic_filter_ip or '*'} 协议={self._traffic_filter_proto or '*'} 端口={self._traffic_filter_port or '*'}")

    def _clear_traffic_filter(self):
        """清除流量筛选"""
        self._traffic_filter_ip = ""
        self._traffic_filter_proto = ""
        self._traffic_filter_port = ""
        self._traffic_ip_cb.set("")
        self._traffic_proto_var.set("全部")
        self._traffic_port_cb.set("")

        self._traffic_tree.delete(*self._traffic_tree.get_children())
        for record in self._records:
            self._insert_traffic_row(record)
        logger.info("流量筛选已清除")

    def _open_config_dialog(self):
        """打开配置对话框"""
        ConfigDialog(self._root)
        self._status_text.set("配置已更新")

    def _show_about(self):
        messagebox.showinfo(
            "关于",
            "网络攻击检测系统 (NIDS)\n\n"
            "版本: 1.0.0\n"
            "功能: 实时网络流量捕获 + 特征匹配检测 + 异常行为分析\n\n"
            "模块1: 数据包捕获与预处理\n"
            "模块2: 特征匹配检测引擎\n"
            "模块3: 异常行为检测引擎\n"
            "模块4: 告警输出与图形界面"
        )

    def _on_alert_double_click(self, event):
        """双击告警行查看详情"""
        selection = self._tree.selection()
        if not selection:
            return
        item = self._tree.item(selection[0])
        values = item["values"]
        if values:
            AlertDetailDialog(self._root, values)

    def _on_traffic_double_click(self, event):
        """双击流量行查看详情"""
        selection = self._traffic_tree.selection()
        if not selection:
            return
        item = self._traffic_tree.item(selection[0])
        values = item["values"]
        if not values:
            return
        # values[0] 是序号，对应 self._records 中的索引
        idx = values[0]
        if 1 <= idx <= len(self._records):
            record = self._records[idx - 1]
            TrafficDetailDialog(self._root, record)

    def _on_close(self):
        if self._running:
            if not messagebox.askyesno("确认", "检测正在运行中，确定退出吗？"):
                return
            self._on_btn_stop()
        self._root.destroy()
        logger.info("GUI 窗口已关闭")

    # ==================== 定时刷新 ====================

    def _schedule_refresh(self):
        """定时刷新统计面板和状态栏"""
        self._refresh_stats()
        self._refresh_status()
        self._root.after(self._refresh_interval, self._schedule_refresh)

    def _refresh_stats(self):
        """刷新右侧统计面板"""
        # 按攻击类型统计
        type_count: Dict[str, int] = {}
        for a in self._alerts:
            key = a.attack_name or a.attack_type or "未知"
            type_count[key] = type_count.get(key, 0) + 1

        type_lines = []
        for name, count in sorted(type_count.items(), key=lambda x: -x[1]):
            type_lines.append(f"  {name}: {count}")

        self._stats_text.config(state=tk.NORMAL)
        self._stats_text.delete("1.0", tk.END)
        self._stats_text.insert("1.0", "\n".join(type_lines) if type_lines else "  暂无数据")
        self._stats_text.config(state=tk.DISABLED)

        # 按严重度统计
        sev_count: Dict[int, int] = {}
        for a in self._alerts:
            sev_count[a.severity.value] = sev_count.get(a.severity.value, 0) + 1

        sev_lines = []
        for sev_val in [5, 4, 3, 2, 1]:
            if sev_val in sev_count:
                name = SEVERITY_LEVELS.get(sev_val, {}).get("name", str(sev_val))
                sev_lines.append(f"  {name}: {sev_count[sev_val]}")

        self._sev_text.config(state=tk.NORMAL)
        self._sev_text.delete("1.0", tk.END)
        self._sev_text.insert("1.0", "\n".join(sev_lines) if sev_lines else "  暂无数据")
        self._sev_text.config(state=tk.DISABLED)

        # 捕获统计
        cap_lines = []
        if self._stats:
            for key in ["packet_count", "bytes_total", "tcp_flows", "udp_flows"]:
                if key in self._stats:
                    label = {"packet_count": "抓包数", "bytes_total": "字节数",
                             "tcp_flows": "TCP流", "udp_flows": "UDP流"}.get(key, key)
                    cap_lines.append(f"  {label}: {self._stats[key]}")
        else:
            cap_lines.append("  等待数据...")

        self._cap_text.config(state=tk.NORMAL)
        self._cap_text.delete("1.0", tk.END)
        self._cap_text.insert("1.0", "\n".join(cap_lines))
        self._cap_text.config(state=tk.DISABLED)

    def _refresh_status(self):
        """刷新状态栏"""
        self._lbl_total.config(text=f"告警: {len(self._alerts)} | 流量: {len(self._records)}")

        if self._running and self._start_time:
            elapsed = int(time.time() - self._start_time)
            h, m, s = elapsed // 3600, (elapsed % 3600) // 60, elapsed % 60
            self._runtime_text.set(f"运行时间: {h:02d}:{m:02d}:{s:02d}")


# ==================== 配置对话框 ====================

class ConfigDialog(tk.Toplevel):
    """检测阈值配置对话框"""

    def __init__(self, parent):
        super().__init__(parent)
        self.title("检测阈值配置")
        self.geometry("420x380")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self._build()

    def _build(self):
        frame = ttk.Frame(self, padding=16)
        frame.pack(fill=tk.BOTH, expand=True)

        row = 0

        # 端口扫描
        ttk.Label(frame, text="端口扫描阈值 (不同端口数/窗口):").grid(row=row, column=0, sticky=tk.W, pady=4)
        self._port_scan_thresh = tk.IntVar(value=ANOMALY_CONFIG.get("port_scan_threshold", 50))
        ttk.Entry(frame, textvariable=self._port_scan_thresh, width=10).grid(row=row, column=1, pady=4)
        row += 1

        ttk.Label(frame, text="端口扫描时间窗口 (秒):").grid(row=row, column=0, sticky=tk.W, pady=4)
        self._port_scan_window = tk.IntVar(value=ANOMALY_CONFIG.get("port_scan_window_sec", 10))
        ttk.Entry(frame, textvariable=self._port_scan_window, width=10).grid(row=row, column=1, pady=4)
        row += 1

        ttk.Separator(frame, orient=tk.HORIZONTAL).grid(row=row, columnspan=2, sticky=tk.EW, pady=6)
        row += 1

        # 暴力破解
        ttk.Label(frame, text="暴力破解阈值 (连接数):").grid(row=row, column=0, sticky=tk.W, pady=4)
        self._brute_thresh = tk.IntVar(value=ANOMALY_CONFIG.get("brute_force_threshold", 10))
        ttk.Entry(frame, textvariable=self._brute_thresh, width=10).grid(row=row, column=1, pady=4)
        row += 1

        ttk.Label(frame, text="暴力破解时间窗口 (秒):").grid(row=row, column=0, sticky=tk.W, pady=4)
        self._brute_window = tk.IntVar(value=ANOMALY_CONFIG.get("brute_force_window_sec", 5))
        ttk.Entry(frame, textvariable=self._brute_window, width=10).grid(row=row, column=1, pady=4)
        row += 1

        ttk.Separator(frame, orient=tk.HORIZONTAL).grid(row=row, columnspan=2, sticky=tk.EW, pady=6)
        row += 1

        # SYN Flood
        ttk.Label(frame, text="SYN Flood 阈值 (包数/秒):").grid(row=row, column=0, sticky=tk.W, pady=4)
        self._syn_thresh = tk.IntVar(value=ANOMALY_CONFIG.get("syn_flood_threshold", 100))
        ttk.Entry(frame, textvariable=self._syn_thresh, width=10).grid(row=row, column=1, pady=4)
        row += 1

        ttk.Separator(frame, orient=tk.HORIZONTAL).grid(row=row, columnspan=2, sticky=tk.EW, pady=6)
        row += 1

        # 带宽异常
        ttk.Label(frame, text="带宽异常倍数阈值:").grid(row=row, column=0, sticky=tk.W, pady=4)
        self._bw_thresh = tk.DoubleVar(value=ANOMALY_CONFIG.get("bandwidth_anomaly_threshold", 5.0))
        ttk.Entry(frame, textvariable=self._bw_thresh, width=10).grid(row=row, column=1, pady=4)
        row += 1

        ttk.Separator(frame, orient=tk.HORIZONTAL).grid(row=row, columnspan=2, sticky=tk.EW, pady=6)
        row += 1

        # GUI 刷新间隔
        ttk.Label(frame, text="界面刷新间隔 (秒):").grid(row=row, column=0, sticky=tk.W, pady=4)
        self._refresh_sec = tk.IntVar(value=UI_CONFIG.get("refresh_interval", 2))
        ttk.Entry(frame, textvariable=self._refresh_sec, width=10).grid(row=row, column=1, pady=4)
        row += 1

        # 按钮
        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=row, columnspan=2, pady=16)

        ttk.Button(btn_frame, text="保存", command=self._save).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="取消", command=self.destroy).pack(side=tk.LEFT, padx=4)

    def _save(self):
        """保存配置到全局配置"""
        ANOMALY_CONFIG["port_scan_threshold"] = self._port_scan_thresh.get()
        ANOMALY_CONFIG["port_scan_window_sec"] = self._port_scan_window.get()
        ANOMALY_CONFIG["brute_force_threshold"] = self._brute_thresh.get()
        ANOMALY_CONFIG["brute_force_window_sec"] = self._brute_window.get()
        ANOMALY_CONFIG["syn_flood_threshold"] = self._syn_thresh.get()
        ANOMALY_CONFIG["bandwidth_anomaly_threshold"] = self._bw_thresh.get()
        UI_CONFIG["refresh_interval"] = self._refresh_sec.get()

        message_bus.publish(message_bus.EVENT_CONFIG_CHANGE, {"anomaly": dict(ANOMALY_CONFIG)})
        messagebox.showinfo("成功", "配置已保存")
        self.destroy()


# ==================== 告警详情对话框 ====================

class AlertDetailDialog(tk.Toplevel):
    """告警详情对话框"""

    def __init__(self, parent, values: tuple):
        super().__init__(parent)
        self.title("告警详情")
        self.geometry("500x320")
        self.resizable(False, False)
        self.transient(parent)

        frame = ttk.Frame(self, padding=16)
        frame.pack(fill=tk.BOTH, expand=True)

        labels = ["告警ID", "时间", "攻击类型", "等级", "来源", "目标", "描述"]
        for i, (label, value) in enumerate(zip(labels, values)):
            ttk.Label(frame, text=f"{label}:", font=("", 9, "bold")).grid(
                row=i, column=0, sticky=tk.W, pady=2, padx=(0, 8))
            ttk.Label(frame, text=str(value), wraplength=380).grid(
                row=i, column=1, sticky=tk.W, pady=2)

        ttk.Button(frame, text="关闭", command=self.destroy).grid(
            row=len(labels), columnspan=2, pady=16)


class TrafficDetailDialog(tk.Toplevel):
    """流量详情对话框"""

    def __init__(self, parent, record: TrafficRecord):
        super().__init__(parent)
        self.title("流量详情")
        self.geometry("520x400")
        self.resizable(False, False)
        self.transient(parent)
        self._record = record

        frame = ttk.Frame(self, padding=16)
        frame.pack(fill=tk.BOTH, expand=True)

        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(record.timestamp)) if record.timestamp else "--"
        proto_name = record.protocol.value.upper() if hasattr(record.protocol, 'value') else str(record.protocol)
        src = record.src.to_str() if hasattr(record.src, 'to_str') else f"{record.src.ip}:{record.src.port}"
        dst = record.dst.to_str() if hasattr(record.dst, 'to_str') else f"{record.dst.ip}:{record.dst.port}"

        rows = [
            ("时间", ts),
            ("协议", proto_name),
            ("来源 IP", record.src.ip),
            ("来源端口", str(record.src.port)),
            ("目标 IP", record.dst.ip),
            ("目标端口", str(record.dst.port)),
        ]

        # 附加信息
        if record.http_method:
            rows.append(("HTTP 方法", record.http_method))
        if record.http_uri:
            rows.append(("HTTP URI", record.http_uri[:100]))
        if record.dns_query:
            rows.append(("DNS 查询", record.dns_query))
        if record.tls_sni:
            rows.append(("TLS SNI", record.tls_sni))
        extra = record.protocol_detail or ""
        if extra:
            rows.append(("详情", extra[:120]))

        has_payload = False
        if record.payload_size:
            rows.append(("载荷大小", f"{record.payload_size} 字节"))
            has_payload = True
        if record.payload_raw:
            hex_preview = record.payload_raw[:32].hex(' ') if isinstance(record.payload_raw, bytes) else str(record.payload_raw)[:80]
            rows.append(("载荷预览", hex_preview))

        for i, (label, value) in enumerate(rows):
            ttk.Label(frame, text=f"{label}:", font=("", 9, "bold")).grid(
                row=i, column=0, sticky=tk.W, pady=2, padx=(0, 8))
            ttk.Label(frame, text=str(value), wraplength=380, foreground="#333").grid(
                row=i, column=1, sticky=tk.W, pady=2)

        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=len(rows), columnspan=2, pady=16)

        ttk.Button(btn_frame, text="下载", command=self._download).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(btn_frame, text="关闭", command=self.destroy).pack(side=tk.LEFT)

    def _download(self):
        """导出流量包数据到文件"""
        from tkinter import filedialog

        record = self._record
        ts_tag = time.strftime("%Y%m%d_%H%M%S", time.localtime(record.timestamp)) if record.timestamp else "unknown"
        proto = record.protocol.value if hasattr(record.protocol, 'value') else str(record.protocol or "unknown")
        default_name = f"packet_{proto}_{record.src.ip}_{record.dst.ip}_{ts_tag}"

        payload = record.payload_raw
        if payload and isinstance(payload, bytes) and len(payload) > 0:
            filepath = filedialog.asksaveasfilename(
                parent=self,
                title="保存流量包",
                initialfile=f"{default_name}.bin",
                defaultextension=".bin",
                filetypes=[("原始二进制", "*.bin"), ("所有文件", "*.*")],
            )
            if filepath:
                with open(filepath, "wb") as f:
                    f.write(payload)
                self._show_toast(f"已保存 {len(payload)} 字节到 {filepath}")
        else:
            # 无载荷时导出元数据 JSON
            filepath = filedialog.asksaveasfilename(
                parent=self,
                title="保存流量信息",
                initialfile=f"{default_name}.json",
                defaultextension=".json",
                filetypes=[("JSON 文件", "*.json"), ("文本文件", "*.txt"), ("所有文件", "*.*")],
            )
            if filepath:
                import json
                meta = {
                    "timestamp": ts_tag,
                    "protocol": proto,
                    "src": f"{record.src.ip}:{record.src.port}",
                    "dst": f"{record.dst.ip}:{record.dst.port}",
                    "http_method": getattr(record, "http_method", None),
                    "http_uri": getattr(record, "http_uri", None),
                    "dns_query": getattr(record, "dns_query", None),
                    "tls_sni": getattr(record, "tls_sni", None),
                    "payload_size": getattr(record, "payload_size", 0),
                    "detail": getattr(record, "protocol_detail", ""),
                }
                meta = {k: v for k, v in meta.items() if v}
                with open(filepath, "w", encoding="utf-8") as f:
                    json.dump(meta, f, ensure_ascii=False, indent=2)
                self._show_toast(f"已保存到 {filepath}")

    def _show_toast(self, msg: str):
        """短暂提示"""
        toast = tk.Toplevel(self)
        toast.title("")
        toast.geometry(f"+{self.winfo_x() + 40}+{self.winfo_y() + 40}")
        toast.resizable(False, False)
        toast.overrideredirect(True)
        ttk.Label(toast, text=msg, padding=12, background="#e6f7ff",
                  relief="solid", borderwidth=1).pack()
        toast.after(2000, toast.destroy)


# ==================== 直接运行入口 ====================

if __name__ == "__main__":
    gui = MainWindow()
    gui.run()
