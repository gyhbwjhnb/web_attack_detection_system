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
from common.config import UI_CONFIG, SEVERITY_LEVELS, ATTACK_TYPES, ANOMALY_CONFIG, CAPTURE_CONFIG, WHITELIST_IPS
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
        self._total_traffic_received = 0    # 不受上限限制的总计数
        self._total_alerts_received = 0     # 不受上限限制的总计数
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

        # ---- 告警处理状态 ----
        self._alert_states: Dict[str, dict] = {}  # alert_id -> {"status": "待处理", "note": ""}

        # ---- 回调 ----
        self._on_start: Optional[Callable[[], None]] = None
        self._on_stop: Optional[Callable[[], None]] = None
        self._import_rules_callback: Optional[Callable[[str], None]] = None
        self._on_alert_ignored: Optional[Callable[[dict], None]] = None

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
        file_menu.add_command(label="导出报告 HTML...", command=self._export_report_html)
        file_menu.add_separator()
        file_menu.add_command(label="清空告警列表", command=self._clear_alerts)
        file_menu.add_command(label="清空流量列表", command=self._clear_traffic)
        file_menu.add_separator()
        file_menu.add_command(label="退出", command=self._on_close)
        menubar.add_cascade(label="文件", menu=file_menu)

        # 配置菜单
        config_menu = tk.Menu(menubar, tearoff=0)
        config_menu.add_command(label="检测阈值设置...", command=self._open_config_dialog)
        config_menu.add_command(label="白名单管理...", command=self._open_whitelist_dialog)
        config_menu.add_separator()
        config_menu.add_command(label="导入自定义规则...", command=self._on_import_rules)
        menubar.add_cascade(label="配置", menu=config_menu)

        # 帮助菜单
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="使用帮助", command=self._open_help_dialog)
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

        self._btn_import_rules = ttk.Button(control_frame, text="📂 导入规则", command=self._on_import_rules)
        self._btn_import_rules.pack(side=tk.LEFT, padx=4)

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

        columns = ("id", "time", "type", "severity", "src", "dst", "description", "status", "note")
        self._tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")

        self._tree.heading("id", text="ID")
        self._tree.heading("time", text="时间")
        self._tree.heading("type", text="攻击类型")
        self._tree.heading("severity", text="等级")
        self._tree.heading("src", text="来源")
        self._tree.heading("dst", text="目标")
        self._tree.heading("description", text="描述")
        self._tree.heading("status", text="状态")
        self._tree.heading("note", text="备注")

        self._tree.column("id", width=65, minwidth=55)
        self._tree.column("time", width=120, minwidth=90)
        self._tree.column("type", width=90, minwidth=70)
        self._tree.column("severity", width=45, minwidth=40)
        self._tree.column("src", width=140, minwidth=100)
        self._tree.column("dst", width=140, minwidth=100)
        self._tree.column("description", width=220, minwidth=120)
        self._tree.column("status", width=60, minwidth=55)
        self._tree.column("note", width=100, minwidth=60)

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

        # 右键菜单
        self._tree.bind("<Button-3>", self._on_alert_right_click)
        if sys.platform == "darwin":
            self._tree.bind("<Button-2>", self._on_alert_right_click)

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
        """订阅 MessageBus 事件，全部通过 root.after(0) 调度到主线程，
        确保 yview() / insert / delete 等 GUI 操作在正确的线程执行。"""
        message_bus.subscribe(
            message_bus.EVENT_SIGNATURE_ALERT,
            lambda a: self._root.after(0, self.add_alert, a))
        message_bus.subscribe(
            message_bus.EVENT_ANOMALY_ALERT,
            lambda a: self._root.after(0, self.add_alert, a))
        message_bus.subscribe(
            message_bus.EVENT_TRAFFIC_RECORD,
            lambda r: self._root.after(0, self.add_traffic_record, r))
        message_bus.subscribe(
            message_bus.EVENT_STATISTICS,
            lambda s: self._root.after(0, self.update_statistics, s))

    def _is_tree_at_bottom(self, tree) -> bool:
        """检查 treeview 是否滚动到最底部（最后一个 item 完全可见）。
        
        用 bbox 检查比 yview()[1] >= 0.99 更可靠：
        - 少量数据时 yview()[1] 始终为 1.0 导致误判
        - bbox 直接检查最后一个 item 的像素位置
        """
        children = tree.get_children()
        if not children:
            return True
        bbox = tree.bbox(children[-1])
        # bbox 在 item 未渲染时为 "" 或 None
        if not bbox:
            return False
        tree_height = tree.winfo_height()
        return bbox[1] + bbox[3] <= tree_height + 2  # 2px 容差

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
        self._total_alerts_received += 1

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
        """将一条告警插入树表格（仅底部时跟随滚动）"""
        # 插入前：检查用户是否在底部（通过 bbox 精确判断）
        at_bottom = self._is_tree_at_bottom(self._tree)

        # 初始状态
        state = self._alert_states.setdefault(alert.alert_id, {"status": "待处理", "note": ""})

        ts = time.strftime("%H:%M:%S", time.localtime(alert.timestamp))
        severity_name = SEVERITY_LEVELS.get(alert.severity.value, {}).get("name", str(alert.severity.value))
        tag = SEVERITY_TAGS.get(alert.severity.value, "")

        src = f"{alert.src_ip}:{alert.src_port}" if alert.src_port else alert.src_ip
        dst = f"{alert.dst_ip}:{alert.dst_port}" if alert.dst_port else alert.dst_ip

        self._tree.insert("", "end", values=(
            alert.alert_id[:8],
            ts,
            alert.attack_name or alert.attack_type,
            severity_name,
            src,
            dst,
            alert.title or alert.description[:60],
            state["status"],
            state["note"],
        ), tags=(tag,))

        # 超出上限删最旧行
        children = self._tree.get_children()
        if len(children) > self._max_alerts:
            self._tree.delete(children[0])

        # 仅在用户处于底部时才跟随最新
        if at_bottom:
            children = self._tree.get_children()
            if children:
                self._tree.see(children[-1])

    def add_traffic_record(self, record: TrafficRecord):
        """接收 TrafficRecord 并添加到流量列表"""
        self._records.append(record)
        self._total_traffic_received += 1

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
        """将一条流量记录插入树表格（仅底部时跟随滚动）"""
        # 插入前：检查用户是否在底部（通过 bbox 精确判断）
        at_bottom = self._is_tree_at_bottom(self._traffic_tree)

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
        self._traffic_tree.insert("", "end", values=(
            idx, ts, proto, src, dst, info,
        ), tags=(tag,))

        # 超出上限删最旧行
        children = self._traffic_tree.get_children()
        if len(children) > self._max_records:
            self._traffic_tree.delete(children[0])

        # 仅在用户处于底部时才跟随最新
        if at_bottom:
            children = self._traffic_tree.get_children()
            if children:
                self._traffic_tree.see(children[-1])

    def update_statistics(self, stats: dict):
        """更新统计面板"""
        self._stats = stats

    def set_on_start(self, callback: Callable[[], None]):
        """注册启动回调"""
        self._on_start = callback

    def set_on_stop(self, callback: Callable[[], None]):
        """注册停止回调"""
        self._on_stop = callback

    def set_on_import_rules(self, callback: Callable[[str], None]):
        """注册导入规则回调（参数为所选 JSON 文件路径）"""
        self._import_rules_callback = callback

    def set_on_alert_ignored(self, callback: Callable[[dict], None]):
        """注册告警忽略回调（用户标记误报时触发，参数为 alert 摘要 dict）"""
        self._on_alert_ignored = callback

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

    def _on_import_rules(self):
        """打开文件对话框导入自定义规则"""
        file_path = filedialog.askopenfilename(
            title="导入自定义规则文件",
            filetypes=[("JSON 规则文件", "*.json"), ("所有文件", "*.*")],
        )
        if not file_path:
            return  # 用户取消

        if self._import_rules_callback:
            try:
                self._import_rules_callback(file_path)
                messagebox.showinfo("导入成功", f"规则文件已导入:\n{file_path}")
            except Exception as e:
                messagebox.showerror("导入失败", f"导入规则时出错:\n{e}")
        else:
            messagebox.showwarning("未就绪", "检测引擎未初始化，请先启动系统。")

    def _on_btn_reset(self):
        """重置统计"""
        if messagebox.askyesno("确认", "确定要清空所有告警、流量并重置统计吗？"):
            self._clear_alerts()
            self._clear_traffic()
            self._alerts.clear()
            self._records.clear()
            self._total_alerts_received = 0
            self._total_traffic_received = 0
            self._alert_states.clear()
            self._stats = {}
            # 通知后台引擎一起重置
            message_bus.publish(message_bus.EVENT_CONFIG_CHANGE, {"action": "reset"})
            # 立刻刷新界面，不等下一轮定时器
            self._refresh_stats()
            self._status_text.set("统计已重置")
            logger.info("统计已重置")

    # ==================== 告警右键菜单 ====================

    def _on_alert_right_click(self, event):
        """右键菜单：修改状态 / 编辑备注"""
        row_id = self._tree.identify_row(event.y)
        if not row_id:
            return

        self._tree.selection_set(row_id)
        values = self._tree.item(row_id, "values")
        if not values:
            return

        alert_id_full = self._get_full_alert_id_from_row(values)

        menu = tk.Menu(self._root, tearoff=0)

        status_menu = tk.Menu(menu, tearoff=0)
        current_status = self._alert_states.get(alert_id_full, {}).get("status", "待处理")
        for s in ("待处理", "已确认", "误报", "已忽略"):
            if s == current_status:
                status_menu.add_command(label=f"✓ {s}")
            else:
                status_menu.add_command(
                    label=s,
                    command=lambda sid=alert_id_full, st=s: self._set_alert_status(sid, st, row_id),
                )

        menu.add_cascade(label="修改状态", menu=status_menu)
        menu.add_command(
            label="编辑备注...",
            command=lambda: self._edit_alert_note(alert_id_full, row_id),
        )
        menu.add_separator()
        menu.add_command(label="取消", command=lambda: None)

        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _set_alert_status(self, alert_id: str, status: str, row_id: str):
        """修改一条告警的状态"""
        if alert_id not in self._alert_states:
            self._alert_states[alert_id] = {"status": "待处理", "note": ""}
        self._alert_states[alert_id]["status"] = status

        # 更新表格显示
        if self._tree.exists(row_id):
            values = list(self._tree.item(row_id, "values"))
            values[7] = status
            self._tree.item(row_id, values=values)

        self._status_text.set(f"告警状态已更新: {status}")
        logger.info(f"告警 {alert_id[:8]} 状态 → {status}")

        # ★ 用户标记误报/已忽略 → 通知自学习抑制器
        if status in ("误报", "已忽略") and self._on_alert_ignored:
            try:
                alert_data = self._alert_states.get(alert_id, {})
                self._on_alert_ignored({
                    "alert_id": alert_id,
                    "src_ip": values[4] if len(values) > 4 else "",
                    "attack_type": values[2] if len(values) > 2 else "",
                    "dst_port": int(values[6]) if len(values) > 6 and values[6].isdigit() else 0,
                    "status": status,
                    "timestamp": time.time(),
                })
            except Exception:
                pass  # 静默，不影响主流程

    def _edit_alert_note(self, alert_id: str, row_id: str):
        """弹窗编辑告警备注"""
        if alert_id not in self._alert_states:
            self._alert_states[alert_id] = {"status": "待处理", "note": ""}

        current_note = self._alert_states[alert_id].get("note", "")

        dialog = tk.Toplevel(self._root)
        dialog.title("编辑告警备注")
        dialog.geometry("400x200")
        dialog.transient(self._root)
        dialog.grab_set()

        ttk.Label(dialog, text="备注内容:", padding=(8, 4)).pack(anchor=tk.W)

        text = tk.Text(dialog, width=45, height=6, font=("", 10))
        text.insert("1.0", current_note)
        text.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill=tk.X, padx=8, pady=(0, 8))

        def save():
            note = text.get("1.0", "end-1c").strip()
            self._alert_states[alert_id]["note"] = note
            if self._tree.exists(row_id):
                values = list(self._tree.item(row_id, "values"))
                values[8] = note[:50]
                self._tree.item(row_id, values=values)
            self._status_text.set("备注已保存")
            dialog.destroy()

        ttk.Button(btn_frame, text="保存", command=save).pack(side=tk.RIGHT, padx=4)
        ttk.Button(btn_frame, text="取消", command=dialog.destroy).pack(side=tk.RIGHT, padx=4)

    def _get_full_alert_id_from_row(self, values: tuple) -> str:
        """从表格行值反查完整 alert_id"""
        id_prefix = values[0]
        for a in self._alerts:
            if a.alert_id.startswith(id_prefix):
                return a.alert_id
        return id_prefix

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

    def _export_report_html(self):
        """导出美观的 HTML 分析报告"""
        if not self._alerts and not self._stats:
            messagebox.showinfo("提示", "无数据可导出")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML 文件", "*.html")],
            initialfile="detection_report.html",
        )
        if not path:
            return

        try:
            html = self._generate_html_report()
            with open(path, "w", encoding="utf-8") as f:
                f.write(html)
            self._status_text.set(f"报告已导出: {os.path.basename(path)}")
            messagebox.showinfo("成功", f"HTML 报告已导出到:\n{path}")
            logger.info(f"HTML 报告导出: {path}")
        except Exception as e:
            messagebox.showerror("错误", f"导出失败: {e}")

    def _generate_html_report(self) -> str:
        """生成美观的 HTML 分析报告（内嵌 CSS，无外部依赖）"""
        now = time.strftime("%Y-%m-%d %H:%M:%S")

        # ---- 统计计算 ----
        total_alerts = len(self._alerts)
        total_traffic = len(self._records)
        severity_count = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
        type_count: Dict[str, int] = {}
        status_count = {"待处理": 0, "已确认": 0, "误报": 0, "已忽略": 0}
        for a in self._alerts:
            sev = a.severity.value
            if sev in severity_count:
                severity_count[sev] += 1
            atype = a.attack_name or a.attack_type or "未知"
            type_count[atype] = type_count.get(atype, 0) + 1
            aid = a.alert_id
            st = self._alert_states.get(aid, {}).get("status", "待处理")
            status_count[st] = status_count.get(st, 0) + 1

        # 最高严重度
        max_severity = 0
        for sev in (5, 4, 3, 2, 1):
            if severity_count.get(sev, 0) > 0:
                max_severity = sev
                break
        sev_names = {1: "信息", 2: "低危", 3: "中危", 4: "高危", 5: "严重"}
        sev_icon = {5: "🔴", 4: "🟠", 3: "🟡", 2: "🟢", 1: "🔵"}
        if max_severity == 0:
            conclusion_text = "✅ 系统运行正常，未检测到攻击行为"
            conclusion_class = "clean"
        elif max_severity >= 4:
            conclusion_text = f"⚠️ 检测到 {severity_count.get(max_severity, 0)} 条{sev_names.get(max_severity, '')}级别告警，建议立即处理"
            conclusion_class = "danger"
        else:
            conclusion_text = f"ℹ️ 检测到 {severity_count.get(max_severity, 0)} 条{sev_names.get(max_severity, '')}级别告警，请关注"
            conclusion_class = "warning"

        # 攻击类型摘要
        type_summary_parts = []
        for t, c in sorted(type_count.items(), key=lambda x: -x[1])[:5]:
            type_summary_parts.append(f"{t}({c}条)")
        type_summary = "、".join(type_summary_parts) if type_summary_parts else "无"

        # ---- 流量协议分布 ----
        proto_dist: Dict[str, int] = {}
        for r in self._records[-2000:]:
            p = r.protocol.value if hasattr(r, 'protocol') and r.protocol else "?"
            proto_dist[p] = proto_dist.get(p, 0) + 1

        # 协议颜色映射
        proto_colors = {
            "TCP": "#1890ff", "UDP": "#52c41a", "HTTP": "#fa8c16",
            "HTTPS": "#13c2c2", "DNS": "#722ed1", "TLS": "#eb2f96",
            "ICMP": "#f5222d", "ARP": "#faad14", "SSH": "#0958d9",
            "FTP": "#d48806", "SMTP": "#cf1322", "MYSQL": "#1677ff",
            "REDIS": "#f5222d", "MONGODB": "#52c41a",
        }

        # ---- 告警表格行 ----
        alert_rows = ""
        for a in self._alerts[-200:]:
            ts = time.strftime("%H:%M:%S", time.localtime(a.timestamp))
            sev_name = sev_names.get(a.severity.value, "未知")
            sev_cls = {5: "sev-critical", 4: "sev-high", 3: "sev-medium", 2: "sev-low", 1: "sev-info"}.get(a.severity.value, "")
            atype = a.attack_name or a.attack_type or "?"
            src = f"{a.src_ip}:{a.src_port}" if a.src_port else a.src_ip
            dst = f"{a.dst_ip}:{a.dst_port}" if a.dst_port else a.dst_ip
            state = self._alert_states.get(a.alert_id, {}).get("status", "待处理")
            state_cls = {"待处理": "state-pending", "已确认": "state-confirmed",
                         "误报": "state-fp", "已忽略": "state-ignored"}.get(state, "")
            alert_rows += f"""<tr>
                <td><code>{a.alert_id[:8]}</code></td>
                <td>{ts}</td>
                <td><span class="attack-tag">{atype}</span></td>
                <td><span class="sev-badge {sev_cls}">{sev_name}</span></td>
                <td>{src}</td>
                <td>{dst}</td>
                <td class="desc-cell" title="{a.title or ''}">{a.title or '-'}</td>
                <td><span class="state-badge {state_cls}">{state}</span></td>
            </tr>"""

        # ---- 流量协议表格行 ----
        proto_table_rows = ""
        if proto_dist:
            for p, c in sorted(proto_dist.items(), key=lambda x: -x[1])[:12]:
                pct = c * 100 / max(total_traffic, 1)
                color = proto_colors.get(p.upper(), "#8c8c8c")
                proto_table_rows += f"""<tr>
                    <td><span class="proto-dot" style="background:{color}"></span>{p}</td>
                    <td>{c}</td>
                    <td>{pct:.1f}%</td>
                    <td><div class="mini-bar"><div class="mini-fill" style="width:{pct}%;background:{color}"></div></div></td>
                </tr>"""

        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>网络安全检测报告 - {now}</title>
<style>
  /* ===== Reset & Base ===== */
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: 'Microsoft YaHei', -apple-system, 'Segoe UI', Arial, sans-serif;
    background: #f0f2f5; color: #1f2937; margin: 0; padding: 24px; line-height: 1.6;
  }}
  .container {{ max-width: 1140px; margin: 0 auto; }}

  /* ===== Header ===== */
  .header {{
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #334155 100%);
    color: #fff; padding: 32px 36px; border-radius: 12px; margin-bottom: 24px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.15);
  }}
  .header h1 {{ margin: 0; font-size: 26px; font-weight: 700; letter-spacing: 1px; }}
  .header h1 span {{ color: #60a5fa; }}
  .header .sub {{ margin: 10px 0 0; opacity: 0.75; font-size: 14px; display: flex; flex-wrap: wrap; gap: 8px 20px; }}
  .header .sub-item {{ display: inline-flex; align-items: center; gap: 4px; }}

  /* ===== Overview Cards ===== */
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }}
  .card {{
    background: #fff; padding: 22px 16px; border-radius: 10px;
    box-shadow: 0 1px 4px rgba(0,0,0,0.06); text-align: center;
    transition: transform 0.15s, box-shadow 0.15s;
    border-top: 3px solid #d9d9d9;
  }}
  .card:hover {{ transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,0,0,0.1); }}
  .card .num {{ font-size: 34px; font-weight: 800; margin: 4px 0 0; line-height: 1.2; }}
  .card .label {{ color: #64748b; font-size: 13px; margin-top: 4px; letter-spacing: 0.3px; }}
  .card.card-danger {{ border-top-color: #f5222d; }}
  .card.card-danger .num {{ color: #f5222d; }}
  .card.card-warning {{ border-top-color: #fa8c16; }}
  .card.card-warning .num {{ color: #fa8c16; }}
  .card.card-info {{ border-top-color: #1890ff; }}
  .card.card-info .num {{ color: #1890ff; }}
  .card.card-success {{ border-top-color: #52c41a; }}
  .card.card-success .num {{ color: #52c41a; }}

  /* ===== Sections ===== */
  .section {{
    background: #fff; padding: 24px 28px; border-radius: 10px;
    box-shadow: 0 1px 4px rgba(0,0,0,0.06); margin-bottom: 20px;
  }}
  .section-title {{
    margin: 0 0 16px; font-size: 17px; font-weight: 700;
    border-left: 4px solid #3b82f6; padding-left: 12px; color: #0f172a;
  }}
  .section-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
  @media (max-width: 700px) {{ .section-grid {{ grid-template-columns: 1fr; }} }}

  /* ===== Conclusion ===== */
  .conclusion {{
    display: flex; align-items: center; gap: 10px;
    font-size: 16px; padding: 16px 20px; border-radius: 8px;
    border: 1px solid #ffd591; background: #fffbe6;
  }}
  .conclusion.clean {{ border-color: #b7eb8f; background: #f6ffed; }}
  .conclusion.danger {{ border-color: #ffa39e; background: #fff1f0; }}
  .conclusion.warning {{ border-color: #ffe58f; background: #fffbe6; }}
  .conclusion .summary {{ color: #595959; font-size: 13px; margin-top: 4px; }}

  /* ===== Stat Bars ===== */
  .stat-bar {{ display: flex; margin: 8px 0; align-items: center; gap: 0; }}
  .stat-bar .bar-label {{
    width: 100px; min-width: 100px; font-size: 13px; font-weight: 500;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #333;
  }}
  .stat-bar .bar-track {{
    flex: 1; background: #f0f0f0; height: 22px; border-radius: 11px; overflow: hidden; position: relative;
  }}
  .stat-bar .bar-fill {{
    height: 100%; border-radius: 11px; min-width: 24px;
    display: flex; align-items: center; justify-content: flex-end;
    padding-right: 8px; color: #fff; font-size: 11px; font-weight: 600;
    line-height: 22px; transition: width 0.3s;
  }}

  /* ===== Tables ===== */
  .table-wrap {{ overflow-x: auto; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ padding: 10px 8px; border-bottom: 1px solid #f0f0f0; text-align: left; vertical-align: middle; }}
  th {{ background: #fafafa; font-weight: 600; color: #475569; font-size: 12px; text-transform: uppercase; letter-spacing: 0.3px; }}
  tr:last-child td {{ border-bottom: none; }}
  tbody tr:hover {{ background: #f0f7ff; }}
  tbody tr:nth-child(even) {{ background: #fafbfc; }}
  tbody tr:nth-child(even):hover {{ background: #f0f7ff; }}
  .desc-cell {{ max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}

  /* ----- Badges ----- */
  .sev-badge {{
    display: inline-block; padding: 2px 10px; border-radius: 10px;
    font-size: 11px; font-weight: 700; letter-spacing: 0.3px;
  }}
  .sev-critical {{ background: #fff1f0; color: #cf1322; border: 1px solid #ffa39e; }}
  .sev-high {{ background: #fff7e6; color: #d46b08; border: 1px solid #ffd591; }}
  .sev-medium {{ background: #fffbe6; color: #d4b106; border: 1px solid #ffe58f; }}
  .sev-low {{ background: #f6ffed; color: #389e0d; border: 1px solid #b7eb8f; }}
  .sev-info {{ background: #e6f7ff; color: #096dd9; border: 1px solid #91d5ff; }}

  .state-badge {{
    display: inline-block; padding: 2px 10px; border-radius: 10px;
    font-size: 11px; font-weight: 600;
  }}
  .state-pending {{ background: #fff1f0; color: #cf1322; }}
  .state-confirmed {{ background: #e6f7ff; color: #096dd9; }}
  .state-fp {{ background: #f6ffed; color: #389e0d; }}
  .state-ignored {{ background: #f5f5f5; color: #8c8c8c; }}

  .attack-tag {{
    display: inline-block; padding: 2px 8px; border-radius: 4px;
    background: #f0f5ff; color: #1d39c4; font-size: 12px;
  }}

  /* ===== Protocol Distribution ===== */
  .proto-table {{ margin-top: 12px; }}
  .proto-table td {{ padding: 6px 8px; }}
  .proto-dot {{ display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 8px; vertical-align: middle; }}
  .mini-bar {{ height: 8px; background: #f0f0f0; border-radius: 4px; overflow: hidden; min-width: 60px; }}
  .mini-fill {{ height: 100%; border-radius: 4px; transition: width 0.3s; }}

  /* ===== Footer ===== */
  .footer {{ text-align: center; color: #94a3b8; font-size: 12px; margin-top: 32px; padding: 16px 0; border-top: 1px solid #e2e8f0; }}

  /* ===== Print ===== */
  @media print {{
    body {{ background: #fff; padding: 0; }}
    .header {{ border-radius: 0; box-shadow: none; }}
    .card, .section {{ box-shadow: none; border: 1px solid #e2e8f0; break-inside: avoid; }}
  }}
</style>
</head>
<body>
<div class="container">

<!-- ==================== HEADER ==================== -->
<div class="header">
  <h1>🛡️ <span>网络攻击检测系统</span> · 分析报告</h1>
  <div class="sub">
    <span class="sub-item">📅 生成时间: {now}</span>
    <span class="sub-item">🔍 检测引擎: 特征匹配 + 异常行为分析</span>
    <span class="sub-item">📊 数据范围: {total_alerts} 条告警 / {total_traffic} 条流量</span>
  </div>
</div>

<!-- ==================== OVERVIEW CARDS ==================== -->
<div class="cards">
  <div class="card {'card-danger' if severity_count.get(5,0) > 0 else 'card-warning' if max_severity >= 4 else 'card-info'}">
    <p class="num">{total_alerts}</p>
    <p class="label">📋 告警总数</p>
  </div>
  <div class="card card-info">
    <p class="num">{total_traffic}</p>
    <p class="label">🌐 流量记录</p>
  </div>
  <div class="card card-danger">
    <p class="num">{severity_count.get(5, 0)}</p>
    <p class="label">🔴 严重告警</p>
  </div>
  <div class="card card-warning">
    <p class="num">{severity_count.get(4, 0)}</p>
    <p class="label">🟠 高危告警</p>
  </div>
  <div class="card card-success">
    <p class="num">{status_count.get("已确认", 0) + status_count.get("误报", 0) + status_count.get("已忽略", 0) if total_alerts > 0 else 0}</p>
    <p class="label">✅ 已处理状态</p>
  </div>
</div>

<!-- ==================== CONCLUSION ==================== -->
<div class="section">
  <h2 class="section-title">检测结论</h2>
  <div class="conclusion {conclusion_class}">
    <div>
      <div><strong>{conclusion_text}</strong></div>
      <div class="summary">
        攻击类型分布：{type_summary}
        {' | 共 ' + str(len(type_count)) + ' 种攻击类型' if type_count else ''}
      </div>
    </div>
  </div>
</div>

<!-- ==================== TWO-COLUMN CHARTS ==================== -->
<div class="section-grid">

  <!-- 攻击类型分布 -->
  <div class="section">
    <h2 class="section-title">🎯 攻击类型分布</h2>
    {''.join(f'''<div class="stat-bar">
      <span class="bar-label" title="{t}">{t}</span>
      <div class="bar-track"><div class="bar-fill" style="width:{max(5, c*100//max(type_count.values(), default=1))}%; background:#f59e0b">{c}</div></div>
    </div>''' for t, c in sorted(type_count.items(), key=lambda x: -x[1])[:8]) or '<div style="color:#999;text-align:center;padding:20px">暂无攻击数据</div>'}
  </div>

  <!-- 严重度分布 -->
  <div class="section">
    <h2 class="section-title">⚠️ 严重度分布</h2>
    {''.join(f'''<div class="stat-bar">
      <span class="bar-label">{sev_icon.get(s, '')} {sev_names[s]}</span>
      <div class="bar-track"><div class="bar-fill" style="width:{max(5, severity_count[s]*100//max(total_alerts, 1))}%; background:{SEVERITY_COLORS.get(s, '#999')}">{severity_count[s]}</div></div>
    </div>''' for s in (5, 4, 3, 2, 1) if severity_count.get(s, 0) > 0) or '<div style="color:#999;text-align:center;padding:20px">暂无告警数据</div>'}
  </div>

</div>

<!-- ==================== ALERT STATUS & PROTOCOL ==================== -->
<div class="section-grid">

  <!-- 告警处理状态 -->
  <div class="section">
    <h2 class="section-title">📌 告警处理状态</h2>
    {''.join(f'''<div class="stat-bar">
      <span class="bar-label">{k}</span>
      <div class="bar-track"><div class="bar-fill" style="width:{max(5, v*100//max(total_alerts, 1))}%; background:{'#ff4d4f' if k == '待处理' else '#1890ff' if k == '已确认' else '#52c41a' if k == '误报' else '#8c8c8c'}">{v}</div></div>
    </div>''' for k, v in sorted(status_count.items(), key=lambda x: -x[1]) if v > 0) or '<div style="color:#999;text-align:center;padding:20px">无数据</div>'}
  </div>

  <!-- 流量协议分布 -->
  <div class="section">
    <h2 class="section-title">📡 流量协议分布</h2>
    <div style="color:#64748b;font-size:12px;margin-bottom:10px">最近 {min(len(self._records), 2000)} 条记录</div>
    {proto_table_rows or '<div style="color:#999;text-align:center;padding:20px">暂无流量数据</div>'}
  </div>

</div>

<!-- ==================== ALERT DETAIL TABLE ==================== -->
<div class="section">
  <h2 class="section-title">📋 告警明细（最近 {min(total_alerts, 200)} 条）</h2>
  <div class="table-wrap">
  <table>
    <thead><tr>
      <th>ID</th><th>时间</th><th>攻击类型</th><th>等级</th><th>来源</th><th>目标</th><th>描述</th><th>状态</th>
    </tr></thead>
    <tbody>{alert_rows or '<tr><td colspan="8" style="text-align:center;color:#999;padding:32px">📭 暂无告警数据</td></tr>'}</tbody>
  </table>
  </div>
</div>

<!-- ==================== FOOTER ==================== -->
<div class="footer">
  <p>🛡️ 网络攻击检测系统 &copy; 2026 &nbsp;|&nbsp; 自动生成，仅供参考 &nbsp;|&nbsp; 生成时间: {now}</p>
</div>

</div>
</body>
</html>"""

    def _clear_alerts(self):
        for item in self._tree.get_children():
            self._tree.delete(item)
        self._alerts.clear()
        self._alert_states.clear()
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

    def _open_whitelist_dialog(self):
        """打开白名单管理弹窗"""
        dialog = tk.Toplevel(self._root)
        dialog.title("白名单管理")
        dialog.geometry("400x400")
        dialog.transient(self._root)
        dialog.grab_set()

        # 说明文字
        ttk.Label(dialog, text="白名单中的 IP 将被所有检测引擎忽略（不产生告警）",
                  padding=(8, 6)).pack(anchor=tk.W)

        # 列表（左侧大框）
        list_frame = ttk.Frame(dialog)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

        listbox = tk.Listbox(list_frame, height=12, font=("Consolas", 10))
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=listbox.yview)
        listbox.configure(yscrollcommand=scrollbar.set)
        listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 填充已有白名单
        for ip in sorted(WHITELIST_IPS):
            listbox.insert(tk.END, ip)

        # 添加区域
        add_frame = ttk.Frame(dialog)
        add_frame.pack(fill=tk.X, padx=8, pady=4)

        ttk.Label(add_frame, text="IP 地址:").pack(side=tk.LEFT, padx=(0, 4))
        ip_entry = ttk.Entry(add_frame, width=20)
        ip_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 4))

        def add_ip():
            ip = ip_entry.get().strip()
            if not ip:
                return
            if ip in WHITELIST_IPS:
                self._status_text.set(f"IP {ip} 已在白名单中")
                return
            WHITELIST_IPS.append(ip)
            listbox.insert(tk.END, ip)
            ip_entry.delete(0, tk.END)
            self._status_text.set(f"已添加白名单: {ip}")
            logger.info(f"白名单添加: {ip}")

        def delete_ip():
            selection = listbox.curselection()
            if not selection:
                return
            idx = selection[0]
            ip = listbox.get(idx)
            if ip in WHITELIST_IPS:
                WHITELIST_IPS.remove(ip)
            listbox.delete(idx)
            self._status_text.set(f"已移除白名单: {ip}")
            logger.info(f"白名单移除: {ip}")

        ttk.Button(add_frame, text="添加", command=add_ip, width=6).pack(side=tk.LEFT, padx=2)
        ttk.Button(add_frame, text="删除选中", command=delete_ip, width=8).pack(side=tk.LEFT, padx=2)

        # IP 也可以从 GUI 已知 IP 中快速选择
        if self._known_ips:
            quick_frame = ttk.Frame(dialog)
            quick_frame.pack(fill=tk.X, padx=8, pady=(8, 4))
            ttk.Label(quick_frame, text="快速添加（已出现在流量中）:").pack(anchor=tk.W)

            # 过滤掉已经在白名单中的
            candidates = sorted(self._known_ips - set(WHITELIST_IPS))
            if candidates:
                quick_var = tk.StringVar()
                quick_cb = ttk.Combobox(quick_frame, textvariable=quick_var,
                                        values=candidates, width=18, state="readonly")
                quick_cb.pack(side=tk.LEFT, padx=(0, 4))

                def quick_add():
                    ip = quick_var.get()
                    if ip and ip not in WHITELIST_IPS:
                        WHITELIST_IPS.append(ip)
                        listbox.insert(tk.END, ip)
                        quick_cb["values"] = sorted(self._known_ips - set(WHITELIST_IPS))
                        self._status_text.set(f"已添加白名单: {ip}")
                        logger.info(f"白名单添加: {ip}")

                ttk.Button(quick_frame, text="加入白名单", command=quick_add, width=10).pack(side=tk.LEFT)
            else:
                ttk.Label(quick_frame, text="（所有已知 IP 已在白名单中）", foreground="#999").pack(anchor=tk.W)

        # 关闭按钮
        ttk.Button(dialog, text="关闭", command=dialog.destroy, width=10).pack(pady=8)

    def _open_help_dialog(self):
        """打开使用帮助弹窗（多标签页）"""
        dialog = tk.Toplevel(self._root)
        dialog.title("使用帮助")
        dialog.geometry("600x480")
        dialog.transient(self._root)
        dialog.grab_set()

        notebook = ttk.Notebook(dialog)
        notebook.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # ---- Tab 1: 快速开始 ----
        tab1 = ttk.Frame(notebook)
        notebook.add(tab1, text="快速开始")
        t1 = tk.Text(tab1, wrap=tk.WORD, font=("", 10), padx=10, pady=8,
                     relief=tk.FLAT, bg=self._root.cget("bg"))
        t1.pack(fill=tk.BOTH, expand=True)
        t1.insert("1.0", """\
【快速开始】

1. 模拟演示（无需管理员权限）
   python tests/live_demo.py

2. 实时抓包检测（需管理员 + Npcap）
   python main.py --auto

3. 离线 PCAP 分析
   python main.py --pcap 文件路径.pcap --auto

4. 普通 GUI 模式（手动点"开始检测"）
   python main.py

5. 运行集成测试
   python tests/quick_test.py

【环境要求】
- Python 3.8+
- Npcap/WinPcap（Windows 实时抓包需要）
- 无额外 pip 依赖（仅用内置库 tkinter/threading/json）
""")
        t1.configure(state=tk.DISABLED)

        # ---- Tab 2: 界面指南 ----
        tab2 = ttk.Frame(notebook)
        notebook.add(tab2, text="界面指南")
        t2 = tk.Text(tab2, wrap=tk.WORD, font=("", 10), padx=10, pady=8,
                     relief=tk.FLAT, bg=self._root.cget("bg"))
        t2.pack(fill=tk.BOTH, expand=True)
        t2.insert("1.0", """\
【界面布局】

┌─────────────────────────────────────────────┐
│  [▶ 开始检测] [■ 停止检测] [↺ 重置]  ● 状态 │  ← 控制栏
├──────────────────────┬──────────────────────┤
│  ┌ 告警列表 ┐  ┌ 正常流量 ┐  │   统计面板      │
│  │筛选栏    │  │筛选栏    │   │   ● 告警总数    │
│  │IP 类型 端口│  │IP 协议 端口│  │   ● 攻击类型   │
│  │[筛选][清除]│  │[筛选][清除]│  │   ● 严重度分…  │
│  │          │  │          │   │   ● 攻击链     │
│  │  ID 时间  │  │  # 协议   │   │               │
│  │  类型 …   │  │  来源 …   │   │               │
│  └──────────┘  └──────────┘  └───────────────┤
├──────────────────────────────────────────────┤
│  就绪                      运行时间: 00:00:00 │  ← 状态栏
└──────────────────────────────────────────────┘

【告警列表标签页】
- 显示所有检测到的攻击告警（特征匹配 + 异常检测）
- 按严重度着色：蓝(信息) 绿(低) 黄(中) 橙(高) 红(严重)
- 双击某行可查看详细信息
- 右键可标记状态、添加备注

【正常流量标签页】
- 显示所有通过检测的流量记录
- 按协议着色：蓝(TCP) 绿(UDP) 橙(HTTP) 紫(DNS)
- 同样支持 IP/协议/端口组合筛选

【统计面板（右侧）】
- 实时显示告警总数、攻击类型分布、严重度分布
""")
        t2.configure(state=tk.DISABLED)

        # ---- Tab 3: 筛选与标记 ----
        tab3 = ttk.Frame(notebook)
        notebook.add(tab3, text="筛选与标记")
        t3 = tk.Text(tab3, wrap=tk.WORD, font=("", 10), padx=10, pady=8,
                     relief=tk.FLAT, bg=self._root.cget("bg"))
        t3.pack(fill=tk.BOTH, expand=True)
        t3.insert("1.0", """\
【筛选功能】

每个标签页顶部都有筛选栏，三个条件可任意组合：

  IP: [________▼]  类型/协议: [全部 ▼]  端口: [______▼]  [筛选] [清除]

- IP 和端口支持下拉建议（自动收集出现过的值）
- 可手动输入部分匹配
- 点击"清除"恢复显示全部

【告警处理状态】

右键点击告警行 → 弹出菜单：

  ▸ 修改状态  →  待处理 / 已确认 / 误报 / 已忽略
  ▸ 编辑备注... → 弹出文本框输入自由备注

- 状态和备注随告警持久化（运行期间）
- 清空告警列表会同时清空状态
- 导出的 HTML 报告会包含处理状态统计

【滚动行为】
- 滚动条在底部时：新数据自动跟随
- 向上滚动后：停留在当前位置，不受新数据干扰
""")
        t3.configure(state=tk.DISABLED)

        # ---- Tab 4: 白名单与配置 ----
        tab4 = ttk.Frame(notebook)
        notebook.add(tab4, text="白名单与配置")
        t4 = tk.Text(tab4, wrap=tk.WORD, font=("", 10), padx=10, pady=8,
                     relief=tk.FLAT, bg=self._root.cget("bg"))
        t4.pack(fill=tk.BOTH, expand=True)
        t4.insert("1.0", """\
【白名单管理】

菜单：配置 → 白名单管理...

白名单中的 IP 将被所有检测引擎忽略——流量正常统计更新基线，
但不会产生任何告警。

适用场景：
  - 网关/路由器（如 192.168.1.1）
  - DNS 服务器（如 10.0.0.53）
  - 打印机/门禁等物联网设备
  - 已知的安全扫描器 IP

操作方式：
  1. 手动输入 IP → 点击"添加"
  2. 从"快速添加"下拉框选择（已出现在流量中的 IP）
  3. 选中列表项 → "删除选中" 移除

添加/删除即时生效，无需重启检测。

【检测阈值】

菜单：配置 → 检测阈值设置...

可调整各类攻击的检测灵敏度。如果你在真实环境中遇到
大量误报，可以适当调高阈值。

真实环境 vs 测试环境使用不同的默认阈值：
  - main.py 启动：使用高阈值（减少误报）
  - tests/live_demo.py：使用低阈值（方便演示）
""")
        t4.configure(state=tk.DISABLED)

        # ---- Tab 5: 导出报告 ----
        tab5 = ttk.Frame(notebook)
        notebook.add(tab5, text="导出报告")
        t5 = tk.Text(tab5, wrap=tk.WORD, font=("", 10), padx=10, pady=8,
                     relief=tk.FLAT, bg=self._root.cget("bg"))
        t5.pack(fill=tk.BOTH, expand=True)
        t5.insert("1.0", """\
【数据导出】

菜单：文件 →

  ▸ 导出告警 CSV...
     导出告警列表为 CSV 文件（可用 Excel 打开）
     包含：ID、时间、攻击类型、等级、来源/目标、描述、建议

  ▸ 导出告警 TXT...
     导出可读的文本格式日志

  ▸ 导出报告 HTML...
     生成一份完整的分析报告 HTML 文件，包含：
     - 概览卡片（告警总数 / 流量 / 高危数）
     - 检测结论（自动判定最高严重度）
     - 攻击类型分布条形图
     - 严重度分布条形图
     - 告警处理状态统计
     - 流量协议分布
     - 告警明细表（最近 200 条）
     无需外部依赖，浏览器直接打开。

【流量包下载】

双击流量行 → 弹出详情 → 点击"下载"按钮
- 有原始载荷 → 导出为 .bin 二进制文件
- 无载荷 → 导出为 .json 结构化数据

【其他操作】

  ▸ 清空告警列表 — 清除表格显示 + 处理状态
  ▸ 清空流量列表 — 仅清除流量记录
  ▸ ↺ 重置统计 — 同时清空所有数据并通知引擎重置
""")
        t5.configure(state=tk.DISABLED)

        # ---- Tab 6: 自定义规则 ----
        tab6 = ttk.Frame(notebook)
        notebook.add(tab6, text="自定义规则")
        t6 = tk.Text(tab6, wrap=tk.WORD, font=("Consolas", 10), padx=10, pady=8,
                     relief=tk.FLAT, bg=self._root.cget("bg"))
        t6.pack(fill=tk.BOTH, expand=True)
        t6.insert("1.0", """\
【自定义规则指南】

═══════════════════════════════════════════════

  ■ 规则文件位置
    data/rules/  目录下的任意 .json 文件

  ■ 导入方式
    · 菜单"配置 → 导入自定义规则..."选择 .json 文件
    · 或直接复制 .json 文件到 data/rules/ 目录

  ■ 热加载
    放入 data/rules/ 目录的规则文件会在 3 秒内自动生效
    无需重启程序！

═══════════════════════════════════════════════

  ■ 规则 JSON 格式（必需字段）:

  {
    "rule_id":     "CUSTOM-001",
    "attack_name": "SQL注入尝试",
    "attack_type": "sql_injection",
    "pattern":     "(?i)('\\s*or\\s+'|union\\s+select)",
    "severity":    3,
    "description": "检测到SQL注入特征",
    "protocol":    "TCP",
    "dst_port":    80
  }

  ■ 字段说明:
    rule_id     — 唯一标识，建议 CUSTOM-XXX 格式
    attack_name — 告警标题
    attack_type — 攻击分类（自定义或复用已有分类）
    pattern     — 正则表达式（(?i) 表示忽略大小写）
    severity    — 严重度 1-5（1信息 2低 3中 4高 5严重）
    description — 告警详情描述
    protocol    — 协议 TCP/UDP（可选，不填匹配所有）
    dst_port    — 目标端口（可选，不填匹配所有）
    src_port    — 源端口（可选）

  ■ 多条规则格式:
  [
    { "rule_id": "XSS-001", "pattern": "<script>", ... },
    { "rule_id": "SQL-001", "pattern": "union select", ... }
  ]

  ■ 正则示例:
    检测目录遍历:  "(?i)(\\.\\./|\\.\\.\\\\)"
    检测XSS:       "<script[^>]*>.*?</script>"
    检测CVE利用:   "(?i)User-Agent:.*\\$\\(.*\\).*"
    检测一句话木马: "(?<=[a-zA-Z]=)@eval\\(.*\\)"

═══════════════════════════════════════════════

  ■ 验证规则:
    放入文件后 → 观察控制台输出:
    "检测到规则变更，已重新加载 N 条规则"
""")
        t6.configure(state=tk.DISABLED)

        ttk.Button(dialog, text="关闭", command=dialog.destroy, width=10).pack(pady=8)

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
        try:
            idx = int(values[0])
        except (ValueError, TypeError):
            return
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
        self._lbl_total.config(
            text=f"告警: {self._total_alerts_received} | 流量: {self._total_traffic_received}")

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
