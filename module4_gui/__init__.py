"""
模块四：告警输出与图形界面

基于 Tkinter 实现，无需额外安装第三方库。

功能:
  - 实时告警列表（表格，按严重度着色）
  - 统计面板（按攻击类型/严重等级/捕获统计）
  - 控制面板（启动/停止/重置）
  - 状态栏（告警计数 + 运行时间）
  - 配置对话框（可调整检测阈值）
  - 告警日志导出（CSV / TXT）
  - 消息总线自动订阅（接收模块2/3告警）

用法:
    from module4_gui import MainWindow

    gui = MainWindow()
    gui.set_on_start(lambda: capture_engine.start())
    gui.set_on_stop(lambda: capture_engine.stop())
    gui.run()  # 阻塞主循环
"""

from module4_gui.main_window import MainWindow

__all__ = ["MainWindow"]
