"""检查实机抓包环境"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

print("=" * 60)
print("  实机抓包环境检查")
print("=" * 60)

# 1. scapy
try:
    import scapy
    print(f"  [OK] scapy {scapy.__version__}")
except ImportError:
    print("  [FAIL] scapy 未安装 → pip install scapy")
    sys.exit(1)

# 2. Npcap / 网卡
try:
    from scapy.all import get_windows_if_list
    ifaces = get_windows_if_list()
    print(f"  [OK] Npcap 已安装，检测到 {len(ifaces)} 个网卡:")
    for i, iface in enumerate(ifaces[:10]):
        name = iface.get("name", "?")
        desc = iface.get("description", "?")
        ips = iface.get("ips", [])
        print(f"       [{i}] {name}")
        print(f"           描述: {desc}")
        print(f"           IP:   {ips}")
    if len(ifaces) > 10:
        print(f"       ... 共 {len(ifaces)} 个")
except Exception as e:
    print(f"  [FAIL] 获取网卡列表失败: {e}")
    print("  → 是否安装了 Npcap？ https://npcap.com/")

# 3. 权限
import ctypes
is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
if is_admin:
    print("  [OK] 当前以管理员权限运行")
else:
    print("  [WARN] 当前非管理员权限，在线抓包需要管理员运行")

# 4. 自动选网卡测试
print("\n自动选网卡测试:")
try:
    from module1_capture.capture import CaptureEngine
    engine = CaptureEngine(use_message_bus=False)
    iface = engine._auto_select_interface()
    if iface:
        print(f"  [OK] 自动选中: {iface}")
    else:
        print("  [FAIL] 未选中可用网卡")
except Exception as e:
    print(f"  [FAIL] {e}")

print("\n")
if is_admin and iface:
    print("环境就绪！可以运行:")
    print("  python main.py --auto")
else:
    print("操作建议:")
    if not is_admin:
        print("  1. 以管理员身份重新打开终端")
    print("  2. pip install scapy  (如果未安装)")
    print("  3. 安装 Npcap: https://npcap.com/")
    print("  4. 然后运行: python main.py --auto")
