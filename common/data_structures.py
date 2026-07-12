"""
统一数据模型定义

所有模块间传递的数据必须使用此文件中定义的数据类。

数据流:
    模块1 捕获 → TrafficRecord ──→ 模块2(特征匹配)/模块3(异常检测)
                                        │
                                        ▼
                                     Alert ──→ 模块4(GUI)
                              Baseline ──→ 模块4
                            AttackChain ──→ 模块4
"""

import json
import struct
import socket
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any
from enum import Enum

from common.config import PRIVATE_IP_RANGES


# ==================== 枚举类型 ====================

class ProtocolType(Enum):
    """协议类型"""
    TCP = "TCP"
    UDP = "UDP"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    DNS = "DNS"
    TLS = "TLS"
    ICMP = "ICMP"
    SSH = "SSH"
    FTP = "FTP"
    SMTP = "SMTP"
    UNKNOWN = "UNKNOWN"


class AlertSeverity(Enum):
    """告警危险等级（1-5 对应 SEVERITY_LEVELS）"""
    INFO = 1       # 信息
    LOW = 2        # 低危
    MEDIUM = 3     # 中危
    HIGH = 4       # 高危
    CRITICAL = 5   # 严重


class AlertType(Enum):
    """告警来源"""
    SIGNATURE = "signature"     # 特征匹配（模块2）
    ANOMALY = "anomaly"         # 异常行为（模块3）
    ML = "ml"                   # 机器学习（模块3 扩展）


class AlertStatus(Enum):
    """告警处理状态"""
    NEW = "new"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"
    IGNORED = "ignored"


# ==================== IP 工具函数 ====================

def _ip_to_int(ip: str) -> int:
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except (OSError, struct.error):
        return 0


def is_private_ip(ip: str) -> bool:
    """判断是否为内网 IP"""
    ip_int = _ip_to_int(ip)
    if ip_int == 0:
        return False
    for start, end in PRIVATE_IP_RANGES:
        if _ip_to_int(start) <= ip_int <= _ip_to_int(end):
            return True
    return False


# ==================== IPEndpoint：IP 端点 ====================

@dataclass
class IPEndpoint:
    """IP 端点信息（源/目的统一表示）"""
    ip: str = "0.0.0.0"
    port: int = 0
    mac: str = ""

    @property
    def is_internal(self) -> bool:
        """判断是否为内网 IP"""
        return is_private_ip(self.ip)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["is_internal"] = self.is_internal
        return d


# ==================== TrafficRecord：流量记录 ====================

@dataclass
class TrafficRecord:
    """
    流量记录 —— 模块1 产出，模块2/3 消费。

    每解析完一个数据包/一条流，生成一个 TrafficRecord。
    """
    # --- 基本信息 ---
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: float = field(default_factory=time.time)

    # --- 通信双方 ---
    src: IPEndpoint = field(default_factory=IPEndpoint)
    dst: IPEndpoint = field(default_factory=IPEndpoint)

    # --- 协议 ---
    protocol: ProtocolType = ProtocolType.UNKNOWN
    protocol_detail: str = ""       # 如 "HTTP/1.1", "TLS 1.2"

    # --- 载荷 ---
    payload: str = ""               # 文本载荷（UTF-8 解码）
    payload_raw: bytes = field(default_factory=bytes, repr=False)
    payload_size: int = 0

    # ===== TCP 标志 =====
    flags: int = 0                  # TCP flags 位掩码
    seq_num: int = 0
    ack_num: int = 0

    FLAG_FIN = 0x01
    FLAG_SYN = 0x02
    FLAG_RST = 0x04
    FLAG_PSH = 0x08
    FLAG_ACK = 0x10
    FLAG_URG = 0x20

    def is_syn(self) -> bool:
        return (self.flags & self.FLAG_SYN) != 0

    def is_syn_ack(self) -> bool:
        return (self.flags & (self.FLAG_SYN | self.FLAG_ACK)) == (self.FLAG_SYN | self.FLAG_ACK)

    # ===== HTTP 字段 =====
    http_method: str = ""
    http_uri: str = ""
    http_host: str = ""
    http_user_agent: str = ""
    http_referer: str = ""
    http_status_code: int = 0
    http_headers: Dict[str, str] = field(default_factory=dict)
    http_body: str = ""

    @property
    def http_query_params(self) -> Dict[str, str]:
        """解析 URI 中的 query 参数为 dict"""
        result = {}
        if "?" in self.http_uri:
            qs = self.http_uri.split("?", 1)[1]
            for pair in qs.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    result[k] = v
                else:
                    result[pair] = ""
        return result

    @property
    def all_http_text(self) -> str:
        """返回 HTTP 全部文本内容，方便一次性正则匹配"""
        parts = []
        if self.http_uri:       parts.append(self.http_uri)
        if self.http_body:      parts.append(self.http_body)
        if self.http_referer:   parts.append(self.http_referer)
        if self.http_user_agent: parts.append(self.http_user_agent)
        for k, v in self.http_headers.items():
            parts.append(f"{k}: {v}")
        return "\n".join(parts)

    # ===== DNS 字段 =====
    dns_query: str = ""
    dns_query_type: str = ""
    dns_answers: List[str] = field(default_factory=list)

    # ===== TLS 字段 =====
    tls_version: str = ""
    tls_cipher_suite: str = ""
    tls_sni: str = ""
    tls_ja3_hash: str = ""
    tls_ja3s_hash: str = ""
    tls_is_self_signed: bool = False

    # ===== 流/会话信息 =====
    flow_id: str = ""              # 五元组 hash
    flow_bytes_sent: int = 0
    flow_bytes_received: int = 0
    flow_packet_count: int = 1

    # ===== 元数据 =====
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["protocol"] = self.protocol.value
        d["src"] = self.src.to_dict()
        d["dst"] = self.dst.to_dict()
        d["flags"] = int(self.flags) if hasattr(self.flags, '__int__') else self.flags
        d.pop("payload_raw", None)
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    def __repr__(self):
        return (f"TrafficRecord(id={self.id}, "
                f"{self.src.ip}:{self.src.port} -> {self.dst.ip}:{self.dst.port}, "
                f"{self.protocol.value})")


# 保留 PacketInfo 别名以兼容旧代码
PacketInfo = TrafficRecord


# ==================== Alert：告警记录 ====================

@dataclass
class Alert:
    """
    告警记录 —— 模块2/3 产出，模块4 消费。
    """
    # --- 基本信息 ---
    alert_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: float = field(default_factory=time.time)

    # --- 攻击描述 ---
    attack_type: str = ""           # 攻击标识，如 "sql_injection"（对应 ATTACK_TYPES key）
    attack_name: str = ""           # 显示名称，如 "SQL注入-联合查询"
    severity: AlertSeverity = AlertSeverity.MEDIUM
    confidence: float = 0.0         # 置信度 0.0 ~ 1.0
    status: AlertStatus = AlertStatus.NEW

    # --- 检测来源 ---
    alert_source: AlertType = AlertType.SIGNATURE
    rule_id: str = ""               # 触发的规则 ID

    # --- 网络信息 ---
    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 0
    protocol: str = ""

    # --- 描述信息 ---
    title: str = ""                 # 告警标题（简洁）
    description: str = ""           # 详细描述
    matched_pattern: str = ""       # 匹配到的特征/模式
    payload_snippet: str = ""       # 载荷片段（UI 展示用，截取前 200 字符）
    suggestion: str = ""            # 处理建议

    # --- 关联 ---
    flow_id: str = ""
    traffic_record_id: str = ""
    related_alerts: List[str] = field(default_factory=list)
    attack_chain_id: str = ""

    # --- 标签 ---
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["alert_source"] = self.alert_source.value
        d["status"] = self.status.value
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    def to_csv_line(self) -> str:
        d = self.to_dict()
        return ",".join(str(v) for v in d.values())

    def __repr__(self):
        return (f"Alert(id={self.alert_id}, type={self.attack_type}, "
                f"severity={self.severity.value}, src={self.src_ip})")


# ==================== Baseline：行为基线 ====================

@dataclass
class Baseline:
    """
    主机行为基线 —— 模块3 建立和更新。
    记录一台主机在正常状态下的各项指标。
    """
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    host_ip: str = ""
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    # --- 连接指标 ---
    conn_avg_per_min: float = 0.0
    conn_max_per_min: float = 0.0
    conn_std_per_min: float = 0.0

    # --- 端口指标 ---
    unique_ports: int = 0
    common_ports: List[int] = field(default_factory=list)

    # --- 带宽指标 (bytes/s) ---
    bw_avg: float = 0.0
    bw_max: float = 0.0

    # --- 会话指标 ---
    session_duration_avg: float = 0.0

    # --- 通信关系 ---
    internal_peers: List[str] = field(default_factory=list)
    external_peers: List[str] = field(default_factory=list)
    internal_ratio: float = 0.0

    # --- 统计 ---
    sample_count: int = 0

    def is_established(self) -> bool:
        """基线是否已建立（样本足够）"""
        return self.sample_count >= 100

    def to_dict(self) -> dict:
        return asdict(self)


# ==================== AttackChain：攻击链 ====================

@dataclass
class AttackChain:
    """
    攻击链 —— 模块3 攻击链关联分析的产物。

    将零散的告警串联成完整攻击过程:
      侦察 → 武器化 → 投递 → 利用 → 安装 → C2 → 目标达成
    """
    PHASES = [
        "recon",
        "weaponization",
        "delivery",
        "exploitation",
        "installation",
        "c2",
        "actions",
    ]

    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: float = field(default_factory=time.time)
    title: str = ""
    risk_level: int = 3

    # 每项: {"phase": "exploitation", "timestamp": ..., "alert_id": "...", "description": "..."}
    stages: List[Dict[str, Any]] = field(default_factory=list)

    alert_ids: List[str] = field(default_factory=list)
    involved_ips: List[str] = field(default_factory=list)

    is_complete: bool = False
    description: str = ""

    @property
    def phase_count(self) -> int:
        return len(self.stages)

    @property
    def coverage(self) -> float:
        return self.phase_count / len(self.PHASES)

    def add_stage(self, phase: str, alert_id: str, description: str):
        if phase in self.PHASES:
            self.stages.append({
                "phase": phase,
                "timestamp": time.time(),
                "alert_id": alert_id,
                "description": description,
            })
            if alert_id not in self.alert_ids:
                self.alert_ids.append(alert_id)
        else:
            raise ValueError(f"未知攻击阶段: {phase}，有效值: {self.PHASES}")

    def check_complete(self) -> bool:
        key_phases = {"recon", "exploitation", "c2"}
        covered = {s["phase"] for s in self.stages}
        self.is_complete = len(covered & key_phases) >= 2
        return self.is_complete

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)


# ==================== SignatureRule：攻击特征规则 ====================

@dataclass
class SignatureRule:
    """
    攻击特征规则 —— 模块2 使用
    """
    rule_id: str = ""
    attack_name: str = ""
    attack_type: str = ""
    pattern: str = ""               # 特征串
    severity: int = 3               # 1-5
    description: str = ""
    protocol: str = "ANY"
    dst_port: int = 0

    @classmethod
    def from_dict(cls, data: dict) -> "SignatureRule":
        return cls(
            rule_id=data.get("rule_id", ""),
            attack_name=data.get("attack_name", ""),
            attack_type=data.get("attack_type", ""),
            pattern=data.get("pattern", ""),
            severity=data.get("severity", 3),
            description=data.get("description", ""),
            protocol=data.get("protocol", "ANY"),
            dst_port=data.get("dst_port", 0),
        )
