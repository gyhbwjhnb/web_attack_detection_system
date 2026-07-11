"""
公共工具函数
提供日志、配置管理、IP 工具等跨模块共用功能。
"""

import json
import logging
import socket
import struct
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from common.config import PRIVATE_IP_RANGES


# ==================== 日志工具 ====================

def setup_logger(name: str, log_file: Optional[str] = None,
                 level: int = logging.INFO,
                 log_to_console: bool = True) -> logging.Logger:
    """
    创建统一的日志记录器。

    Args:
        name:           日志记录器名称（建议用模块名，如 "module1_capture"）
        log_file:       日志文件路径，为 None 则只输出到控制台
        level:          日志级别
        log_to_console: 是否同时输出到控制台

    Returns:
        logging.Logger 实例

    Usage:
        logger = setup_logger("module1_capture", "logs/capture.log")
        logger.info("抓包模块启动")
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if logger.handlers:
        return logger

    fmt = logging.Formatter(
        "[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(level)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    if log_to_console:
        ch = logging.StreamHandler()
        ch.setLevel(level)
        ch.setFormatter(fmt)
        logger.addHandler(ch)

    return logger


# ==================== 配置管理工具 ====================

class ConfigManager:
    """
    统一的配置文件管理器，从 JSON 文件读取/写入配置。

    Usage:
        config = ConfigManager("config.json")
        interface = config.get("capture.interface", "eth0")
        threshold = config.get("anomaly.port_scan_threshold", 20)
    """

    def __init__(self, config_path: str):
        self._config_path = Path(config_path)
        self._data: dict = {}
        self._load()

    def _load(self):
        if self._config_path.exists():
            try:
                with open(self._config_path, "r", encoding="utf-8") as f:
                    self._data = json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                print(f"[ConfigManager] 加载配置失败: {e}，使用默认配置")
                self._data = {}
        else:
            print(f"[ConfigManager] 配置文件不存在: {self._config_path}，使用默认配置")
            self._data = {}

    def get(self, key: str, default: Any = None) -> Any:
        keys = key.split(".")
        value = self._data
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value

    def set(self, key: str, value: Any):
        keys = key.split(".")
        data = self._data
        for k in keys[:-1]:
            if k not in data:
                data[k] = {}
            data = data[k]
        data[keys[-1]] = value

    def save(self):
        self._config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._config_path, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2, ensure_ascii=False)

    def get_all(self) -> dict:
        return self._data


# ==================== IP 工具函数 ====================

def _ip_to_int(ip: str) -> int:
    """IP 字符串转整数"""
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except OSError:
        return 0


def ip_to_int(ip: str) -> int:
    """IP 字符串转整数（公开接口）"""
    return _ip_to_int(ip)


def is_private_ip(ip: str) -> bool:
    """
    判断是否为内网 IP（统一使用 config.py 中的 PRIVATE_IP_RANGES）。
    """
    ip_int = _ip_to_int(ip)
    if ip_int == 0:
        return False
    for start, end in PRIVATE_IP_RANGES:
        if _ip_to_int(start) <= ip_int <= _ip_to_int(end):
            return True
    return False


# ==================== 时间工具 ====================

def format_timestamp(ts: datetime) -> str:
    """统一的时间戳格式化，如 "2026-07-10 10:30:00.123" """
    return ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


# ==================== 告警 ID 生成器 ====================

class AlertIdGenerator:
    """全局自增告警 ID 生成器"""
    _counter = 0

    @classmethod
    def next_id(cls) -> int:
        cls._counter += 1
        return cls._counter

    @classmethod
    def reset(cls):
        cls._counter = 0
