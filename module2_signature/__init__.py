"""
模块2：特征匹配检测引擎模块

对外提供能力:
    - AhoCorasickMatcher: 多模式匹配器
    - SignatureEngine: 特征匹配检测引擎
    - connect / disconnect: MessageBus 集成函数
"""

from module2_signature.matcher import AhoCorasickMatcher
from module2_signature.signature_engine import SignatureEngine
from module2_signature.integration import connect, disconnect

__all__ = ["AhoCorasickMatcher", "SignatureEngine", "connect", "disconnect"]