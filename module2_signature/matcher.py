"""
Aho-Corasick 多模式匹配器 —— 模块2 内部组件

实现高效的多特征串同时匹配:
  - 构建 Trie + Failure Link (BFS)
  - 单次扫描文本即可匹配全部特征串
  - 支持大小写不敏感匹配
  - 支持 URL 解码归一化（对抗 %20 / %27 等绕过）

用法:
    from module2_signature.matcher import AhoCorasickMatcher

    matcher = AhoCorasickMatcher()
    matcher.add_pattern("' or 1=1", rule_id="SQL-001")
    matcher.add_pattern("<script>", rule_id="XSS-001")
    matcher.build()

    results = matcher.search("GET /page?id=' OR 1=1 --")
    # results: [("SQL-001", "' or 1=1", 15), ...]  (rule_id, pattern, position)
"""

from collections import deque
from typing import List, Tuple, Dict, Optional
from urllib.parse import unquote


# 节点定义
class _Node:
    __slots__ = ("children", "fail", "output")

    def __init__(self):
        self.children: Dict[str, "_Node"] = {}
        self.fail: Optional["_Node"] = None
        self.output: List[Tuple[str, str]] = []


class AhoCorasickMatcher:
    """
    Aho-Corasick 多模式匹配器。

    注意事项:
      - 所有模式与文本在匹配前都会被小写化并做 URL 解码，以实现不区分大小写 + 抗绕过。
      - 构建 (build) 之后仍可调用 add_pattern + rebuild，但更推荐一次性添加后构建。
    """

    def __init__(self, case_sensitive: bool = False, url_decode: bool = True):
        self._root = _Node()
        self._built = False
        self._case_sensitive = case_sensitive
        self._url_decode = url_decode
        self._original_patterns: Dict[str, str] = {}  # rule_id -> raw pattern
        self._pattern_count = 0

    # ------------------------------------------------------------------
    # 公开 API
    # ------------------------------------------------------------------

    def add_pattern(self, pattern: str, rule_id: str) -> None:
        """
        添加一条特征串。

        Args:
            pattern: 特征字符串
            rule_id: 关联的规则 ID
        """
        if not pattern:
            return
        norm = self._normalize(pattern)
        if not norm:
            return

        self._original_patterns[rule_id] = pattern

        node = self._root
        for ch in norm:
            if ch not in node.children:
                node.children[ch] = _Node()
            node = node.children[ch]
        node.output.append((rule_id, pattern))
        self._built = False
        self._pattern_count += 1

    def build(self) -> None:
        """构建 Failure 链接（BFS）。添加完所有模式后调用一次。"""
        root = self._root
        root.fail = root
        queue: deque = deque()

        # 深度为 1 的节点 fail 指向 root
        for ch, child in root.children.items():
            child.fail = root
            queue.append(child)

        while queue:
            curr = queue.popleft()
            for ch, child in curr.children.items():
                queue.append(child)
                # 沿 fail 链查找
                fail = curr.fail
                while fail is not root and ch not in fail.children:
                    fail = fail.fail
                child.fail = fail.children.get(ch, root)
                if child.fail is child:
                    child.fail = root
                # 合并 output（字典后缀链接）
                child.output = child.output + child.fail.output

        self._built = True

    def search(self, text: str) -> List[Tuple[str, str, int]]:
        """
        在文本中搜索所有匹配的特征串。

        Returns:
            命中列表，每项为 (rule_id, pattern, position)。
            position 是归一化后文本中匹配起始位置（字符索引）。
        """
        if not self._built:
            self.build()

        norm_text = self._normalize(text)
        if not norm_text:
            return []

        results: List[Tuple[str, str, int]] = []
        node = self._root
        root = self._root

        for i, ch in enumerate(norm_text):
            while node is not root and ch not in node.children:
                assert node.fail is not None  # build() 保证 fail 已设置
                node = node.fail
            node = node.children.get(ch, root)

            # 收集当前节点的全部 output（已在 build 时合并）
            if node.output:
                for rule_id, pattern in node.output:
                    norm_pat = self._normalize(pattern)
                    start = i - len(norm_pat) + 1
                    results.append((rule_id, pattern, max(start, 0)))

        return results

    def search_first(self, text: str) -> Optional[Tuple[str, str, int]]:
        """返回第一个匹配，或 None。"""
        results = self.search(text)
        if not results:
            return None
        results.sort(key=lambda r: (r[2], -len(r[1])))
        return results[0]

    def clear(self) -> None:
        """清空所有模式。"""
        self._root = _Node()
        self._built = False
        self._original_patterns.clear()
        self._pattern_count = 0

    @property
    def pattern_count(self) -> int:
        return self._pattern_count

    # ------------------------------------------------------------------
    # 内部工具
    # ------------------------------------------------------------------

    def _normalize(self, text: str) -> str:
        """归一化：URL 解码 + 小写化（视配置）"""
        if self._url_decode:
            prev = text
            for _ in range(3):
                try:
                    decoded = unquote(prev)
                except Exception:
                    decoded = prev
                if decoded == prev:
                    break
                prev = decoded
            text = prev
        if not self._case_sensitive:
            text = text.lower()
        return text