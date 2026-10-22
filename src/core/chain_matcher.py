"""
链模式匹配器：子序列匹配算法
"""

from typing import Any
import yaml

from src.models.input import ToolCallInput


class ChainMatcher:
    """
    链模式匹配器

    使用子序列匹配算法检测危险的工具调用链。
    不要求工具连续调用，但要求顺序，且中间间隔不超过max_gap。
    """

    def __init__(self, patterns_path: str):
        """
        初始化匹配器

        Args:
            patterns_path: 危险模式库路径（YAML格式）
        """
        self.patterns = self._load_patterns(patterns_path)

    def _load_patterns(self, path: str) -> list[dict[str, Any]]:
        """加载危险模式库"""
        try:
            with open(path, "r", encoding="utf-8") as f:
                patterns = yaml.safe_load(f)
            return patterns if patterns else []
        except FileNotFoundError:
            print(f"警告: 模式库文件不存在: {path}")
            return []
        except Exception as e:
            print(f"警告: 加载模式库失败: {e}")
            return []

    def check(self, buffer: list[ToolCallInput], param_compliant_map: dict[int, bool] = None) -> dict[str, Any]:
        """
        检查buffer中是否包含危险链

        Args:
            buffer: 工具调用历史
            param_compliant_map: buffer索引到参数合规状态的映射

        Returns:
            {
                "matched": bool,
                "pattern": dict (如果匹配),
                "chain": list[str],
                "skipped": bool (是否因参数合规而跳过),
                "skip_reason": str (跳过原因)
            }
        """
        if param_compliant_map is None:
            param_compliant_map = {}
        
        tool_names = [tc.tool_name for tc in buffer]

        for pattern in self.patterns:
            matched_indices = self._subsequence_match_with_indices(tool_names, pattern["tools"])
            if matched_indices:
                # 检查匹配到的工具是否都已参数合规
                all_compliant = all(
                    param_compliant_map.get(idx, False) 
                    for idx in matched_indices
                )
                
                if all_compliant:
                    # 所有相关工具都参数合规，跳过告警
                    return {
                        "matched": False,
                        "skipped": True,
                        "skip_reason": f"链模式 {pattern.get('name', 'unknown')} 匹配，但相关工具参数均合规",
                        "pattern": {
                            "name": pattern.get("name", "unknown"),
                            "tools": pattern["tools"],
                            "risk": pattern.get("risk", "medium"),
                            "description": pattern.get("description", ""),
                            "recommendation": pattern.get("remediation", "")
                        },
                        "chain": tool_names
                    }
                
                return {
                    "matched": True,
                    "skipped": False,
                    "pattern": {
                        "name": pattern.get("name", "unknown"),
                        "tools": pattern["tools"],
                        "risk": pattern.get("risk", "medium"),
                        "description": pattern.get("description", ""),
                        "recommendation": pattern.get("remediation", "")
                    },
                    "chain": tool_names
                }

        return {"matched": False, "skipped": False}

    def _subsequence_match(
        self,
        buffer: list[str],
        pattern: list[str],
        max_gap: int = 5
    ) -> bool:
        """
        子序列匹配算法（核心）

        不要求连续，但要求顺序，且中间间隔不超过max_gap。

        Args:
            buffer: 工具调用序列
            pattern: 危险模式（工具列表）
            max_gap: 最大允许间隔

        Returns:
            是否匹配
        """
        indices = self._subsequence_match_with_indices(buffer, pattern, max_gap)
        return indices is not None

    def _subsequence_match_with_indices(
        self,
        buffer: list[str],
        pattern: list[str],
        max_gap: int = 5
    ) -> list[int] | None:
        """
        子序列匹配算法，返回匹配到的索引列表

        Args:
            buffer: 工具调用序列
            pattern: 危险模式（工具列表）
            max_gap: 最大允许间隔

        Returns:
            匹配到的索引列表，如果未匹配则返回 None
        """
        if len(pattern) == 0:
            return None

        if len(buffer) < len(pattern):
            return None

        # 从每个可能的起始位置尝试匹配
        for start_idx in range(len(buffer)):
            if buffer[start_idx] != pattern[0]:
                continue

            # 从start_idx开始匹配
            indices = self._match_from_position_with_indices(buffer, pattern, start_idx, max_gap)
            if indices:
                return indices

        return None

    def _match_from_position(
        self,
        buffer: list[str],
        pattern: list[str],
        start_idx: int,
        max_gap: int
    ) -> bool:
        """
        从指定位置开始匹配

        Args:
            buffer: 工具调用序列
            pattern: 危险模式
            start_idx: 起始位置
            max_gap: 最大允许间隔（从上一个匹配位置计算）

        Returns:
            是否匹配成功
        """
        indices = self._match_from_position_with_indices(buffer, pattern, start_idx, max_gap)
        return indices is not None

    def _match_from_position_with_indices(
        self,
        buffer: list[str],
        pattern: list[str],
        start_idx: int,
        max_gap: int
    ) -> list[int] | None:
        """
        从指定位置开始匹配，返回匹配到的索引列表

        Args:
            buffer: 工具调用序列
            pattern: 危险模式
            start_idx: 起始位置
            max_gap: 最大允许间隔（从上一个匹配位置计算）

        Returns:
            匹配到的索引列表，如果未匹配则返回 None
        """
        pattern_idx = 0
        last_match = start_idx  # 记录上一个匹配位置
        matched_indices = []

        for i in range(start_idx, len(buffer)):
            if buffer[i] == pattern[pattern_idx]:
                pattern_idx += 1
                last_match = i
                matched_indices.append(i)
                if pattern_idx == len(pattern):
                    return matched_indices  # 完全匹配
            elif i - last_match > max_gap:
                # 从上一个匹配位置计算间隔，超过最大间隔则失败
                break

        return None
