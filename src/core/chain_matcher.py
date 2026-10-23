"""
链模式匹配器：能力序列匹配算法

基于工具调用的能力序列检测危险链。
"""

from typing import Any
import yaml

from src.models.input import ToolCallInput


class ChainMatcher:
    """
    链模式匹配器

    使用能力序列匹配算法检测危险的工具调用链。
    不要求工具连续调用，但要求顺序，且中间间隔不超过max_gap。
    """

    def __init__(self, capability_patterns_path: str):
        """
        初始化匹配器

        Args:
            capability_patterns_path: 能力模式库路径（YAML格式）
        """
        self.capability_patterns = self._load_patterns(capability_patterns_path)

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

    def check(
        self,
        buffer: list[ToolCallInput],
        param_risk_map: dict[int, str] = None,
        capabilities_map: dict[int, list[str]] = None
    ) -> dict[str, Any]:
        """
        检查buffer中是否包含危险链

        Args:
            buffer: 工具调用历史
            param_risk_map: buffer索引到参数危险度的映射
            capabilities_map: buffer索引到能力列表的映射

        Returns:
            {
                "matched": bool,
                "capability_patterns": list[dict] (所有匹配的能力模式),
                "chain": list[str],
                "skipped_patterns": list[dict] (因参数低风险而跳过的模式),
            }
        """
        if param_risk_map is None:
            param_risk_map = {}
        if capabilities_map is None:
            capabilities_map = {}
        
        tool_names = [tc.tool_name for tc in buffer]

        # 能力模式匹配
        matched_capability_patterns = []
        skipped_capability_patterns = []

        for pattern in self.capability_patterns:
            required_capabilities = pattern.get("capabilities", [])
            matched_indices = self._capability_match_with_indices(
                capabilities_map, required_capabilities
            )
            if matched_indices:
                # 检查匹配到的工具是否都已参数低风险
                all_low_risk = all(
                    param_risk_map.get(idx, "low") == "low"
                    for idx in matched_indices
                )
                
                pattern_info = {
                    "name": pattern.get("name", "unknown"),
                    "capabilities": required_capabilities,
                    "risk": pattern.get("risk", "medium"),
                    "description": pattern.get("description", ""),
                    "recommendation": pattern.get("remediation", ""),
                    "matched_indices": matched_indices
                }
                
                if all_low_risk:
                    # 所有相关工具都参数低风险，跳过告警
                    skipped_capability_patterns.append(pattern_info)
                else:
                    matched_capability_patterns.append(pattern_info)

        return {
            "matched": len(matched_capability_patterns) > 0,
            "capability_patterns": matched_capability_patterns,
            "chain": tool_names,
            "skipped_patterns": skipped_capability_patterns
        }

    def _capability_match_with_indices(
        self,
        capabilities_map: dict[int, list[str]],
        required_capabilities: list[str],
        max_gap: int = 5
    ) -> list[int] | None:
        """
        能力序列匹配算法，返回匹配到的索引列表

        Args:
            capabilities_map: buffer索引到能力列表的映射
            required_capabilities: 需要的能力序列
            max_gap: 最大允许间隔

        Returns:
            匹配到的索引列表，如果未匹配则返回 None
        """
        if len(required_capabilities) == 0:
            return None

        if len(capabilities_map) == 0:
            return None

        # 获取所有索引并排序
        sorted_indices = sorted(capabilities_map.keys())
        
        # 从每个可能的起始位置尝试匹配
        for start_pos, start_idx in enumerate(sorted_indices):
            # 检查起始索引是否包含第一个需要的能力
            if required_capabilities[0] not in capabilities_map.get(start_idx, []):
                continue

            # 从start_idx开始匹配
            indices = self._match_capabilities_from_position(
                sorted_indices, start_pos, capabilities_map, required_capabilities, max_gap
            )
            if indices:
                return indices

        return None

    def _match_capabilities_from_position(
        self,
        sorted_indices: list[int],
        start_pos: int,
        capabilities_map: dict[int, list[str]],
        required_capabilities: list[str],
        max_gap: int
    ) -> list[int] | None:
        """
        从指定位置开始匹配能力序列

        Args:
            sorted_indices: 排序后的索引列表
            start_pos: 起始位置（在sorted_indices中的位置）
            capabilities_map: buffer索引到能力列表的映射
            required_capabilities: 需要的能力序列
            max_gap: 最大允许间隔

        Returns:
            匹配到的索引列表，如果未匹配则返回 None
        """
        pattern_idx = 0
        last_match_idx = sorted_indices[start_pos]
        matched_indices = []
        used_indices = set()  # 记录已使用的索引，避免同一个工具调用匹配多个能力

        for pos in range(start_pos, len(sorted_indices)):
            idx = sorted_indices[pos]
            
            # 如果这个索引已经被使用过，跳过
            if idx in used_indices:
                continue
            
            tool_capabilities = capabilities_map.get(idx, [])
            
            # 检查当前索引是否包含需要的能力（每个工具调用只匹配一个能力）
            if pattern_idx < len(required_capabilities) and required_capabilities[pattern_idx] in tool_capabilities:
                pattern_idx += 1
                last_match_idx = idx
                matched_indices.append(idx)
                used_indices.add(idx)
                if pattern_idx == len(required_capabilities):
                    return matched_indices  # 完全匹配
            
            # 检查间隔
            if pattern_idx < len(required_capabilities) and idx - last_match_idx > max_gap:
                # 从上一个匹配位置计算间隔，超过最大间隔则失败
                break

        return None
