"""
权限策略检查器
"""

from typing import Any
import yaml

from src.rules.tool_classifier import classify_tool


class PermissionChecker:
    """
    权限策略检查器

    检查工具是否在允许列表中（白名单/黑名单）。
    """

    def __init__(self, policy_path: str):
        """
        初始化权限检查器

        Args:
            policy_path: 权限策略配置路径（YAML格式）
        """
        self.policy = self._load_policy(policy_path)
        
        # 加载工具风险等级配置
        self.tool_risk_levels = self.policy.get("tool_risk_levels", {})
        
        # 加载风险阈值配置
        self.risk_thresholds = self.policy.get("risk_thresholds", {})

    def _load_policy(self, path: str) -> dict[str, Any]:
        """加载权限策略"""
        try:
            with open(path, "r", encoding="utf-8") as f:
                policy = yaml.safe_load(f)
            return policy if policy else {}
        except FileNotFoundError:
            print(f"警告: 权限策略文件不存在: {path}")
            return {}
        except Exception as e:
            print(f"警告: 加载权限策略失败: {e}")
            return {}

    def check(self, tool_name: str) -> dict[str, Any]:
        """
        检查工具是否允许

        Args:
            tool_name: 工具名称

        Returns:
            {
                "allowed": bool,
                "blocked": bool (是否应该阻断),
                "reason": str (如果不允许),
                "risk": str,
                "risk_note": str (风险标记，用于后续评分)
            }
        """
        # 检查黑名单
        forbidden_tools = self.policy.get("forbidden_tools", [])
        if tool_name in forbidden_tools:
            return {
                "allowed": False,
                "blocked": True,  # 黑名单工具直接阻断
                "reason": f"工具 {tool_name} 在黑名单中",
                "risk": "critical",
                "risk_note": f"工具 {tool_name} 被明确禁止"
            }

        # 检查白名单
        allowed_tools = self.policy.get("allowed_tools", [])
        if allowed_tools and tool_name not in allowed_tools:
            # 不在白名单中，优先使用 YAML 配置的风险等级，否则使用 tool_classifier 动态评估
            if tool_name in self.tool_risk_levels:
                risk = self.tool_risk_levels[tool_name]
                risk_note = f"工具 {tool_name} 未在白名单中配置，YAML 配置风险等级为 {risk}"
            else:
                classification = classify_tool(tool_name)
                risk = classification.risk
                risk_note = f"工具 {tool_name} 未在白名单中配置，动态分类为 {classification.risk} 风险：{classification.description}"
            
            return {
                "allowed": True,  # 允许，但标记风险
                "blocked": False,
                "reason": f"工具 {tool_name} 不在白名单中",
                "risk": risk,
                "risk_note": risk_note
            }

        # 通过检查
        return {
            "allowed": True,
            "blocked": False,
            "risk_note": None
        }
