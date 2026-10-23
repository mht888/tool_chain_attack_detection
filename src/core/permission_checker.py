"""
权限策略检查器

仅拦截黑名单工具（完全禁止执行，命中即阻断）；
非黑名单工具一律放行，交由注入检查、链模式检查、频率检查进一步检测。
"""

from typing import Any
import yaml


class PermissionChecker:
    """
    权限策略检查器

    黑名单工具直接阻断，其余工具放行。
    """

    def __init__(self, policy_path: str):
        """
        初始化权限检查器

        Args:
            policy_path: 权限策略配置路径（YAML格式）
        """
        self.policy = self._load_policy(policy_path)

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
        # 仅检查黑名单：命中即阻断，不做后续检查
        forbidden_tools = self.policy.get("forbidden_tools", [])
        if tool_name in forbidden_tools:
            return {
                "allowed": False,
                "blocked": True,
                "tool_name": tool_name,
                "reason": f"工具 {tool_name} 在黑名单中",
                "risk": "critical",
                "risk_note": f"工具 {tool_name} 被明确禁止"
            }

        # 非黑名单工具一律放行
        return {
            "allowed": True,
            "blocked": False,
            "tool_name": tool_name,
            "risk_note": None
        }
