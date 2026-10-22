"""
权限策略检查器
"""

from typing import Any
import yaml


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
                "reason": str (如果不允许),
                "risk": str
            }
        """
        # 检查黑名单
        forbidden_tools = self.policy.get("forbidden_tools", [])
        if tool_name in forbidden_tools:
            return {
                "allowed": False,
                "reason": f"工具 {tool_name} 在黑名单中",
                "risk": "critical"
            }

        # 检查白名单
        allowed_tools = self.policy.get("allowed_tools", [])
        if allowed_tools and tool_name not in allowed_tools:
            return {
                "allowed": False,
                "reason": f"工具 {tool_name} 不在白名单中",
                "risk": "high"
            }

        # 通过检查
        return {"allowed": True}
