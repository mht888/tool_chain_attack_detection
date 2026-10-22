"""
参数注入检查器
"""

import re
from typing import Any

from src.rules.injection_patterns import INJECTION_PATTERNS


class InjectionChecker:
    """
    参数注入检查器

    检测工具参数中是否包含注入攻击（SQL注入、命令注入等）。
    """

    def __init__(self):
        """初始化注入检查器"""
        self.patterns = INJECTION_PATTERNS

    def check(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """
        检查工具参数是否包含注入攻击

        Args:
            tool_name: 工具名称
            arguments: 工具参数

        Returns:
            {
                "detected": bool,
                "attack_type": str (如果检测到),
                "pattern": str (匹配的模式),
                "malicious_param": str (恶意参数)
            }
        """
        for param_name, param_value in arguments.items():
            if not isinstance(param_value, str):
                continue

            for attack_type, patterns in self.patterns.items():
                for pattern in patterns:
                    if re.search(pattern, param_value, re.IGNORECASE):
                        return {
                            "detected": True,
                            "attack_type": attack_type,
                            "pattern": pattern,
                            "malicious_param": f"{param_name}={param_value}",
                            "risk": "critical"
                        }

        # 未检测到注入
        return {"detected": False}
