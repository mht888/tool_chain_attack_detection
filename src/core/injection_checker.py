"""
参数注入检查器
"""

import re
from typing import Any
import yaml

from src.rules.injection_patterns import INJECTION_PATTERNS


class InjectionChecker:
    """
    参数注入检查器

    检测工具参数中是否包含注入攻击（SQL注入、命令注入等）。
    支持递归检查嵌套参数。
    对高风险工具进行参数白名单检查。
    """

    # 需要参数白名单检查的高风险工具
    HIGH_RISK_TOOLS = {"http_request", "write_file", "shell"}

    def __init__(self, whitelist_path: str = "src/rules/param_whitelist.yaml"):
        """初始化注入检查器"""
        self.patterns = INJECTION_PATTERNS
        self.whitelist = self._load_whitelist(whitelist_path)

    def _load_whitelist(self, path: str) -> dict[str, Any]:
        """加载参数白名单"""
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            return data.get("param_whitelist", {}) if data else {}
        except FileNotFoundError:
            print(f"警告: 参数白名单文件不存在: {path}")
            return {}
        except Exception as e:
            print(f"警告: 加载参数白名单失败: {e}")
            return {}

    def _extract_strings(self, value: Any) -> list[tuple[str, str]]:
        """
        递归提取所有字符串值

        Args:
            value: 任意类型的值

        Returns:
            [(param_path, string_value), ...]
        """
        results = []
        
        if isinstance(value, str):
            results.append(("", value))
        elif isinstance(value, dict):
            for key, val in value.items():
                nested = self._extract_strings(val)
                for path, s in nested:
                    results.append((f"{key}{path}", s))
        elif isinstance(value, list):
            for i, item in enumerate(value):
                nested = self._extract_strings(item)
                for path, s in nested:
                    results.append((f"[{i}]{path}", s))
        
        return results

    def _match_pattern(self, value: str, pattern: str) -> bool:
        """
        匹配模式（支持通配符 *）

        Args:
            value: 待匹配的值
            pattern: 模式（支持 * 通配符）

        Returns:
            是否匹配
        """
        # 将通配符转换为正则
        regex_pattern = pattern.replace("*", ".*")
        return bool(re.match(f"^{regex_pattern}$", value, re.IGNORECASE))

    def _check_whitelist(self, tool_name: str, arguments: dict[str, Any]) -> tuple[bool, str]:
        """
        检查参数是否在白名单中

        Args:
            tool_name: 工具名称
            arguments: 工具参数

        Returns:
            (is_compliant, reason)
        """
        if tool_name not in self.HIGH_RISK_TOOLS:
            return True, "非高风险工具，无需白名单检查"
        
        tool_whitelist = self.whitelist.get(tool_name, {})
        if not tool_whitelist:
            # 没有配置白名单，视为不合规
            return False, f"工具 {tool_name} 未配置参数白名单"
        
        # 根据工具类型检查对应的参数
        if tool_name == "http_request":
            url = arguments.get("url", "")
            patterns = tool_whitelist.get("url_patterns", [])
            for pattern in patterns:
                if self._match_pattern(url, pattern):
                    return True, f"URL {url} 匹配白名单模式 {pattern}"
            return False, f"URL {url} 不在白名单中"
        
        elif tool_name == "write_file":
            path = arguments.get("path", "")
            patterns = tool_whitelist.get("path_patterns", [])
            for pattern in patterns:
                if self._match_pattern(path, pattern):
                    return True, f"路径 {path} 匹配白名单模式 {pattern}"
            return False, f"路径 {path} 不在白名单中"
        
        elif tool_name == "shell":
            command = arguments.get("command", "")
            patterns = tool_whitelist.get("command_patterns", [])
            for pattern in patterns:
                if self._match_pattern(command, pattern):
                    return True, f"命令 {command} 匹配白名单模式 {pattern}"
            return False, f"命令 {command} 不在白名单中"
        
        return False, "未知高风险工具"

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
                "malicious_param": str (恶意参数),
                "risk": str,
                "param_compliant": bool (参数是否在白名单中),
                "whitelist_reason": str (白名单检查结果原因)
            }
        """
        # 1. 递归提取所有字符串值
        all_strings = self._extract_strings(arguments)
        
        # 2. 检查注入模式
        for param_path, param_value in all_strings:
            for attack_type, patterns in self.patterns.items():
                for pattern in patterns:
                    if re.search(pattern, param_value, re.IGNORECASE):
                        return {
                            "detected": True,
                            "attack_type": attack_type,
                            "pattern": pattern,
                            "malicious_param": f"{param_path}={param_value}",
                            "risk": "critical",
                            "param_compliant": False,
                            "whitelist_reason": "检测到注入攻击"
                        }

        # 3. 检查参数白名单（仅高风险工具）
        if tool_name in self.HIGH_RISK_TOOLS:
            is_compliant, reason = self._check_whitelist(tool_name, arguments)
            return {
                "detected": False,
                "param_compliant": is_compliant,
                "whitelist_reason": reason
            }

        # 4. 未检测到注入，非高风险工具
        return {
            "detected": False,
            "param_compliant": True,
            "whitelist_reason": "非高风险工具"
        }
