"""
参数注入检查器 + 参数定级引擎

1. 注入检测：检测工具参数中是否包含注入攻击（SQL注入、命令注入等）
2. 参数定级：根据工具参数值动态定级，支持联合条件
3. 能力标注：根据参数值和注入检测结果标注能力
"""

import re
from typing import Any
import yaml

from src.rules.injection_patterns import INJECTION_PATTERNS


class InjectionChecker:
    """
    参数注入检查器 + 参数定级引擎

    - 注入检测：递归检查所有字符串值是否命中注入模式
    - 参数定级：根据工具参数值动态定级（max 聚合 + 联合条件）
    - 能力标注：根据参数值和注入检测结果标注能力
    """

    def __init__(self, grading_path: str = "src/rules/param_grading.yaml"):
        """初始化注入检查器

        Args:
            grading_path: 参数定级配置路径
        """
        self.patterns = INJECTION_PATTERNS
        self.grading_config = self._load_grading_config(grading_path)

    def _load_grading_config(self, path: str) -> dict[str, Any]:
        """加载参数定级配置"""
        try:
            with open(path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f)
            return config if config else {}
        except FileNotFoundError:
            print(f"警告: 参数定级配置文件不存在: {path}")
            return {}
        except Exception as e:
            print(f"警告: 加载参数定级配置失败: {e}")
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
        regex_pattern = pattern.replace("*", ".*")
        return bool(re.match(f"^{regex_pattern}$", value, re.IGNORECASE))

    def _check_injection(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """
        检查参数是否包含注入攻击

        Args:
            arguments: 工具参数

        Returns:
            注入检测结果（含 capabilities）
        """
        all_strings = self._extract_strings(arguments)
        all_capabilities = set()

        for param_path, param_value in all_strings:
            for attack_type, attack_config in self.patterns.items():
                patterns = attack_config["patterns"]
                capabilities = attack_config.get("capabilities", [])
                for pattern in patterns:
                    if re.search(pattern, param_value, re.IGNORECASE):
                        # 收集注入命中的能力
                        all_capabilities.update(capabilities)
                        return {
                            "detected": True,
                            "attack_type": attack_type,
                            "pattern": pattern,
                            "malicious_param": f"{param_path}={param_value}",
                            "risk": "critical",
                            "capabilities": list(all_capabilities),
                        }

        return {"detected": False, "capabilities": []}

    def _grade_param(
        self, param_name: str, param_value: Any, param_config: dict
    ) -> tuple[str, list[str]]:
        """
        对单个参数定级

        Args:
            param_name: 参数名
            param_value: 参数值
            param_config: 参数定级配置

        Returns:
            (参数危险度等级, 参数能力列表)
        """
        default_risk = param_config.get("risk", "low")
        default_capabilities = param_config.get("capabilities", [])
        conditions = param_config.get("conditions", [])

        # 提取参数值的字符串表示
        value_str = str(param_value) if not isinstance(param_value, (dict, list)) else ""

        # 检查值条件
        for condition in conditions:
            if_clause = condition.get("if", {})
            then_risk = condition.get("then", default_risk)
            then_capabilities = condition.get("capabilities", default_capabilities)

            # patterns: 通配符匹配值
            if "patterns" in if_clause:
                for pattern in if_clause["patterns"]:
                    if self._match_pattern(value_str, pattern):
                        return then_risk, then_capabilities

            # key_patterns: 匹配字典的键名
            if "key_patterns" in if_clause and isinstance(param_value, dict):
                for key in param_value.keys():
                    for pattern in if_clause["key_patterns"]:
                        if self._match_pattern(str(key), pattern):
                            return then_risk, then_capabilities

            # value_regex: 正则匹配值
            if "value_regex" in if_clause:
                if re.search(if_clause["value_regex"], value_str, re.IGNORECASE):
                    return then_risk, then_capabilities

            # equals: 精确匹配值
            if "equals" in if_clause:
                if param_value == if_clause["equals"]:
                    return then_risk, then_capabilities

        return default_risk, default_capabilities

    def _check_joint_conditions(
        self, arguments: dict[str, Any], tool_config: dict
    ) -> tuple[bool, str, list[str]]:
        """
        检查联合条件

        Args:
            arguments: 工具参数
            tool_config: 工具定级配置

        Returns:
            (是否命中联合条件, 命中后的等级, 命中后的能力)
        """
        joint_conditions = tool_config.get("joint_conditions", [])

        for joint in joint_conditions:
            when_clause = joint.get("when", {})
            then_risk = joint.get("then", "low")
            then_capabilities = joint.get("capabilities", [])

            all_match = True
            for param_name, condition in when_clause.items():
                param_value = arguments.get(param_name)
                if param_value is None:
                    all_match = False
                    break

                # 检查条件
                if "patterns" in condition:
                    value_str = str(param_value)
                    matched = any(
                        self._match_pattern(value_str, p) for p in condition["patterns"]
                    )
                    if not matched:
                        all_match = False
                        break

                if "key_patterns" in condition and isinstance(param_value, dict):
                    matched = any(
                        self._match_pattern(str(k), p)
                        for k in param_value.keys()
                        for p in condition["key_patterns"]
                    )
                    if not matched:
                        all_match = False
                        break

                if "value_regex" in condition:
                    value_str = str(param_value)
                    if not re.search(
                        condition["value_regex"], value_str, re.IGNORECASE
                    ):
                        all_match = False
                        break

                if "equals" in condition:
                    if param_value != condition["equals"]:
                        all_match = False
                        break

            if all_match:
                return True, then_risk, then_capabilities

        return False, "", []

    def _grade_tool_call(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> tuple[str, list[str], list[str]]:
        """
        对工具调用整体定级

        Args:
            tool_name: 工具名称
            arguments: 工具参数

        Returns:
            (整体危险度等级, 各参数定级详情, 合并后的能力列表)
        """
        tool_config = self.grading_config.get(tool_name, {})
        if not tool_config:
            # 未登记工具，使用 classify_tool 兜底
            from src.rules.tool_classifier import classify_tool
            classification = classify_tool(tool_name)
            return classification.risk, [f"未登记工具，动态分类为 {classification.risk}"], []

        params_config = tool_config.get("params", {})
        unregistered_risk = tool_config.get("unregistered_param_risk", "low")

        # 逐参数定级
        param_risks = {}
        all_capabilities = set()
        for param_name, param_value in arguments.items():
            if param_name in params_config:
                risk, capabilities = self._grade_param(
                    param_name, param_value, params_config[param_name]
                )
                param_risks[param_name] = risk
                all_capabilities.update(capabilities)
            else:
                param_risks[param_name] = unregistered_risk

        # max 聚合
        risk_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        max_risk = max(
            param_risks.values(),
            key=lambda r: risk_order.get(r, 0),
            default="low",
        )

        # 检查联合条件
        joint_hit, joint_risk, joint_capabilities = self._check_joint_conditions(
            arguments, tool_config
        )
        if joint_hit:
            # 联合条件命中，覆盖 max 聚合结果
            final_risk = joint_risk
            # 联合条件的能力覆盖参数能力
            final_capabilities = joint_capabilities
        else:
            final_risk = max_risk
            final_capabilities = list(all_capabilities)

        # 生成详情
        details = [f"{k}={v}" for k, v in param_risks.items()]

        return final_risk, details, final_capabilities

    def check(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """
        检查工具参数

        Args:
            tool_name: 工具名称
            arguments: 工具参数

        Returns:
            {
                "detected": bool (是否检测到注入),
                "attack_type": str (如果检测到注入),
                "pattern": str (匹配的注入模式),
                "malicious_param": str (恶意参数),
                "risk": str (注入检测的风险等级，固定 critical),
                "param_risk": str (参数定级结果),
                "param_risk_details": list[str] (各参数定级详情),
                "capabilities": list[str] (合并后的能力列表),
                "param_compliant": bool (兼容性字段，始终 True),
                "whitelist_reason": str (兼容性字段)
            }
        """
        # 1. 注入检测
        injection_result = self._check_injection(arguments)

        # 2. 参数定级
        param_risk, param_risk_details, param_capabilities = self._grade_tool_call(
            tool_name, arguments
        )

        # 3. 合并能力（注入能力 + 参数能力）
        all_capabilities = set(injection_result.get("capabilities", []))
        all_capabilities.update(param_capabilities)

        # 4. 合并结果
        result = {
            "detected": injection_result["detected"],
            "param_risk": param_risk,
            "param_risk_details": param_risk_details,
            "capabilities": list(all_capabilities),
            "param_compliant": True,  # 兼容性字段
            "whitelist_reason": "参数定级完成",
        }

        if injection_result["detected"]:
            result.update(
                {
                    "attack_type": injection_result["attack_type"],
                    "pattern": injection_result["pattern"],
                    "malicious_param": injection_result["malicious_param"],
                    "risk": "critical",
                }
            )

        return result
