"""
实时检测器：整合所有检测规则
"""

import uuid

from src.models.input import ToolCallInput
from src.models.alert import Alert
from src.core.chain_matcher import ChainMatcher
from src.core.permission_checker import PermissionChecker
from src.core.injection_checker import InjectionChecker
from src.core.frequency_checker import FrequencyChecker
from src.core.risk_scorer import RiskScorer


class RealTimeDetector:
    """
    实时工具调用链攻击检测器

    整合4类检测规则：
    1. 权限策略检查
    2. 参数注入检查
    3. 链模式检测
    4. 频率异常检查
    """

    def __init__(self, rules_dir: str = "src/rules"):
        """
        初始化检测器

        Args:
            rules_dir: 规则配置目录
        """
        self.chain_matcher = ChainMatcher(f"{rules_dir}/chain_patterns.yaml")
        self.permission_checker = PermissionChecker(f"{rules_dir}/permission_policy.yaml")
        self.injection_checker = InjectionChecker(f"{rules_dir}/param_whitelist.yaml")
        self.frequency_checker = FrequencyChecker(f"{rules_dir}/permission_policy.yaml")
        self.risk_scorer = RiskScorer()

        # 会话buffer（维护每个session的工具调用历史）
        self.session_buffers: dict[str, list[ToolCallInput]] = {}
        
        # 每个工具调用的参数合规状态（buffer索引 -> 是否合规）
        # 使用索引而非工具名，避免同一工具多次调用时覆盖
        self.param_compliant_map: dict[int, bool] = {}
        
        # 记录"初判有风险但参数合规"的情况
        self.skipped_chain_warnings: list[dict] = []

    def on_tool_call(self, tool_call: ToolCallInput) -> list[Alert]:
        """
        处理一次工具调用

        Args:
            tool_call: 工具调用输入

        Returns:
            检测到的告警列表（可能为空）
        """
        session_id = tool_call.session_id or "default"

        # 更新buffer
        if session_id not in self.session_buffers:
            self.session_buffers[session_id] = []
        self.session_buffers[session_id].append(tool_call)

        alerts: list[Alert] = []
        tool_chain = [tc.tool_name for tc in self.session_buffers[session_id]]

        # 1. 权限检查（仅对黑名单工具阻断）
        perm_result = self.permission_checker.check(tool_call.tool_name)
        if perm_result.get("blocked"):
            alerts.append(self._create_alert(
                alert_type="PERMISSION_VIOLATION",
                details=perm_result,
                tool_call=tool_call,
                tool_chain=tool_chain
            ))
            # 黑名单工具直接阻断，不再执行后续检查
            return alerts

        # 2. 参数注入检查
        injection_result = self.injection_checker.check(
            tool_call.tool_name,
            tool_call.arguments
        )
        
        # 记录参数合规状态（使用buffer索引）
        current_index = len(self.session_buffers[session_id]) - 1
        self.param_compliant_map[current_index] = injection_result.get("param_compliant", True)
        
        if injection_result["detected"]:
            alerts.append(self._create_alert(
                alert_type="INJECTION_DETECTED",
                details=injection_result,
                tool_call=tool_call,
                tool_chain=tool_chain
            ))

        # 3. 链模式检查
        chain_result = self.chain_matcher.check(self.session_buffers[session_id], self.param_compliant_map)
        if chain_result["matched"]:
            alerts.append(self._create_alert(
                alert_type="DANGEROUS_CHAIN",
                details=chain_result,
                tool_call=tool_call,
                tool_chain=tool_chain
            ))
        elif chain_result.get("skipped"):
            # 记录"初判有风险但参数合规"的情况
            self.skipped_chain_warnings.append({
                "tool_name": tool_call.tool_name,
                "pattern": chain_result.get("pattern", {}),
                "reason": chain_result.get("skip_reason", ""),
                "timestamp": tool_call.timestamp
            })

        # 4. 频率检查
        freq_result = self.frequency_checker.check(session_id, tool_call)
        if freq_result["anomaly"]:
            alerts.append(self._create_alert(
                alert_type="FREQUENCY_ANOMALY",
                details=freq_result,
                tool_call=tool_call,
                tool_chain=tool_chain
            ))

        # 返回所有检测到的告警
        return alerts

    def _create_alert(
        self,
        alert_type: str,
        details: dict,
        tool_call: ToolCallInput,
        tool_chain: list[str]
    ) -> Alert:
        """
        创建告警对象

        Args:
            alert_type: 告警类型
            details: 详细信息
            tool_call: 触发告警的工具调用
            tool_chain: 当前工具调用链

        Returns:
            Alert对象
        """
        session_id = tool_call.session_id or "default"

        # 计算风险评分
        risk_score = self.risk_scorer.calculate(alert_type, details)
        risk_level = self.risk_scorer.get_risk_level(risk_score)

        return Alert(
            alert_id=f"alert_{uuid.uuid4().hex[:8]}",
            session_id=session_id,
            alert_type=alert_type,
            risk_level=risk_level,
            risk_score=risk_score,
            details=details,
            tool_chain=tool_chain,
            timestamp=tool_call.timestamp
        )
