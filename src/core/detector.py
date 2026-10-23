"""
实时检测器：整合所有检测规则
"""

import uuid
from datetime import datetime

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
        self.chain_matcher = ChainMatcher(f"{rules_dir}/capability_chain_patterns.yaml")
        self.permission_checker = PermissionChecker(f"{rules_dir}/permission_policy.yaml")
        self.injection_checker = InjectionChecker(f"{rules_dir}/param_grading.yaml")
        self.frequency_checker = FrequencyChecker(f"{rules_dir}/permission_policy.yaml")
        self.risk_scorer = RiskScorer()

        # 会话buffer（维护每个session的工具调用历史）
        self.session_buffers: dict[str, list[ToolCallInput]] = {}
        
        # 每个session中每个工具调用的参数危险度
        # 格式: {session_id: {index: str}} (index -> risk_level)
        self.param_risk_map: dict[str, dict[int, str]] = {}
        
        # 每个session中每个工具调用的能力列表
        # 格式: {session_id: {index: list[str]}} (index -> capabilities)
        self.capabilities_map: dict[str, dict[int, list[str]]] = {}
        
        # 记录"初判有风险但参数低风险"的情况
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

        # 2. 参数注入检查 + 参数定级
        injection_result = self.injection_checker.check(
            tool_call.tool_name,
            tool_call.arguments
        )
        
        # 记录参数危险度和能力（使用session_id和buffer索引）
        current_index = len(self.session_buffers[session_id]) - 1
        if session_id not in self.param_risk_map:
            self.param_risk_map[session_id] = {}
        self.param_risk_map[session_id][current_index] = injection_result.get("param_risk", "low")
        
        if session_id not in self.capabilities_map:
            self.capabilities_map[session_id] = {}
        self.capabilities_map[session_id][current_index] = injection_result.get("capabilities", [])
        
        if injection_result["detected"]:
            alerts.append(self._create_alert(
                alert_type="INJECTION_DETECTED",
                details=injection_result,
                tool_call=tool_call,
                tool_chain=tool_chain
            ))

        # 3. 链模式检查（能力模式）
        session_risk_map = self.param_risk_map.get(session_id, {})
        session_capabilities_map = self.capabilities_map.get(session_id, {})
        chain_result = self.chain_matcher.check(
            self.session_buffers[session_id],
            session_risk_map,
            session_capabilities_map
        )
        
        # 为每个匹配的能力模式生成告警
        for pattern_info in chain_result.get("capability_patterns", []):
            alerts.append(self._create_alert(
                alert_type="CAPABILITY_CHAIN",
                details={"pattern": pattern_info},
                tool_call=tool_call,
                tool_chain=tool_chain
            ))
        
        # 记录"初判有风险但参数低风险"的情况
        for pattern_info in chain_result.get("skipped_patterns", []):
            self.skipped_chain_warnings.append({
                "tool_name": tool_call.tool_name,
                "pattern": pattern_info,
                "reason": f"能力链模式 {pattern_info.get('name', 'unknown')} 匹配，但相关工具参数均为 low 危险度",
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

    def cleanup_old_sessions(self, max_age_seconds: int = 3600):
        """
        清理过期的 session，防止内存泄漏

        Args:
            max_age_seconds: session 最大存活时间（秒），默认 1 小时
        """
        now = datetime.now()
        expired_sessions = []

        for session_id, buffer in self.session_buffers.items():
            if buffer:
                last_call_time = buffer[-1].timestamp
                # 处理带时区和不带时区的情况
                if last_call_time.tzinfo is not None:
                    last_call_time = last_call_time.replace(tzinfo=None)
                if (now - last_call_time).total_seconds() > max_age_seconds:
                    expired_sessions.append(session_id)

        for session_id in expired_sessions:
            del self.session_buffers[session_id]
            if session_id in self.param_risk_map:
                del self.param_risk_map[session_id]
            if session_id in self.capabilities_map:
                del self.capabilities_map[session_id]
            # 同时清理 frequency_checker 中的时间戳
            if session_id in self.frequency_checker.call_timestamps:
                del self.frequency_checker.call_timestamps[session_id]
