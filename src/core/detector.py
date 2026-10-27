"""
实时检测器：整合所有检测规则，提供事后告警与执行前判决两条路径

- on_tool_call(): 事后检测，返回告警（批量报告模式，行为保持不变）
- evaluate():     执行前判决，返回 PolicyDecision（ALLOW / REVIEW / BLOCK）
"""

import uuid
from datetime import datetime

import yaml

from src.models.input import ToolCallInput
from src.models.alert import Alert
from src.models.decision import PolicyDecision
from src.core.chain_matcher import ChainMatcher
from src.core.permission_checker import PermissionChecker
from src.core.injection_checker import InjectionChecker
from src.core.frequency_checker import FrequencyChecker
from src.core.risk_scorer import RiskScorer

# 风险等级排序，用于比较
_LEVEL_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# 无告警时按判决等级给出的基础分
_DECISION_BASE_SCORE = {"low": 10.0, "medium": 30.0, "high": 50.0, "critical": 70.0}

_ALERT_TYPE_CN = {
    "PERMISSION_VIOLATION": "权限违规",
    "INJECTION_DETECTED": "注入检测",
    "CAPABILITY_CHAIN": "能力链",
    "FREQUENCY_ANOMALY": "频率异常",
}


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

        # 判决阈值与工具风险等级（来自 permission_policy.yaml）
        self._decision_policy = self._load_decision_policy(f"{rules_dir}/permission_policy.yaml")
        self.risk_thresholds = self._decision_policy.get("risk_thresholds", {})
        self.tool_risk_levels = self._decision_policy.get("tool_risk_levels", {})

        # 会话buffer（维护每个session的工具调用历史）
        self.session_buffers: dict[str, list[ToolCallInput]] = {}

        # 每个session中每个工具调用的参数危险度
        # 格式: {session_id: {index: str}} (index -> risk_level)
        self.param_risk_map: dict[str, dict[int, str]] = {}

        # 每个session中每个工具调用的能力列表
        # 格式: {session_id: {index: list[str]}} (index -> capabilities)
        self.capabilities_map: dict[str, dict[int, list[str]]] = {}

        # 会话状态：是否已失守（命中 BLOCK 后置为 True）
        self.session_state: dict[str, dict] = {}

        # 记录"初判有风险但参数低风险"的情况
        self.skipped_chain_warnings: list[dict] = []

    # ------------------------------------------------------------------
    # 对外接口
    # ------------------------------------------------------------------

    def on_tool_call(self, tool_call: ToolCallInput) -> list[Alert]:
        """
        处理一次工具调用（事后检测，返回告警）

        Args:
            tool_call: 工具调用输入

        Returns:
            检测到的告警列表（可能为空）
        """
        return self._process(tool_call)["alerts"]

    def evaluate(self, tool_call: ToolCallInput) -> PolicyDecision:
        """
        执行前判决：决定这次调用该放行、审批还是拦截

        注意：调用会先记入会话历史（被拦截的调用同样留痕），再基于
        "当前调用 + 历史" 做判决，符合"拦截也要留痕"的策略。

        Args:
            tool_call: 工具调用输入

        Returns:
            PolicyDecision
        """
        session_id = tool_call.session_id or "default"
        was_compromised = self.session_state.get(session_id, {}).get("compromised", False)

        result = self._process(tool_call)
        alerts: list[Alert] = result["alerts"]
        tool_risk = self._tool_risk_level(tool_call.tool_name)
        param_risk = result["param_risk"]

        alert_risk = self._max_level([a.risk_level for a in alerts])
        has_critical_alert = alert_risk == "critical"
        matched_chain = self._pick_matched_chain(result["matched_patterns"])

        # ---- 判决 ----
        allow_log = False
        if result["permission_blocked"]:
            action = "BLOCK"
            decision_level = "critical"
            reason = f"命中黑名单工具 {tool_call.tool_name}，禁止执行"
        elif has_critical_alert:
            action = "BLOCK"
            decision_level = "critical"
            detail = self._alert_types_cn(alerts)
            reason = f"命中 critical 级告警（{detail}）"
            if matched_chain:
                reason += f"，能力链 {matched_chain}"
        elif was_compromised and tool_risk == "critical":
            action = "BLOCK"
            decision_level = "critical"
            reason = "会话已标记失守，后续 critical 工具一律拦截"
        elif alert_risk == "high" or (
            self._level_ge(tool_risk, "high") and self._level_ge(param_risk, "high")
        ):
            action = "REVIEW"
            decision_level = "high"
            if alert_risk == "high":
                reason = f"命中 high 级告警（{self._alert_types_cn(alerts)}），需人工审批"
            else:
                reason = (
                    f"工具风险 {tool_risk} 且参数风险 {param_risk}，"
                    "单步高危操作，需人工审批"
                )
        elif alert_risk == "medium" or self._level_ge(tool_risk, "medium"):
            action = "ALLOW"
            decision_level = "medium"
            allow_log = True
            reason = "风险可控，放行并留痕"
        else:
            action = "ALLOW"
            decision_level = "low"
            reason = "未命中任何风险规则"

        # 命中 BLOCK 后将会话标记为失守
        if action == "BLOCK":
            self.session_state.setdefault(session_id, {})["compromised"] = True
        compromised_now = self.session_state.get(session_id, {}).get("compromised", False)

        if alerts:
            risk_score = max(a.risk_score for a in alerts)
        else:
            risk_score = _DECISION_BASE_SCORE[decision_level]

        alert_types = list(dict.fromkeys(a.alert_type for a in alerts))

        return PolicyDecision(
            session_id=session_id,
            tool_name=tool_call.tool_name,
            action=action,
            reason=reason,
            risk_level=decision_level,
            risk_score=round(risk_score, 1),
            alert_types=alert_types,
            matched_chain=matched_chain,
            log_required=allow_log or action != "ALLOW" or self._level_ge(tool_risk, "medium"),
            approval_required=action == "REVIEW",
            session_compromised=compromised_now,
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
            if session_id in self.session_state:
                del self.session_state[session_id]
            # 同时清理 frequency_checker 中的时间戳
            if session_id in self.frequency_checker.call_timestamps:
                del self.frequency_checker.call_timestamps[session_id]

    # ------------------------------------------------------------------
    # 内部实现
    # ------------------------------------------------------------------

    def _process(self, tool_call: ToolCallInput) -> dict:
        """
        执行四层检查并把这次调用记入会话历史

        Returns:
            {
                "alerts": list[Alert],
                "param_risk": str,
                "permission_blocked": bool,
                "matched_patterns": list[dict],
                "tool_chain": list[str],
            }
        """
        session_id = tool_call.session_id or "default"

        # 更新buffer（被拦截的调用也留痕）
        if session_id not in self.session_buffers:
            self.session_buffers[session_id] = []
        self.session_buffers[session_id].append(tool_call)

        alerts: list[Alert] = []
        tool_chain = [tc.tool_name for tc in self.session_buffers[session_id]]

        result = {
            "alerts": alerts,
            "param_risk": "low",
            "permission_blocked": False,
            "matched_patterns": [],
            "tool_chain": tool_chain,
        }

        # 1. 权限检查（仅对黑名单工具阻断）
        perm_result = self.permission_checker.check(tool_call.tool_name)
        if perm_result.get("blocked"):
            alerts.append(self._create_alert(
                alert_type="PERMISSION_VIOLATION",
                details=perm_result,
                tool_call=tool_call,
                tool_chain=tool_chain
            ))
            result["permission_blocked"] = True
            # 黑名单工具直接阻断，不再执行后续检查
            return result

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
        result["param_risk"] = injection_result.get("param_risk", "low")

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
            result["matched_patterns"].append(pattern_info)
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

        return result

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

    def _tool_risk_level(self, tool_name: str) -> str:
        """工具自身风险等级：优先查 YAML，未登记时动态分类兜底"""
        if tool_name in self.tool_risk_levels:
            return self.tool_risk_levels[tool_name]
        from src.rules.tool_classifier import classify_tool
        return classify_tool(tool_name).risk

    @staticmethod
    def _load_decision_policy(path: str) -> dict:
        """加载权限策略（用于判决阈值与工具风险等级）"""
        try:
            with open(path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except FileNotFoundError:
            print(f"警告: 权限策略文件不存在: {path}")
            return {}
        except Exception as e:
            print(f"警告: 加载权限策略失败: {e}")
            return {}

    @staticmethod
    def _level_ge(level: str, threshold: str) -> bool:
        """level 是否 >= threshold"""
        return _LEVEL_RANK.get(level, 0) >= _LEVEL_RANK.get(threshold, 0)

    @staticmethod
    def _max_level(levels: list[str]) -> str:
        """取风险等级最高的一项，空列表返回 low"""
        if not levels:
            return "low"
        return max(levels, key=lambda lv: _LEVEL_RANK.get(lv, 0))

    @staticmethod
    def _pick_matched_chain(patterns: list[dict]) -> str | None:
        """从命中的能力链中取风险最高的一条，返回其名称"""
        if not patterns:
            return None
        best = max(patterns, key=lambda p: _LEVEL_RANK.get(p.get("risk", "low"), 0))
        return best.get("name")

    @staticmethod
    def _alert_types_cn(alerts: list[Alert]) -> str:
        """告警类型转中文，去重后用顿号连接"""
        names = list(dict.fromkeys(
            _ALERT_TYPE_CN.get(a.alert_type, a.alert_type) for a in alerts
        ))
        return "、".join(names)