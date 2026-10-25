"""
检测服务层：封装 RealTimeDetector，提供整链检测能力

不改动现有 src/ 检测引擎，本层只做编排：
1. 逐个调用 detector.on_tool_call 执行四层检测
2. 用 DetectionReport 汇总并生成 Markdown
3. 落库 SQLite，返回结构化结果供前端展示
"""

import uuid
from datetime import datetime

from app.config import RULES_DIR
from app.services import storage

from src.core.detector import RealTimeDetector
from src.models.input import ToolCallInput
from src.models.report import DetectionReport


def _parse_timestamp(ts_str: str | None) -> datetime:
    """解析 ISO 时间戳，缺省用当前时间"""
    if ts_str:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    return datetime.now()


def _verdict_short(verdict_cn: str) -> str:
    """报告模型返回形如 'MALICIOUS（恶意）'，取英文前缀供前端判定颜色"""
    for prefix in ("MALICIOUS", "SUSPICIOUS", "SAFE"):
        if verdict_cn.startswith(prefix):
            return prefix
    return "UNKNOWN"


class DetectionService:
    """检测服务（单例：规则只加载一次）"""

    _instance: "DetectionService | None" = None

    def __init__(self):
        self.detector = RealTimeDetector(rules_dir=RULES_DIR)

    @classmethod
    def get_instance(cls) -> "DetectionService":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def detect_session(self, data: dict) -> dict:
        """
        对一个完整的工具调用序列执行检测

        Args:
            data: {session_id?, agent_name?, description?, tool_calls: [...]}

        Returns:
            结构化检测结果（含逐步过程、告警、汇总、Markdown）
        """
        session_id = data.get("session_id") or f"session_{uuid.uuid4().hex[:8]}"
        agent_name = data.get("agent_name")
        description = data.get("description")
        tool_calls_data = data.get("tool_calls", [])

        # 清理过期 session，防止内存增长
        self.detector.cleanup_old_sessions()

        # skipped_chain_warnings 是检测器级累积列表（长驻服务跨请求共享），
        # 只取本次会话新增的部分，避免跨请求污染
        warnings_start = len(self.detector.skipped_chain_warnings)

        report = DetectionReport(session_id=session_id)
        steps: list[dict] = []

        # 逐个工具调用执行检测（与 main.py 流程一致）
        for i, call_data in enumerate(tool_calls_data, 1):
            tool_call = ToolCallInput(
                tool_name=call_data["tool_name"],
                arguments=call_data.get("arguments", {}),
                timestamp=_parse_timestamp(call_data.get("timestamp")),
                session_id=session_id,
                agent_name=agent_name,
                metadata=call_data.get("metadata", {}),
            )

            alerts = self.detector.on_tool_call(tool_call)
            blocked = bool(alerts)

            report.add_tool_call(tool_call.tool_name, tool_call.arguments, blocked=blocked)
            for alert in alerts:
                report.add_alert(alert)

            steps.append({
                "index": i,
                "tool_name": tool_call.tool_name,
                "arguments": tool_call.arguments,
                "blocked": blocked,
                "alerts": [self._alert_to_dict(a) for a in alerts],
            })

        # 记录"初判有风险但参数低风险"的跳过链（仅本次新增，datetime 转 ISO 字符串）
        skipped_warnings = []
        for warning in self.detector.skipped_chain_warnings[warnings_start:]:
            w = dict(warning)
            if isinstance(w.get("timestamp"), datetime):
                w["timestamp"] = w["timestamp"].isoformat()
            skipped_warnings.append(w)
            report.add_skipped_chain_warning(w)

        report.finalize()

        # 汇总
        overall_score = report._calculate_overall_risk_score()
        verdict = report._get_verdict(overall_score)
        markdown = report.to_markdown()

        report_id = f"rpt_{uuid.uuid4().hex[:12]}"
        created_at = datetime.now().isoformat(timespec="seconds")

        alerts_flat = [self._alert_to_dict(a) for a in report.alerts]
        report_data = {
            "steps": steps,
            "alerts": alerts_flat,
            "skipped_chain_warnings": skipped_warnings,
        }
        summary = {
            "report_id": report_id,
            "session_id": session_id,
            "agent_name": agent_name,
            "description": description,
            "verdict": _verdict_short(verdict),
            "overall_risk_score": round(overall_score, 1),
            "highest_risk_level": report._get_highest_risk(),
            "total_tool_calls": report.total_tool_calls,
            "alert_count": len(report.alerts),
            "created_at": created_at,
        }

        storage.save_report(summary, report_data, markdown)

        return {
            **summary,
            "verdict": verdict,  # 响应中保留中文完整判定
            "steps": steps,
            "alerts": alerts_flat,
            "skipped_chain_warnings": skipped_warnings,
            "markdown": markdown,
        }

    def detect_single_tool_call(
        self,
        session_id: str,
        tool_name: str,
        arguments: dict,
        timestamp_str: str | None = None,
        agent_name: str | None = None,
    ) -> list[dict]:
        """
        实时单步检测：只对一次工具调用执行检测，不生成报告、不落库

        （后续 WebSocket 实时反馈将复用此入口）
        """
        tool_call = ToolCallInput(
            tool_name=tool_name,
            arguments=arguments,
            timestamp=_parse_timestamp(timestamp_str),
            session_id=session_id,
            agent_name=agent_name,
        )
        alerts = self.detector.on_tool_call(tool_call)
        return [self._alert_to_dict(a) for a in alerts]

    @staticmethod
    def _alert_to_dict(alert) -> dict:
        """Alert (pydantic v2) -> JSON 安全的 dict"""
        return alert.model_dump(mode="json")
