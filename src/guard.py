"""
前置阻断包装器

Agent 在执行工具前先过 AgentGuard：
- BLOCK  → 工具不执行
- REVIEW → 挂起不执行（当前无人工审批通道，一律不执行）
- ALLOW  → 执行

用法：
    guard = AgentGuard()
    result = guard.safe_execute("read_file", {"path": "./a.txt"}, executor, session_id="s1")
    if not result["executed"]:
        print("已被拦截:", result["decision"]["reason"])
"""

from datetime import datetime
from typing import Any, Callable, Optional

from src.core.detector import RealTimeDetector
from src.models.decision import PolicyDecision
from src.models.input import ToolCallInput


class AgentGuard:
    """工具执行前的策略闸口"""

    def __init__(
        self,
        rules_dir: str = "src/rules",
        detector: Optional[RealTimeDetector] = None,
    ):
        self.detector = detector or RealTimeDetector(rules_dir=rules_dir)

    def evaluate(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        session_id: str = "default",
        agent_name: Optional[str] = None,
        timestamp: Optional[datetime] = None,
    ) -> PolicyDecision:
        """只判决，不执行"""
        tool_call = ToolCallInput(
            tool_name=tool_name,
            arguments=arguments,
            session_id=session_id,
            agent_name=agent_name,
            **({"timestamp": timestamp} if timestamp is not None else {}),
        )
        return self.detector.evaluate(tool_call)

    def safe_execute(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        executor: Callable[[str, dict[str, Any]], Any],
        session_id: str = "default",
        agent_name: Optional[str] = None,
        timestamp: Optional[datetime] = None,
    ) -> dict:
        """
        过闸后执行工具

        Args:
            tool_name: 工具名
            arguments: 工具参数
            executor: 真正执行工具的函数，签名 executor(tool_name, arguments)
            session_id: 会话ID
            agent_name: Agent 名称
            timestamp: 调用时间

        Returns:
            {
                "executed": bool,
                "action": "ALLOW" / "REVIEW" / "BLOCK",
                "decision": PolicyDecision 的 dict,
                "result": executor 的返回值（仅 ALLOW 时非 None）,
                "pending_approval": bool（仅 REVIEW 时为 True）,
            }
        """
        decision = self.evaluate(
            tool_name, arguments, session_id, agent_name, timestamp
        )

        if decision.action == "BLOCK":
            return {
                "executed": False,
                "action": "BLOCK",
                "decision": decision.model_dump(mode="json"),
                "result": None,
            }

        if decision.action == "REVIEW":
            # 暂无人工审批通道，挂起不执行
            return {
                "executed": False,
                "action": "REVIEW",
                "decision": decision.model_dump(mode="json"),
                "result": None,
                "pending_approval": True,
            }

        return {
            "executed": True,
            "action": "ALLOW",
            "decision": decision.model_dump(mode="json"),
            "result": executor(tool_name, arguments),
        }