"""
前置阻断决策模型

区别于事后告警（Alert）：PolicyDecision 是给调用方执行前用的"放行/审批/拦截"指令。
"""

from typing import Optional

from pydantic import BaseModel, Field


class PolicyDecision(BaseModel):
    """
    单次工具调用的策略判决

    action:
        ALLOW  — 放行（可能仍需留痕，见 log_required）
        REVIEW — 挂起，等待人工审批
        BLOCK  — 拦截，工具不得执行
    """

    session_id: str = Field(description="会话ID")
    tool_name: str = Field(description="工具名称")
    action: str = Field(description="判决动作: ALLOW / REVIEW / BLOCK")
    reason: str = Field(description="判决原因")
    risk_level: str = Field(description="判决风险等级: low / medium / high / critical")
    risk_score: float = Field(ge=0.0, le=100.0, description="风险评分（0-100）")
    alert_types: list[str] = Field(default_factory=list, description="触发的告警类型")
    matched_chain: Optional[str] = Field(default=None, description="命中的能力链名称（如有）")
    log_required: bool = Field(default=False, description="是否需要留痕")
    approval_required: bool = Field(default=False, description="是否需要人工审批")
    session_compromised: bool = Field(
        default=False, description="本次判决后该会话是否已被标记为失守"
    )