"""
告警模型
"""

from datetime import datetime
from pydantic import BaseModel, Field


class Alert(BaseModel):
    """
    安全告警

    当检测到工具调用违规时生成的告警信息。
    """

    alert_id: str = Field(description="告警唯一ID")
    session_id: str = Field(description="会话ID")
    alert_type: str = Field(
        description="告警类型: PERMISSION_VIOLATION, INJECTION_DETECTED, CAPABILITY_CHAIN, FREQUENCY_ANOMALY"
    )
    risk_level: str = Field(description="风险等级: critical, high, medium, low")
    risk_score: float = Field(ge=0.0, le=100.0, description="风险评分（0-100）")
    details: dict = Field(default_factory=dict, description="详细信息")
    tool_chain: list[str] = Field(default_factory=list, description="工具调用链")
    timestamp: datetime = Field(description="告警时间戳")

    class Config:
        """Pydantic配置"""
        json_schema_extra = {
            "example": {
                "alert_id": "alert_a1b2c3d4",
                "session_id": "session_123",
                "alert_type": "CAPABILITY_CHAIN",
                "risk_level": "critical",
                "risk_score": 95.0,
                "details": {
                    "pattern": {
                        "name": "private_data_exfiltration",
                        "capabilities": ["PRIVATE_ACCESS", "EXTERNAL_ACTION"],
                        "description": "读取内部数据后发送到外部"
                    }
                },
                "tool_chain": ["read_file", "http_request"],
                "timestamp": "2024-01-15T10:32:10Z"
            }
        }
