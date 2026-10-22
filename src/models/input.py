"""
输入格式定义（参考ZIRAN的ToolCallEvent）
"""

from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, Field


class ToolCallInput(BaseModel):
    """
    工具调用输入

    每次agent要调用工具时，都会产生这个输入。
    参考了ZIRAN的ToolCallEvent格式。
    """

    # 必填字段
    tool_name: str = Field(description="工具名称")
    arguments: dict[str, Any] = Field(default_factory=dict, description="工具参数")

    # 可选字段（参考ZIRAN）
    timestamp: datetime = Field(default_factory=datetime.now, description="调用时间戳")
    session_id: Optional[str] = Field(default=None, description="会话ID（用于关联多次调用）")
    agent_name: Optional[str] = Field(default=None, description="Agent名称")

    # 扩展字段
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="额外元数据（如用户ID、请求ID等）"
    )

    class Config:
        """Pydantic配置"""
        json_schema_extra = {
            "example": {
                "tool_name": "read_file",
                "arguments": {"path": "/data/customers.csv"},
                "timestamp": "2024-01-15T10:30:15Z",
                "session_id": "session_123",
                "agent_name": "customer_support_agent"
            }
        }
