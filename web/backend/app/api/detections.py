"""
检测相关 API
"""

from fastapi import APIRouter, HTTPException

from app.schemas.detection import (
    DetectSessionRequest,
    DetectSessionResponse,
    ToolCallItem,
)
from app.services.detection_service import DetectionService

router = APIRouter(tags=["detection"])


@router.post("/detect/session", response_model=DetectSessionResponse)
async def detect_session(req: DetectSessionRequest):
    """对一个完整的工具调用序列执行四层检测，生成报告并落库"""
    if not req.tool_calls:
        raise HTTPException(status_code=400, detail="tool_calls 不能为空")

    service = DetectionService.get_instance()
    try:
        result = service.detect_session(req.model_dump())
    except KeyError as e:
        raise HTTPException(status_code=400, detail=f"工具调用缺少必填字段: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"检测失败: {e}")
    return result


@router.post("/detect/tool-call")
async def detect_single_tool_call(req: ToolCallItem, session_id: str = "default"):
    """
    实时单步检测（预留接口，供后续 WebSocket 实时反馈使用）

    对单次工具调用执行四层检测，返回该步告警。不生成报告、不落库。
    """
    service = DetectionService.get_instance()
    try:
        alerts = service.detect_single_tool_call(
            session_id=session_id,
            tool_name=req.tool_name,
            arguments=req.arguments,
            timestamp_str=req.timestamp,
            agent_name=None,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"检测失败: {e}")
    return {
        "session_id": session_id,
        "tool_name": req.tool_name,
        "alert_count": len(alerts),
        "alerts": alerts,
    }
