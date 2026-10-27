"""
前置阻断 API：执行前判决

调用方（agent / MCP 代理）在真正执行工具之前调用 /api/guard/evaluate，
返回 ALLOW / REVIEW / BLOCK，调用方按判决决定是否放行。
"""

from fastapi import APIRouter, HTTPException

from app.schemas.detection import GuardEvaluateRequest, PolicyDecisionResponse
from app.services.detection_service import DetectionService

router = APIRouter(tags=["guard"])


@router.post("/guard/evaluate", response_model=PolicyDecisionResponse)
async def evaluate(req: GuardEvaluateRequest):
    """对单次工具调用做执行前判决（ALLOW / REVIEW / BLOCK）"""
    service = DetectionService.get_instance()
    try:
        return service.evaluate_tool_call(
            session_id=req.session_id,
            tool_name=req.tool_name,
            arguments=req.arguments,
            timestamp_str=req.timestamp,
            agent_name=req.agent_name,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"判决失败: {e}")