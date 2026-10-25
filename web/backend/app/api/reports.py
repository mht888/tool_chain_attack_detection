"""
报告与配置查询 API
"""

import yaml
from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from app.config import RULES_DIR
from app.schemas.detection import ChainPatternItem, ReportSummary
from app.services import storage

router = APIRouter(tags=["reports"])


@router.get("/reports", response_model=list[ReportSummary])
async def list_reports(limit: int = 100):
    """报告列表（按创建时间倒序）"""
    return storage.list_reports(limit=min(limit, 500))


@router.get("/reports/{report_id}")
async def get_report(report_id: str):
    """报告详情（含逐步检测过程、告警明细）"""
    row = storage.get_report(report_id)
    if row is None:
        raise HTTPException(status_code=404, detail="报告不存在")

    report_data = row.pop("report_data")
    return {
        **row,
        "steps": report_data.get("steps", []),
        "alerts": report_data.get("alerts", []),
        "skipped_chain_warnings": report_data.get("skipped_chain_warnings", []),
    }


@router.get("/reports/{report_id}/markdown")
async def get_report_markdown(report_id: str):
    """下载报告 Markdown（以附件形式下载，而非在浏览器中直接展示）"""
    row = storage.get_report(report_id)
    if row is None:
        raise HTTPException(status_code=404, detail="报告不存在")
    return Response(
        content=row["markdown"],
        media_type="text/markdown; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{report_id}.md"',
        },
    )


@router.delete("/reports/{report_id}")
async def delete_report(report_id: str):
    """删除报告"""
    ok = storage.delete_report(report_id)
    if not ok:
        raise HTTPException(status_code=404, detail="报告不存在")
    return {"deleted": True, "report_id": report_id}


@router.get("/config/chain-patterns", response_model=list[ChainPatternItem])
async def get_chain_patterns():
    """能力链模式列表（供前端展示规则配置）"""
    with open(f"{RULES_DIR}/capability_chain_patterns.yaml", "r", encoding="utf-8") as f:
        patterns = yaml.safe_load(f) or []
    return [
        ChainPatternItem(
            pattern_id=p.get("pattern_id", f"FC-{i}"),
            name=p["name"],
            capabilities=p.get("capabilities", []),
            risk=p.get("risk", "unknown"),
            description=p.get("description", ""),
            remediation=p.get("remediation", ""),
        )
        for i, p in enumerate(patterns, 1)
    ]
