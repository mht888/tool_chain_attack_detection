"""
演示数据 API：浏览 examples 目录下的测试场景
"""

import json
from pathlib import Path

from fastapi import APIRouter, HTTPException

from app.config import PROJECT_ROOT

router = APIRouter(tags=["examples"])

EXAMPLES_DIR = PROJECT_ROOT / "examples"

# 分类中文名映射
CATEGORY_NAMES = {
    "dangerous_chains": "危险链测试",
    "normal_chains": "正常链测试",
    "injection_tests": "注入检测测试",
    "frequency_tests": "频率检测测试",
    "long_chains": "长链测试",
    "real_world_scenarios": "真实业务场景",
    "tool_classifier_tests": "工具分类测试",
    "whitelist_tests": "白名单测试",
}


def _safe_path(category: str, filename: str) -> Path:
    """路径安全校验：只允许访问 examples 目录下的合法 JSON 文件"""
    if not filename.endswith(".json"):
        raise HTTPException(status_code=400, detail="只支持 JSON 文件")
    for part in (category, filename):
        if not part or "/" in part or "\\" in part or ".." in part:
            raise HTTPException(status_code=400, detail="非法路径")
    path = (EXAMPLES_DIR / category / filename).resolve()
    if not str(path).startswith(str(EXAMPLES_DIR.resolve())):
        raise HTTPException(status_code=400, detail="非法路径")
    return path


@router.get("/examples")
async def list_examples():
    """列出所有演示数据（按 examples 目录结构分类）"""
    if not EXAMPLES_DIR.is_dir():
        raise HTTPException(status_code=404, detail="examples 目录不存在")

    result = []
    for d in sorted(EXAMPLES_DIR.iterdir()):
        if not d.is_dir():
            continue
        files = []
        for f in sorted(d.glob("*.json")):
            info = {"name": f.name, "description": "", "tool_count": 0, "session_id": ""}
            try:
                with open(f, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                info["description"] = data.get("description", "")
                info["tool_count"] = len(data.get("tool_calls", []))
                info["session_id"] = data.get("session_id", "")
            except (json.JSONDecodeError, OSError):
                continue
            files.append(info)
        if files:
            result.append({
                "category": d.name,
                "category_name": CATEGORY_NAMES.get(d.name, d.name),
                "files": files,
            })
    return result


@router.get("/examples/content")
async def get_example_content(category: str, file: str):
    """获取指定演示数据的完整 JSON 内容"""
    path = _safe_path(category, file)
    if not path.is_file():
        raise HTTPException(status_code=404, detail="文件不存在")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="JSON 解析失败")
