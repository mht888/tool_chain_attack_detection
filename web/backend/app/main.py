"""
Web 后端入口：FastAPI 应用
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import FRONTEND_DEV_ORIGIN
from app.services import storage

from app.api import detections, examples, guard, reports

app = FastAPI(
    title="工具调用链攻击检测系统 API",
    description="面向 LLM Agent 的工具调用链攻击检测 Web 服务",
    version="0.1.0",
)

# 允许前端开发服务器跨域访问
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_DEV_ORIGIN],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 路由注册
app.include_router(detections.router, prefix="/api")
app.include_router(reports.router, prefix="/api")
app.include_router(examples.router, prefix="/api")
app.include_router(guard.router, prefix="/api")


@app.on_event("startup")
async def on_startup():
    """初始化数据库表"""
    storage.init_db()


@app.get("/api/health")
async def health():
    """健康检查"""
    return {"status": "ok", "service": "tool-chain-attack-detection"}
