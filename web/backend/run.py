"""
后端启动脚本

用法（在 web/backend 目录下）：
    python run.py            # 开发模式（热重载）
    python run.py --prod     # 生产模式
"""

import argparse

import uvicorn

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="启动检测系统 Web 后端")
    parser.add_argument("--host", type=str, default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--prod", action="store_true", help="生产模式（关闭热重载）")
    args = parser.parse_args()

    uvicorn.run(
        "app.main:app",
        host=args.host,
        port=args.port,
        reload=not args.prod,
    )
