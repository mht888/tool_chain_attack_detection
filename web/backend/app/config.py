"""
Web 后端配置：路径解析与全局配置
"""

import sys
from pathlib import Path

# 项目根目录（web/backend/app/config.py 向上 3 级）
PROJECT_ROOT = Path(__file__).resolve().parents[3]

# 将项目根目录加入 sys.path，使后端可以直接 import src.core.detector
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# 检测规则目录（复用主项目的 src/rules）
RULES_DIR = str(PROJECT_ROOT / "src" / "rules")

# 数据目录（SQLite 数据库）
DATA_DIR = PROJECT_ROOT / "web" / "backend" / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = str(DATA_DIR / "web.db")

# 前端开发服务器地址（CORS 允许）
FRONTEND_DEV_ORIGIN = "http://localhost:5173"
