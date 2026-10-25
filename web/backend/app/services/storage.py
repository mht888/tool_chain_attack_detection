"""
检测报告存储层：SQLite
"""

import json
import sqlite3
import threading

from app.config import DB_PATH

_SCHEMA = """
CREATE TABLE IF NOT EXISTS reports (
    report_id           TEXT PRIMARY KEY,
    session_id          TEXT NOT NULL,
    agent_name          TEXT,
    description         TEXT,
    verdict             TEXT NOT NULL,
    overall_risk_score  REAL NOT NULL,
    highest_risk_level  TEXT NOT NULL,
    total_tool_calls    INTEGER NOT NULL,
    alert_count         INTEGER NOT NULL,
    created_at          TEXT NOT NULL,
    markdown            TEXT NOT NULL,
    report_json         TEXT NOT NULL
);
"""

# SQLite 连接的线程锁（FastAPI 线程池并发访问）
_lock = threading.Lock()


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """初始化数据库表"""
    with _lock, _get_conn() as conn:
        conn.executescript(_SCHEMA)


def save_report(summary: dict, report_data: dict, markdown: str):
    """保存检测报告"""
    with _lock, _get_conn() as conn:
        conn.execute(
            """INSERT INTO reports
               (report_id, session_id, agent_name, description, verdict,
                overall_risk_score, highest_risk_level, total_tool_calls,
                alert_count, created_at, markdown, report_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                summary["report_id"], summary["session_id"], summary["agent_name"],
                summary["description"], summary["verdict"], summary["overall_risk_score"],
                summary["highest_risk_level"], summary["total_tool_calls"],
                summary["alert_count"], summary["created_at"], markdown,
                json.dumps(report_data, ensure_ascii=False),
            ),
        )


def list_reports(limit: int = 100) -> list[dict]:
    """报告列表（倒序）"""
    with _lock, _get_conn() as conn:
        rows = conn.execute(
            """SELECT report_id, session_id, agent_name, description, verdict,
                      overall_risk_score, highest_risk_level, total_tool_calls,
                      alert_count, created_at
               FROM reports ORDER BY created_at DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_report(report_id: str) -> dict | None:
    """查询单条报告（含完整 JSON 与 Markdown）"""
    with _lock, _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM reports WHERE report_id = ?", (report_id,)
        ).fetchone()
    if row is None:
        return None
    result = dict(row)
    result["report_data"] = json.loads(result.pop("report_json"))
    return result


def delete_report(report_id: str) -> bool:
    """删除报告"""
    with _lock, _get_conn() as conn:
        cur = conn.execute(
            "DELETE FROM reports WHERE report_id = ?", (report_id,)
        )
    return cur.rowcount > 0
