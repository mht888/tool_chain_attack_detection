"""
频率异常检查器
"""

from datetime import datetime, timedelta
from typing import Any
from collections import deque

from src.models.input import ToolCallInput


class FrequencyChecker:
    """
    频率异常检查器

    检测工具调用频率是否异常（如短时间内大量调用）。
    """

    def __init__(self, window_seconds: int = 60, max_calls: int = 10):
        """
        初始化频率检查器

        Args:
            window_seconds: 时间窗口（秒）
            max_calls: 窗口内最大允许调用次数
        """
        self.window_seconds = window_seconds
        self.max_calls = max_calls

        # 每个session的调用时间戳
        self.call_timestamps: dict[str, deque] = {}

    def check(self, session_id: str, tool_call: ToolCallInput) -> dict[str, Any]:
        """
        检查工具调用频率是否异常

        Args:
            session_id: 会话ID
            tool_call: 工具调用

        Returns:
            {
                "anomaly": bool,
                "calls_in_window": int (如果异常),
                "window_seconds": int,
                "max_allowed": int
            }
        """
        now = tool_call.timestamp

        # 初始化session的时间戳队列
        if session_id not in self.call_timestamps:
            self.call_timestamps[session_id] = deque()

        # 添加当前时间戳
        self.call_timestamps[session_id].append(now)

        # 清理过期的时间戳
        cutoff = now - timedelta(seconds=self.window_seconds)
        while self.call_timestamps[session_id] and self.call_timestamps[session_id][0] < cutoff:
            self.call_timestamps[session_id].popleft()

        # 检查频率
        calls_in_window = len(self.call_timestamps[session_id])

        if calls_in_window > self.max_calls:
            return {
                "anomaly": True,
                "calls_in_window": calls_in_window,
                "window_seconds": self.window_seconds,
                "max_allowed": self.max_calls,
                "risk": "medium"
            }

        # 频率正常
        return {"anomaly": False}
