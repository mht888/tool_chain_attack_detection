"""
频率异常检查器
"""

from datetime import datetime, timedelta
from typing import Any
from collections import deque
import yaml

from src.models.input import ToolCallInput
from src.rules.tool_classifier import classify_tool


class FrequencyChecker:
    """
    频率异常检查器

    检测工具调用频率是否异常（如短时间内大量调用）。
    根据工具风险等级设置差异化阈值。
    """

    def __init__(self, policy_path: str = "src/rules/permission_policy.yaml"):
        """
        初始化频率检查器

        Args:
            policy_path: 权限策略配置路径（YAML格式）
        """
        # 从 YAML 读取配置
        policy = self._load_policy(policy_path)
        
        # 频率限制配置
        frequency_limits = policy.get("frequency_limits", {})
        self.max_calls_per_minute = frequency_limits.get("max_calls_per_minute", 10)
        
        # 时间窗口（秒）
        self.window_seconds = 60
        
        # 根据工具风险等级设置差异化阈值（基于 max_calls_per_minute）
        self.risk_thresholds = {
            "critical": max(1, self.max_calls_per_minute // 3),   # 高风险工具：约 1/3 阈值
            "high": max(2, self.max_calls_per_minute // 2),       # 中高风险工具：约 1/2 阈值
            "medium": self.max_calls_per_minute,                  # 中等风险工具：默认阈值
            "low": self.max_calls_per_minute * 2                  # 低风险工具：2倍阈值
        }

        # 每个session中每个工具的调用时间戳
        # 格式: {session_id: {tool_name: deque(timestamps)}}
        self.call_timestamps: dict[str, dict[str, deque]] = {}

    def _load_policy(self, path: str) -> dict:
        """加载权限策略配置"""
        try:
            with open(path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except FileNotFoundError:
            print(f"警告: 权限策略文件不存在: {path}")
            return {}
        except Exception as e:
            print(f"警告: 加载权限策略失败: {e}")
            return {}

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
                "max_allowed": int,
                "tool_risk": str (工具风险等级)
            }
        """
        now = tool_call.timestamp
        tool_name = tool_call.tool_name

        # 初始化session
        if session_id not in self.call_timestamps:
            self.call_timestamps[session_id] = {}

        # 初始化工具的时间戳队列
        if tool_name not in self.call_timestamps[session_id]:
            self.call_timestamps[session_id][tool_name] = deque()

        # 添加当前时间戳
        self.call_timestamps[session_id][tool_name].append(now)

        # 清理过期的时间戳
        cutoff = now - timedelta(seconds=self.window_seconds)
        while self.call_timestamps[session_id][tool_name] and self.call_timestamps[session_id][tool_name][0] < cutoff:
            self.call_timestamps[session_id][tool_name].popleft()

        # 检查该工具的调用频率
        calls_in_window = len(self.call_timestamps[session_id][tool_name])

        # 根据工具风险等级获取阈值
        classification = classify_tool(tool_name)
        max_allowed = self.risk_thresholds.get(classification.risk, 10)

        if calls_in_window > max_allowed:
            return {
                "anomaly": True,
                "calls_in_window": calls_in_window,
                "window_seconds": self.window_seconds,
                "max_allowed": max_allowed,
                "tool_risk": classification.risk,
                "risk": "medium"
            }

        # 频率正常
        return {"anomaly": False}
