"""
风险评分计算器
"""

from typing import Any


class RiskScorer:
    """
    风险评分计算器

    根据告警类型和详细信息计算风险评分（0-100）。
    """

    def __init__(self):
        """初始化风险评分器"""
        # 不同告警类型的基础权重
        self.alert_weights = {
            "PERMISSION_VIOLATION": 40,
            "INJECTION_DETECTED": 50,
            "DANGEROUS_CHAIN": 45,
            "FREQUENCY_ANOMALY": 20
        }

        # 风险等级的额外权重
        self.risk_weights = {
            "critical": 40,
            "high": 25,
            "medium": 15,
            "low": 5
        }

    def calculate(self, alert_type: str, details: dict[str, Any]) -> float:
        """
        计算风险评分

        Args:
            alert_type: 告警类型
            details: 详细信息

        Returns:
            风险评分（0-100）
        """
        # 基础分数
        base_score = self.alert_weights.get(alert_type, 30)

        # 根据风险等级调整
        risk = details.get("risk", "medium")
        risk_bonus = self.risk_weights.get(risk, 15)

        # 特殊规则
        if alert_type == "DANGEROUS_CHAIN":
            # 链越长，风险越高
            pattern = details.get("pattern", {})
            tools = pattern.get("tools", [])
            length_bonus = min(len(tools) * 5, 20)
            total = base_score + risk_bonus + length_bonus
        elif alert_type == "FREQUENCY_ANOMALY":
            # 频率越高，风险越高
            calls = details.get("calls_in_window", 0)
            max_allowed = details.get("max_allowed", 10)
            if max_allowed > 0:
                ratio = calls / max_allowed
                freq_bonus = min(int(ratio * 20), 30)
                total = base_score + freq_bonus
            else:
                total = base_score
        else:
            total = base_score + risk_bonus

        # 限制在0-100范围内
        return min(100.0, max(0.0, total))

    def get_risk_level(self, score: float) -> str:
        """
        根据评分获取风险等级

        Args:
            score: 风险评分

        Returns:
            风险等级：critical, high, medium, low
        """
        if score >= 70:
            return "critical"
        elif score >= 50:
            return "high"
        elif score >= 30:
            return "medium"
        else:
            return "low"
