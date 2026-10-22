"""
检测报告模型（生成Markdown）
"""

from datetime import datetime
from typing import Optional

from src.models.alert import Alert


class DetectionReport:
    """
    检测报告

    记录整个检测过程，生成Markdown格式的报告。
    """

    def __init__(self, session_id: str):
        """
        初始化报告

        Args:
            session_id: 会话ID
        """
        self.session_id = session_id
        self.start_time = datetime.now()
        self.end_time: Optional[datetime] = None
        self.total_tool_calls = 0
        self.alerts: list[Alert] = []
        self.tool_call_log: list[dict] = []

    def add_tool_call(self, tool_name: str, arguments: dict, blocked: bool = False):
        """
        记录工具调用

        Args:
            tool_name: 工具名称
            arguments: 工具参数
            blocked: 是否被阻止
        """
        self.total_tool_calls += 1
        self.tool_call_log.append({
            "tool": tool_name,
            "arguments": arguments,
            "blocked": blocked,
            "timestamp": datetime.now()
        })

    def add_alert(self, alert: Alert):
        """添加告警"""
        self.alerts.append(alert)

    def finalize(self):
        """完成报告"""
        self.end_time = datetime.now()

    def to_markdown(self) -> str:
        """生成Markdown报告"""
        lines = []

        # 标题
        lines.append("# 工具调用链安全检测报告")
        lines.append("")
        lines.append(f"**生成时间:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")

        # 摘要
        lines.append("## 检测摘要")
        lines.append("")
        lines.append(f"- **会话ID:** {self.session_id}")
        lines.append(f"- **检测时长:** {self._format_duration()}")
        lines.append(f"- **工具调用总数:** {self.total_tool_calls}")
        lines.append(f"- **告警数量:** {len(self.alerts)}")
        lines.append(f"- **最高风险等级:** {self._get_highest_risk()}")
        lines.append(f"- **综合风险评分:** {self._calculate_overall_risk_score()}/100")
        lines.append("")

        # 风险判定
        overall_score = self._calculate_overall_risk_score()
        verdict = self._get_verdict(overall_score)
        lines.append(f"### 风险判定: **{verdict}**")
        lines.append("")

        if verdict.startswith("SAFE"):
            lines.append("✅ 未检测到明显的安全威胁")
        elif verdict.startswith("SUSPICIOUS"):
            lines.append("⚠️ 检测到可疑行为，建议人工审查")
        else:
            lines.append("🚨 检测到恶意行为，已阻止危险操作")
        lines.append("")

        # 告警详情
        if self.alerts:
            lines.append("## 告警详情")
            lines.append("")

            for i, alert in enumerate(self.alerts, 1):
                lines.append(f"### 告警 {i}: {alert.alert_type}")
                lines.append("")
                lines.append(f"- **告警ID:** {alert.alert_id}")
                lines.append(f"- **风险等级:** {self._format_risk_level(alert.risk_level)}")
                lines.append(f"- **风险评分:** {alert.risk_score}/100")
                lines.append(f"- **时间:** {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
                lines.append("")

                # 根据告警类型显示不同详情
                if alert.alert_type == "DANGEROUS_CHAIN":
                    pattern = alert.details.get("pattern", {})
                    lines.append(f"**危险链模式:** {pattern.get('name', 'unknown')}")
                    lines.append("")
                    lines.append(f"**描述:** {pattern.get('description', '')}")
                    lines.append("")
                    lines.append("**工具调用链:**")
                    lines.append("")
                    lines.append("```")
                    lines.append(" → ".join(alert.tool_chain))
                    lines.append("```")
                    lines.append("")

                elif alert.alert_type == "PERMISSION_VIOLATION":
                    lines.append(f"**违规工具:** {alert.details.get('tool_name', '')}")
                    lines.append("")
                    lines.append(f"**原因:** {alert.details.get('reason', '')}")
                    lines.append("")

                elif alert.alert_type == "INJECTION_DETECTED":
                    lines.append(f"**攻击类型:** {alert.details.get('attack_type', '')}")
                    lines.append("")
                    lines.append(f"**检测模式:** `{alert.details.get('pattern', '')}`")
                    lines.append("")
                    lines.append("**恶意参数:**")
                    lines.append("```")
                    lines.append(alert.details.get('malicious_param', ''))
                    lines.append("```")
                    lines.append("")

                elif alert.alert_type == "FREQUENCY_ANOMALY":
                    lines.append(f"**调用频率:** {alert.details.get('calls_in_window', 0)} 次/{alert.details.get('window_seconds', 60)}秒")
                    lines.append("")
                    lines.append(f"**阈值:** {alert.details.get('max_allowed', 10)} 次/{alert.details.get('window_seconds', 60)}秒")
                    lines.append("")

                # 建议
                recommendation = alert.details.get("recommendation") or alert.details.get("pattern", {}).get("recommendation", "")
                if recommendation:
                    lines.append(f"**建议:** {recommendation}")
                    lines.append("")

                lines.append("---")
                lines.append("")

        # 工具调用时间线
        lines.append("## 工具调用时间线")
        lines.append("")
        lines.append("| 序号 | 时间 | 工具 | 状态 |")
        lines.append("|------|------|------|------|")

        for i, call in enumerate(self.tool_call_log, 1):
            time_str = call['timestamp'].strftime('%H:%M:%S')
            status = "🚫 已阻止" if call['blocked'] else "✓ 已执行"
            lines.append(f"| {i} | {time_str} | `{call['tool']}` | {status} |")

        lines.append("")

        # 工具调用链可视化
        if self.tool_call_log:
            lines.append("## 工具调用链")
            lines.append("")
            lines.append("```")

            for i, call in enumerate(self.tool_call_log):
                if i > 0:
                    lines.append("  ↓")
                lines.append(f"  [{i+1}] {call['tool']}")

            lines.append("```")
            lines.append("")

        # 统计分析
        lines.append("## 统计分析")
        lines.append("")

        # 工具使用频率
        tool_counts: dict[str, int] = {}
        for call in self.tool_call_log:
            tool = call['tool']
            tool_counts[tool] = tool_counts.get(tool, 0) + 1

        lines.append("### 工具使用频率")
        lines.append("")
        lines.append("| 工具 | 调用次数 |")
        lines.append("|------|---------|")
        for tool, count in sorted(tool_counts.items(), key=lambda x: -x[1]):
            lines.append(f"| `{tool}` | {count} |")
        lines.append("")

        # 风险分布
        if self.alerts:
            risk_counts: dict[str, int] = {}
            for alert in self.alerts:
                risk = alert.risk_level
                risk_counts[risk] = risk_counts.get(risk, 0) + 1

            lines.append("### 风险等级分布")
            lines.append("")
            lines.append("| 风险等级 | 数量 |")
            lines.append("|---------|------|")
            for risk in ['critical', 'high', 'medium', 'low']:
                count = risk_counts.get(risk, 0)
                if count > 0:
                    lines.append(f"| {self._format_risk_level(risk)} | {count} |")
            lines.append("")

        # 页脚
        lines.append("---")
        lines.append("")
        lines.append(f"*报告由工具调用链安全检测系统生成 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")

        return "\n".join(lines)

    def _format_duration(self) -> str:
        """格式化检测时长"""
        if not self.end_time:
            return "进行中"

        duration = (self.end_time - self.start_time).total_seconds()
        if duration < 60:
            return f"{duration:.1f}秒"
        elif duration < 3600:
            minutes = int(duration // 60)
            seconds = int(duration % 60)
            return f"{minutes}分{seconds}秒"
        else:
            hours = int(duration // 3600)
            minutes = int((duration % 3600) // 60)
            return f"{hours}小时{minutes}分"

    def _get_highest_risk(self) -> str:
        """获取最高风险等级"""
        if not self.alerts:
            return "无"

        risk_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        highest = max(self.alerts, key=lambda a: risk_order.get(a.risk_level, 0))
        return self._format_risk_level(highest.risk_level)

    def _calculate_overall_risk_score(self) -> float:
        """计算综合风险评分"""
        if not self.alerts:
            return 0.0

        # 取最高风险评分 + 告警数量加成
        max_score = max(alert.risk_score for alert in self.alerts)
        count_bonus = min(len(self.alerts) * 5, 30)

        return min(100, max_score + count_bonus)

    def _get_verdict(self, score: float) -> str:
        """根据评分给出判定"""
        if score >= 70:
            return "MALICIOUS（恶意）"
        elif score >= 30:
            return "SUSPICIOUS（可疑）"
        else:
            return "SAFE（安全）"

    def _format_risk_level(self, risk: str) -> str:
        """格式化风险等级（带emoji）"""
        emojis = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🟢'
        }
        emoji = emojis.get(risk, '⚪')
        return f"{emoji} {risk.upper()}"

    def save(self, filepath: str):
        """保存报告到文件"""
        self.finalize()
        content = self.to_markdown()
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
