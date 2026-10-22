"""
工具风险分类器（从ZIRAN借鉴）

使用正则表达式对工具进行风险分类。
"""

import re
from typing import NamedTuple


class ToolClassification(NamedTuple):
    """工具分类结果"""
    risk: str  # critical, high, medium, low
    description: str


# 关键风险模式（从ZIRAN的tool_classifier.py借鉴）
# 使用 (?:^|[\s_-]) 和 (?:$|[\s_-]) 替代 \b，以匹配下划线分隔的工具名
CRITICAL_PATTERNS = {
    r"(?:^|[\s_-])execute[\s_-]?code(?:$|[\s_-])": "Code execution",
    r"(?:^|[\s_-])shell(?:$|[\s_-])": "Shell command execution",
    r"(?:^|[\s_-])http[\s_-]?request(?:$|[\s_-])": "Outbound HTTP request",
    r"(?:^|[\s_-])read[\s_-]?env(?:$|[\s_-])": "Environment variable access",
    r"(?:^|[\s_-])write[\s_-]?file(?:$|[\s_-])": "File write capability",
    r"(?:^|[\s_-])send[\s_-]?email(?:$|[\s_-])": "Email sending",
    r"(?:^|[\s_-])delete[\s_-]?file(?:$|[\s_-])": "File deletion",
}

HIGH_PATTERNS = {
    r"(?:^|[\s_-])read[\s_-]?file(?:$|[\s_-])": "File read capability",
    r"(?:^|[\s_-])execute[\s_-]?sql(?:$|[\s_-])": "SQL execution",
    r"(?:^|[\s_-])query[\s_-]?database(?:$|[\s_-])": "Database query",
    r"(?:^|[\s_-])access[\s_-]?api(?:$|[\s_-])": "API access",
}

MEDIUM_PATTERNS = {
    r"(?:^|[\s_-])search(?:$|[\s_-])": "Search capability",
    r"(?:^|[\s_-])parse(?:$|[\s_-])": "Data parsing",
    r"(?:^|[\s_-])calculate(?:$|[\s_-])": "Calculation",
    r"(?:^|[\s_-])format(?:$|[\s_-])": "Data formatting",
    r"(?:^|[\s_-])browse[\s_-]?url(?:$|[\s_-])": "URL browsing",
}


def classify_tool(tool_name: str) -> ToolClassification:
    """
    分类工具风险等级

    Args:
        tool_name: 工具名称

    Returns:
        ToolClassification(risk, description)
    """
    # 检查critical级别
    for pattern, description in CRITICAL_PATTERNS.items():
        if re.search(pattern, tool_name, re.IGNORECASE):
            return ToolClassification(risk="critical", description=description)

    # 检查high级别
    for pattern, description in HIGH_PATTERNS.items():
        if re.search(pattern, tool_name, re.IGNORECASE):
            return ToolClassification(risk="high", description=description)

    # 检查medium级别
    for pattern, description in MEDIUM_PATTERNS.items():
        if re.search(pattern, tool_name, re.IGNORECASE):
            return ToolClassification(risk="medium", description=description)

    # 默认low级别
    return ToolClassification(risk="low", description="Unknown tool")
