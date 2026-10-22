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
CRITICAL_PATTERNS = {
    r"\bexecute[\s_-]?code\b": "Code execution",
    r"\bshell\b": "Shell command execution",
    r"\bhttp[\s_-]?request\b": "Outbound HTTP request",
    r"\bread[\s_-]?env\b": "Environment variable access",
    r"\bwrite[\s_-]?file\b": "File write capability",
    r"\bsend[\s_-]?email\b": "Email sending",
    r"\bdelete[\s_-]?file\b": "File deletion",
}

HIGH_PATTERNS = {
    r"\bread[\s_-]?file\b": "File read capability",
    r"\bexecute[\s_-]?sql\b": "SQL execution",
    r"\bquery[\s_-]?database\b": "Database query",
    r"\baccess[\s_-]?api\b": "API access",
}

MEDIUM_PATTERNS = {
    r"\bsearch\b": "Search capability",
    r"\bparse\b": "Data parsing",
    r"\bcalculate\b": "Calculation",
    r"\bformat\b": "Data formatting",
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


def is_high_risk(tool_name: str) -> bool:
    """检查工具是否高风险"""
    classification = classify_tool(tool_name)
    return classification.risk in ("critical", "high")
