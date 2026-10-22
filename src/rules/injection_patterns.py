"""
注入检测正则模式

定义各种注入攻击的检测模式。
"""

from typing import Dict, List

INJECTION_PATTERNS: Dict[str, List[str]] = {
    # SQL注入模式
    "sql_injection": [
        r"UNION\s+SELECT",
        r"UNION\s+ALL\s+SELECT",
        r"DROP\s+TABLE",
        r"DROP\s+DATABASE",
        r"DELETE\s+FROM",
        r"INSERT\s+INTO.*VALUES",
        r"UPDATE\s+\w+\s+SET",
        r"OR\s+1\s*=\s*1",
        r"OR\s+'1'\s*=\s*'1'",
        r"OR\s+\"1\"\s*=\s*\"1\"",
        r"AND\s+1\s*=\s*1",
        r";\s*--",
        r"'\s*OR\s+'",
        r"'\s*;\s*DROP",
        r"EXEC\s*\(",
        r"EXECUTE\s*\(",
        r"xp_cmdshell",
    ],

    # 命令注入模式
    "command_injection": [
        r";\s*rm\s+-rf",
        r";\s*rm\s+/",
        r"\|\s*cat\s+/etc/passwd",
        r"\|\s*cat\s+/etc/shadow",
        r"\|\s*whoami",
        r"\|\s*id",
        r"\|\s*uname\s+-a",
        r"\|\s*ls\s+-la",
        r"\$\(",  # 命令替换 $(...)
        r"`[^`]+`",  # 命令替换 `...`
        r";\s*wget\s+",
        r";\s*curl\s+",
        r";\s*nc\s+-",  # netcat
        r";\s*bash\s+-i",
        r";\s*sh\s+-i",
        r";\s*python\s+-c",
        r";\s*perl\s+-e",
    ],

    # 路径遍历模式
    "path_traversal": [
        r"\.\./",
        r"\.\.\\",
        r"\.\.%2f",
        r"\.\.%5c",
        r"%2e%2e%2f",
        r"%2e%2e/",
        r"\.\.%255c",
        r"/etc/passwd",
        r"/etc/shadow",
        r"/proc/self",
        r"C:\\Windows\\System32",
    ],

    # XSS模式
    "xss": [
        r"<script[^>]*>",
        r"javascript\s*:",
        r"on\w+\s*=",
        r"<iframe[^>]*>",
        r"<object[^>]*>",
        r"<embed[^>]*>",
        r"eval\s*\(",
        r"document\.cookie",
        r"document\.write",
        r"window\.location",
    ],

    # LDAP注入模式
    "ldap_injection": [
        r"\)\s*\(\|",
        r"\)\s*\(&",
        r"\)\s*\!",
        r"\*\(objectclass",
        r"\)\s*\)\s*\(",
    ],
}
