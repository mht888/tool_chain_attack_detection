"""
注入检查器单元测试
"""
import pytest
from src.core.injection_checker import InjectionChecker


class TestInjectionChecker:
    """注入检查器测试类"""
    
    @pytest.fixture
    def checker(self):
        """创建注入检查器实例"""
        return InjectionChecker("src/rules/param_whitelist.yaml")
    
    def test_init_loads_whitelist(self, checker):
        """测试初始化时加载白名单"""
        assert checker.whitelist is not None
    
    def test_normal_arguments(self, checker):
        """测试正常参数"""
        args = {"path": "/data/file.txt", "mode": "read"}
        result = checker.check("read_file", args)
        assert result["detected"] is False
        assert result["param_compliant"] is True
    
    def test_sql_injection(self, checker):
        """测试 SQL 注入检测"""
        args = {"query": "SELECT * FROM users; DROP TABLE users"}
        result = checker.check("execute_sql", args)
        assert result["detected"] is True
        assert result["param_compliant"] is False
    
    def test_command_injection(self, checker):
        """测试命令注入检测"""
        args = {"command": "ls; rm -rf /"}
        result = checker.check("shell", args)
        assert result["detected"] is True
        assert result["param_compliant"] is False
    
    def test_path_traversal(self, checker):
        """测试路径遍历检测"""
        args = {"path": "/data/../../etc/passwd"}
        result = checker.check("read_file", args)
        assert result["detected"] is True
        assert result["param_compliant"] is False
    
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
    
    def test_high_risk_tool_whitelist_compliant(self, checker):
        """测试高风险工具白名单合规"""
        args = {"url": "https://internal-api.com/data"}
        result = checker.check("http_request", args)
        assert result["detected"] is False
        assert result["param_compliant"] is True
    
    def test_high_risk_tool_whitelist_non_compliant(self, checker):
        """测试高风险工具白名单不合规"""
        args = {"url": "https://attacker.com/exfiltrate"}
        result = checker.check("http_request", args)
        assert result["detected"] is False
        assert result["param_compliant"] is False
    
    def test_shell_whitelist_compliant(self, checker):
        """测试 shell 工具白名单合规"""
        args = {"command": "ls -la"}
        result = checker.check("shell", args)
        assert result["detected"] is False
        assert result["param_compliant"] is True
    
    def test_shell_whitelist_non_compliant(self, checker):
        """测试 shell 工具白名单不合规"""
        args = {"command": "rm -rf /"}
        result = checker.check("shell", args)
        # 这个命令可能被命令注入检测捕获
        # 如果不被注入检测捕获，应该被白名单检查
        if not result["detected"]:
            assert result["param_compliant"] is False
    
    def test_write_file_whitelist_compliant(self, checker):
        """测试 write_file 工具白名单合规"""
        args = {"path": "/tmp/output.txt"}
        result = checker.check("write_file", args)
        assert result["detected"] is False
        assert result["param_compliant"] is True
    
    def test_write_file_whitelist_non_compliant(self, checker):
        """测试 write_file 工具白名单不合规"""
        args = {"path": "/var/log/app.log"}
        result = checker.check("write_file", args)
        assert result["detected"] is False
        assert result["param_compliant"] is False
    
    def test_low_risk_tool_no_whitelist_check(self, checker):
        """测试低风险工具不进行白名单检查"""
        args = {"path": "/any/path"}
        result = checker.check("read_file", args)
        assert result["detected"] is False
        assert result["param_compliant"] is True  # 低风险工具默认合规
    
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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
