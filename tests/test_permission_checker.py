"""
权限检查器单元测试
"""
import pytest
from src.core.permission_checker import PermissionChecker


class TestPermissionChecker:
    """权限检查器测试类"""
    
    @pytest.fixture
    def checker(self):
        """创建权限检查器实例"""
        return PermissionChecker("src/rules/permission_policy.yaml")
    
    def test_init_loads_policy(self, checker):
        """测试初始化时加载策略"""
        assert checker.policy is not None
        assert "allowed_tools" in checker.policy
        assert "forbidden_tools" in checker.policy
    
    def test_allowed_tool(self, checker):
        """测试允许的工具"""
        result = checker.check("read_file")
        assert result["allowed"] is True
        assert result["blocked"] is False
    
    def test_forbidden_tool(self, checker):
        """测试禁止的工具"""
        result = checker.check("execute_code")
        assert result["allowed"] is False
        assert result["blocked"] is True
        assert result["risk"] == "critical"
    
    def test_unknown_tool(self, checker):
        """测试未知工具"""
        result = checker.check("unknown_tool_xyz")
        # 未知工具不在白名单中，应该被标记
        assert result["allowed"] is True  # 允许但标记风险
        assert result["blocked"] is False
        assert "risk" in result
    
    def test_shell_tool(self, checker):
        """测试 shell 工具"""
        result = checker.check("shell")
        # shell 不在白名单中，但也不在黑名单中
        assert result["allowed"] is True
        assert result["blocked"] is False
    
    def test_http_request_tool(self, checker):
        """测试 http_request 工具"""
        result = checker.check("http_request")
        # http_request 不在白名单中
        assert result["allowed"] is True
        assert result["blocked"] is False
    
    def test_send_email_tool(self, checker):
        """测试 send_email 工具"""
        result = checker.check("send_email")
        # send_email 在黑名单中
        assert result["allowed"] is False
        assert result["blocked"] is True
    
    def test_tool_risk_levels_loaded(self, checker):
        """测试工具风险等级配置已加载"""
        assert hasattr(checker, "tool_risk_levels")
        # tool_risk_levels 应该包含一些工具的风险等级
    
    def test_allowed_tool_details(self, checker):
        """测试允许工具的返回详情"""
        result = checker.check("read_file")
        assert "tool_name" in result
        assert result["tool_name"] == "read_file"
        assert result["allowed"] is True
        assert result["blocked"] is False
    
    def test_forbidden_tool_details(self, checker):
        """测试禁止工具的返回详情"""
        result = checker.check("execute_code")
        assert "tool_name" in result
        assert result["tool_name"] == "execute_code"
        assert result["allowed"] is False
        assert result["blocked"] is True
        assert "reason" in result
        assert "risk_note" in result
    
    def test_multiple_allowed_tools(self, checker):
        """测试多个允许的工具"""
        allowed_tools = ["read_file", "execute_sql", "search", "parse_json", "calculate"]
        for tool in allowed_tools:
            result = checker.check(tool)
            assert result["allowed"] is True, f"{tool} 应该是允许的"
    
    def test_multiple_forbidden_tools(self, checker):
        """测试多个禁止的工具"""
        forbidden_tools = ["execute_code", "send_email"]
        for tool in forbidden_tools:
            result = checker.check(tool)
            assert result["allowed"] is False, f"{tool} 应该是禁止的"
            assert result["blocked"] is True, f"{tool} 应该被阻断"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
