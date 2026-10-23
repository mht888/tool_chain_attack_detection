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
        assert "forbidden_tools" in checker.policy
        # 白名单已取消
        assert "allowed_tools" not in checker.policy

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
        """测试未知工具：非黑名单一律放行，不做标记"""
        result = checker.check("unknown_tool_xyz")
        assert result["allowed"] is True
        assert result["blocked"] is False
        assert result["risk_note"] is None

    def test_shell_tool(self, checker):
        """测试 shell 工具：非黑名单，放行"""
        result = checker.check("shell")
        assert result["allowed"] is True
        assert result["blocked"] is False

    def test_http_request_tool(self, checker):
        """测试 http_request 工具：非黑名单，放行"""
        result = checker.check("http_request")
        assert result["allowed"] is True
        assert result["blocked"] is False

    def test_send_email_tool(self, checker):
        """测试 send_email 工具"""
        result = checker.check("send_email")
        # send_email 在黑名单中
        assert result["allowed"] is False
        assert result["blocked"] is True
    
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
        """测试多个放行的工具（原白名单工具 + 高风险工具）"""
        allowed_tools = ["read_file", "execute_sql", "search", "parse_json", "calculate",
                         "shell", "http_request", "write_file", "read_env"]
        for tool in allowed_tools:
            result = checker.check(tool)
            assert result["allowed"] is True, f"{tool} 应该是允许的"
            assert result["blocked"] is False, f"{tool} 不应该被阻断"

    def test_multiple_forbidden_tools(self, checker):
        """测试多个禁止的工具（含新增黑名单）"""
        forbidden_tools = ["execute_code", "send_email", "python_repl",
                           "deploy", "run_pipeline", "write_permissions"]
        for tool in forbidden_tools:
            result = checker.check(tool)
            assert result["allowed"] is False, f"{tool} 应该是禁止的"
            assert result["blocked"] is True, f"{tool} 应该被阻断"

    def test_new_forbidden_tools_reason(self, checker):
        """测试新增黑名单工具的阻断详情"""
        for tool in ["python_repl", "deploy", "run_pipeline", "write_permissions"]:
            result = checker.check(tool)
            assert result["risk"] == "critical"
            assert "黑名单" in result["reason"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
