"""
工具分类器单元测试
"""
import pytest
from src.rules.tool_classifier import classify_tool, ToolClassification


class TestToolClassifier:
    """工具分类器测试类"""
    
    def test_classify_critical_tools(self):
        """测试 critical 工具分类"""
        critical_tools = [
            "shell",
            "execute_code",
            "http_request",
            "read_env",
            "delete_file",
            "send_email",
            "write_file"
        ]
        
        for tool in critical_tools:
            result = classify_tool(tool)
            assert result.risk == "critical", f"{tool} 应该是 critical，实际是 {result.risk}"
            assert isinstance(result, ToolClassification)
            assert len(result.description) > 0
    
    def test_classify_high_tools(self):
        """测试 high 工具分类"""
        high_tools = [
            "read_file",
            "execute_sql",
            "query_database"
        ]
        
        for tool in high_tools:
            result = classify_tool(tool)
            assert result.risk == "high", f"{tool} 应该是 high，实际是 {result.risk}"
            assert isinstance(result, ToolClassification)
    
    def test_classify_medium_tools(self):
        """测试 medium 工具分类"""
        medium_tools = [
            "search",
            "browse_url",
            "parse_json",
            "calculate",
            "format_text"
        ]
        
        for tool in medium_tools:
            result = classify_tool(tool)
            assert result.risk == "medium", f"{tool} 应该是 medium，实际是 {result.risk}"
            assert isinstance(result, ToolClassification)
    
    def test_classify_low_tools(self):
        """测试 low 工具分类"""
        low_tools = [
            "unknown_tool",
            "custom_tool",
            "some_random_tool"
        ]
        
        for tool in low_tools:
            result = classify_tool(tool)
            assert result.risk == "low", f"{tool} 应该是 low，实际是 {result.risk}"
            assert isinstance(result, ToolClassification)
    
    def test_pattern_matching_shell(self):
        """测试 shell 模式匹配"""
        result = classify_tool("shell")
        assert result.risk == "critical"
        assert "shell" in result.description.lower()
    
    def test_pattern_matching_http_request(self):
        """测试 http_request 模式匹配"""
        result = classify_tool("http_request")
        assert result.risk == "critical"
    
    def test_pattern_matching_read_file(self):
        """测试 read_file 模式匹配"""
        result = classify_tool("read_file")
        assert result.risk == "high"
    
    def test_pattern_matching_execute_sql(self):
        """测试 execute_sql 模式匹配"""
        result = classify_tool("execute_sql")
        assert result.risk == "high"
    
    def test_unknown_tool(self):
        """测试未知工具"""
        result = classify_tool("completely_unknown_tool_xyz")
        assert result.risk == "low"
        assert result.description == "Unknown tool"
    
    def test_case_insensitive(self):
        """测试大小写不敏感"""
        result1 = classify_tool("SHELL")
        result2 = classify_tool("shell")
        result3 = classify_tool("Shell")
        
        assert result1.risk == result2.risk == result3.risk == "critical"
    
    def test_partial_match(self):
        """测试部分匹配"""
        # 包含 "shell" 的工具名（shell 前面是单词边界）
        result = classify_tool("shell_executor")
        assert result.risk == "critical"
        
        # 包含 "read_file" 的工具名
        result = classify_tool("tool_read_file_v2")
        assert result.risk == "high"
    
    def test_return_type(self):
        """测试返回类型"""
        result = classify_tool("shell")
        assert isinstance(result, ToolClassification)
        assert hasattr(result, "risk")
        assert hasattr(result, "description")
    
    def test_description_not_empty(self):
        """测试描述不为空"""
        tools = ["shell", "read_file", "search", "unknown"]
        for tool in tools:
            result = classify_tool(tool)
            assert len(result.description) > 0, f"{tool} 的描述不应该为空"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
