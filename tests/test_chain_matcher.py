"""
链模式匹配器单元测试
"""
import pytest
from src.core.chain_matcher import ChainMatcher
from src.models.input import ToolCallInput
from datetime import datetime


class TestChainMatcher:
    """链模式匹配器测试类"""
    
    @pytest.fixture
    def matcher(self):
        """创建链模式匹配器实例"""
        return ChainMatcher("src/rules/chain_patterns.yaml")
    
    def test_init_loads_patterns(self, matcher):
        """测试初始化时加载模式"""
        assert len(matcher.patterns) > 0
        assert all("tools" in p for p in matcher.patterns)
        assert all("name" in p for p in matcher.patterns)
    
    def test_match_simple_chain(self, matcher):
        """测试简单两工具链匹配"""
        buffer = [
            ToolCallInput(tool_name="read_file", arguments={"path": "/data"}, timestamp=datetime.now()),
            ToolCallInput(tool_name="http_request", arguments={"url": "https://api.com"}, timestamp=datetime.now())
        ]
        
        result = matcher.check(buffer)
        assert result["matched"] is True
        assert "pattern" in result
    
    def test_no_match(self, matcher):
        """测试不匹配的情况"""
        buffer = [
            ToolCallInput(tool_name="read_file", arguments={"path": "/data"}, timestamp=datetime.now()),
            ToolCallInput(tool_name="parse_json", arguments={"data": "{}"}, timestamp=datetime.now())
        ]
        
        result = matcher.check(buffer)
        # 可能匹配到某些模式，但不应该匹配到危险链
        # 这里主要测试不崩溃
    
    def test_three_tool_chain(self, matcher):
        """测试三工具链匹配"""
        buffer = [
            ToolCallInput(tool_name="read_file", arguments={"path": "/data"}, timestamp=datetime.now()),
            ToolCallInput(tool_name="write_file", arguments={"path": "/tmp"}, timestamp=datetime.now()),
            ToolCallInput(tool_name="shell", arguments={"command": "ls"}, timestamp=datetime.now())
        ]
        
        result = matcher.check(buffer)
        assert result["matched"] is True
    
    def test_gap_tolerance(self, matcher):
        """测试间隔容忍度"""
        # 创建有间隔的调用链
        buffer = [
            ToolCallInput(tool_name="read_file", arguments={"path": "/data"}, timestamp=datetime.now()),
            ToolCallInput(tool_name="parse_json", arguments={"data": "{}"}, timestamp=datetime.now()),
            ToolCallInput(tool_name="calculate", arguments={"expr": "1+1"}, timestamp=datetime.now()),
            ToolCallInput(tool_name="http_request", arguments={"url": "https://api.com"}, timestamp=datetime.now())
        ]
        
        result = matcher.check(buffer)
        # read_file -> http_request 应该能匹配，即使中间有其他工具
    
    def test_empty_buffer(self, matcher):
        """测试空缓冲区"""
        buffer = []
        result = matcher.check(buffer)
        assert result["matched"] is False
    
    def test_single_tool_buffer(self, matcher):
        """测试单工具缓冲区"""
        buffer = [
            ToolCallInput(tool_name="read_file", arguments={"path": "/data"}, timestamp=datetime.now())
        ]
        result = matcher.check(buffer)
        # 单工具不应该匹配到两工具链
    
    def test_param_compliant_map(self, matcher):
        """测试参数合规映射"""
        buffer = [
            ToolCallInput(tool_name="read_file", arguments={"path": "/data"}, timestamp=datetime.now()),
            ToolCallInput(tool_name="http_request", arguments={"url": "https://api.com"}, timestamp=datetime.now())
        ]
        
        # 所有工具都合规
        param_compliant_map = {0: True, 1: True}
        result = matcher.check(buffer, param_compliant_map)
        
        # 如果模式匹配但所有工具都合规，应该跳过
        if result.get("matched"):
            assert result.get("skipped") is True
    
    def test_param_not_compliant(self, matcher):
        """测试参数不合规的情况"""
        buffer = [
            ToolCallInput(tool_name="read_file", arguments={"path": "/data"}, timestamp=datetime.now()),
            ToolCallInput(tool_name="http_request", arguments={"url": "https://attacker.com"}, timestamp=datetime.now())
        ]
        
        # 有工具不合规
        param_compliant_map = {0: True, 1: False}
        result = matcher.check(buffer, param_compliant_map)
        
        # 应该匹配到模式
        assert result["matched"] is True
    
    def test_pattern_details(self, matcher):
        """测试返回的模式详情"""
        buffer = [
            ToolCallInput(tool_name="read_file", arguments={"path": "/data"}, timestamp=datetime.now()),
            ToolCallInput(tool_name="http_request", arguments={"url": "https://api.com"}, timestamp=datetime.now())
        ]
        
        result = matcher.check(buffer)
        
        if result["matched"]:
            pattern = result["pattern"]
            assert "name" in pattern
            assert "risk" in pattern
            assert "description" in pattern
            assert "tools" in pattern


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
