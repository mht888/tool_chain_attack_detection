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
        return ChainMatcher("src/rules/capability_chain_patterns.yaml")
    
    def test_init_loads_patterns(self, matcher):
        """测试初始化时加载模式"""
        assert len(matcher.capability_patterns) > 0
        assert all("capabilities" in p for p in matcher.capability_patterns)
        assert all("name" in p for p in matcher.capability_patterns)
    
    def test_match_simple_chain(self, matcher):
        """测试简单两能力链匹配"""
        buffer = [
            ToolCallInput(tool_name="read_file", arguments={}, timestamp=datetime.now()),
            ToolCallInput(tool_name="http_request", arguments={}, timestamp=datetime.now())
        ]
        
        # read_file -> http_request: PRIVATE_ACCESS -> EXTERNAL_ACTION
        param_risk_map = {0: "low", 1: "critical"}
        capabilities_map = {0: ["PRIVATE_ACCESS"], 1: ["EXTERNAL_ACTION"]}
        result = matcher.check(buffer, param_risk_map, capabilities_map)
        assert result["matched"] is True
        assert "capability_patterns" in result
        assert len(result["capability_patterns"]) > 0
    
    def test_no_match(self, matcher):
        """测试不匹配的情况"""
        buffer = [
            ToolCallInput(tool_name="read_file", arguments={}, timestamp=datetime.now()),
            ToolCallInput(tool_name="parse_json", arguments={}, timestamp=datetime.now())
        ]
        
        # read_file -> parse_json: PRIVATE_ACCESS -> [] (无能力)
        capabilities_map = {0: ["PRIVATE_ACCESS"], 1: []}
        result = matcher.check(buffer, capabilities_map=capabilities_map)
        # 不匹配任何能力链模式
        assert result["matched"] is False
    
    def test_three_capability_chain(self, matcher):
        """测试三能力链匹配"""
        buffer = [
            ToolCallInput(tool_name="read_file", arguments={}, timestamp=datetime.now()),
            ToolCallInput(tool_name="write_file", arguments={}, timestamp=datetime.now()),
            ToolCallInput(tool_name="http_request", arguments={}, timestamp=datetime.now())
        ]
        
        # read_file -> write_file -> http_request: PRIVATE_ACCESS -> LOCAL_MUTATION -> EXTERNAL_ACTION
        param_risk_map = {0: "low", 1: "low", 2: "critical"}
        capabilities_map = {0: ["PRIVATE_ACCESS"], 1: ["LOCAL_MUTATION"], 2: ["EXTERNAL_ACTION"]}
        result = matcher.check(buffer, param_risk_map, capabilities_map)
        assert result["matched"] is True
    
    def test_gap_tolerance(self, matcher):
        """测试间隔容忍度"""
        # 创建有间隔的能力调用链
        buffer = [
            ToolCallInput(tool_name="read_file", arguments={}, timestamp=datetime.now()),
            ToolCallInput(tool_name="parse_json", arguments={}, timestamp=datetime.now()),
            ToolCallInput(tool_name="calculate", arguments={}, timestamp=datetime.now()),
            ToolCallInput(tool_name="http_request", arguments={}, timestamp=datetime.now())
        ]
        
        # read_file -> http_request: PRIVATE_ACCESS -> EXTERNAL_ACTION
        param_risk_map = {0: "low", 1: "low", 2: "low", 3: "critical"}
        capabilities_map = {0: ["PRIVATE_ACCESS"], 1: [], 2: [], 3: ["EXTERNAL_ACTION"]}
        result = matcher.check(buffer, param_risk_map, capabilities_map)
        # read_file -> http_request 应该能匹配，即使中间有无能力的工具
        assert result["matched"] is True
    
    def test_empty_buffer(self, matcher):
        """测试空缓冲区"""
        buffer = []
        result = matcher.check(buffer)
        assert result["matched"] is False
        assert result["capability_patterns"] == []
    
    def test_single_tool_buffer(self, matcher):
        """测试单工具缓冲区"""
        buffer = [
            ToolCallInput(tool_name="read_file", arguments={}, timestamp=datetime.now())
        ]
        capabilities_map = {0: ["PRIVATE_ACCESS"]}
        result = matcher.check(buffer, capabilities_map=capabilities_map)
        # 单工具不应该匹配到两能力链
        assert result["matched"] is False
    
    def test_param_risk_map_all_low(self, matcher):
        """测试所有工具参数低风险的情况"""
        buffer = [
            ToolCallInput(tool_name="read_file", arguments={}, timestamp=datetime.now()),
            ToolCallInput(tool_name="http_request", arguments={}, timestamp=datetime.now())
        ]
        
        # 所有工具都低风险
        param_risk_map = {0: "low", 1: "low"}
        capabilities_map = {0: ["PRIVATE_ACCESS"], 1: ["EXTERNAL_ACTION"]}
        result = matcher.check(buffer, param_risk_map, capabilities_map)
        
        # 如果模式匹配但所有工具都低风险，应该跳过
        assert result["matched"] is False
        assert len(result["skipped_patterns"]) > 0
    
    def test_param_risk_not_all_low(self, matcher):
        """测试参数不全低风险的情况"""
        buffer = [
            ToolCallInput(tool_name="read_file", arguments={}, timestamp=datetime.now()),
            ToolCallInput(tool_name="http_request", arguments={}, timestamp=datetime.now())
        ]
        
        # 有工具不是低风险
        param_risk_map = {0: "low", 1: "critical"}
        capabilities_map = {0: ["PRIVATE_ACCESS"], 1: ["EXTERNAL_ACTION"]}
        result = matcher.check(buffer, param_risk_map, capabilities_map)
        
        # 应该匹配到模式
        assert result["matched"] is True
        assert len(result["capability_patterns"]) > 0
    
    def test_pattern_details(self, matcher):
        """测试返回的模式详情"""
        buffer = [
            ToolCallInput(tool_name="read_file", arguments={}, timestamp=datetime.now()),
            ToolCallInput(tool_name="http_request", arguments={}, timestamp=datetime.now())
        ]
        
        param_risk_map = {0: "low", 1: "critical"}
        capabilities_map = {0: ["PRIVATE_ACCESS"], 1: ["EXTERNAL_ACTION"]}
        result = matcher.check(buffer, param_risk_map, capabilities_map)
        
        if result["matched"]:
            for pattern in result["capability_patterns"]:
                assert "name" in pattern
                assert "risk" in pattern
                assert "description" in pattern
                assert "capabilities" in pattern
                assert "matched_indices" in pattern
    
    def test_multiple_patterns_matched(self, matcher):
        """测试匹配多个模式"""
        # read_file -> http_request: PRIVATE_ACCESS -> EXTERNAL_ACTION
        buffer = [
            ToolCallInput(tool_name="read_file", arguments={}, timestamp=datetime.now()),
            ToolCallInput(tool_name="http_request", arguments={}, timestamp=datetime.now())
        ]
        
        param_risk_map = {0: "low", 1: "critical"}
        capabilities_map = {0: ["PRIVATE_ACCESS"], 1: ["EXTERNAL_ACTION"]}
        result = matcher.check(buffer, param_risk_map, capabilities_map)
        # 应该至少匹配到一个模式
        assert result["matched"] is True
        # 可能匹配到多个模式（如 private_data_exfiltration 等）
        assert len(result["capability_patterns"]) >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
