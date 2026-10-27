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


class TestNewCapabilityChains:
    """FC-8/9/10/14 新增功能链测试"""

    @pytest.fixture
    def matcher(self):
        return ChainMatcher("src/rules/capability_chain_patterns.yaml")

    def _check(self, matcher, caps, risks):
        buffer = [
            ToolCallInput(tool_name=f"tool_{i}", arguments={}, timestamp=datetime.now())
            for i in range(len(caps))
        ]
        return matcher.check(
            buffer,
            param_risk_map={i: r for i, r in enumerate(risks)},
            capabilities_map={i: c for i, c in enumerate(caps)},
        )

    def test_fc8_external_content_exfiltration(self, matcher):
        """浏览/爬取外部内容后外传 -> FC-8"""
        result = self._check(
            matcher,
            caps=[["EXTERNAL_INGESTION"], ["EXTERNAL_ACTION"]],
            risks=["high", "critical"],
        )
        names = [p["name"] for p in result["capability_patterns"]]
        assert "external_content_exfiltration" in names

    def test_fc9_external_action_to_mutation(self, matcher):
        """对外请求后写入本地 -> FC-9"""
        result = self._check(
            matcher,
            caps=[["EXTERNAL_ACTION"], ["LOCAL_MUTATION"]],
            risks=["critical", "high"],
        )
        names = [p["name"] for p in result["capability_patterns"]]
        assert "external_action_to_mutation" in names

    def test_fc10_external_action_then_read(self, matcher):
        """对外请求后读取内部数据 -> FC-10"""
        result = self._check(
            matcher,
            caps=[["EXTERNAL_ACTION"], ["PRIVATE_ACCESS"]],
            risks=["critical", "medium"],
        )
        names = [p["name"] for p in result["capability_patterns"]]
        assert "external_action_then_read" in names

    def test_fc14_read_then_privilege_escalation(self, matcher):
        """读取内部数据后伪造高权令牌 -> FC-14"""
        result = self._check(
            matcher,
            caps=[["PRIVATE_ACCESS"], ["CREDENTIAL_ACCESS", "PRIVILEGE_CHANGE"]],
            risks=["low", "medium"],
        )
        names = [p["name"] for p in result["capability_patterns"]]
        assert "read_then_privilege_escalation" in names

    def test_new_chains_risk_levels(self, matcher):
        """FC-8/14 为 critical，FC-9/10 为 high"""
        patterns = {p["name"]: p for p in matcher.capability_patterns}
        assert patterns["external_content_exfiltration"]["risk"] == "critical"
        assert patterns["read_then_privilege_escalation"]["risk"] == "critical"
        assert patterns["external_action_to_mutation"]["risk"] == "high"
        assert patterns["external_action_then_read"]["risk"] == "high"

    def test_pattern_count(self, matcher):
        """模式库共 14 个功能链"""
        assert len(matcher.capability_patterns) == 14


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
