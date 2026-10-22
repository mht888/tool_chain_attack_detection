"""
频率检查器单元测试
"""
import pytest
from datetime import datetime, timedelta
from src.core.frequency_checker import FrequencyChecker
from src.models.input import ToolCallInput


class TestFrequencyChecker:
    """频率检查器测试类"""
    
    @pytest.fixture
    def checker(self):
        """创建频率检查器实例"""
        return FrequencyChecker("src/rules/permission_policy.yaml")
    
    def test_init_loads_config(self, checker):
        """测试初始化时加载配置"""
        assert checker.max_calls_per_minute > 0
        assert checker.window_seconds == 60
    
    def test_risk_thresholds(self, checker):
        """测试风险阈值配置"""
        assert "critical" in checker.risk_thresholds
        assert "high" in checker.risk_thresholds
        assert "medium" in checker.risk_thresholds
        assert "low" in checker.risk_thresholds
        
        # critical 工具阈值最低
        assert checker.risk_thresholds["critical"] < checker.risk_thresholds["low"]
    
    def test_normal_frequency(self, checker):
        """测试正常频率"""
        base_time = datetime.now()
        
        # 低风险工具调用 5 次（阈值 20）
        for i in range(5):
            tool_call = ToolCallInput(
                tool_name="search",
                arguments={"query": f"test{i}"},
                timestamp=base_time + timedelta(seconds=i)
            )
            result = checker.check("session1", tool_call)
        
        assert result["anomaly"] is False
    
    def test_high_frequency_anomaly(self, checker):
        """测试高频异常"""
        base_time = datetime.now()
        
        # 低风险工具调用 25 次（阈值 20）
        for i in range(25):
            tool_call = ToolCallInput(
                tool_name="search",
                arguments={"query": f"test{i}"},
                timestamp=base_time + timedelta(seconds=i)
            )
            result = checker.check("session1", tool_call)
        
        # 第 21 次开始应该检测到异常
        assert result["anomaly"] is True
    
    def test_critical_tool_low_threshold(self, checker):
        """测试 critical 工具低阈值"""
        base_time = datetime.now()
        
        # critical 工具调用 4 次（阈值 3）
        for i in range(4):
            tool_call = ToolCallInput(
                tool_name="shell",
                arguments={"command": f"cmd{i}"},
                timestamp=base_time + timedelta(seconds=i)
            )
            result = checker.check("session1", tool_call)
        
        # 第 4 次应该检测到异常
        assert result["anomaly"] is True
    
    def test_per_tool_tracking(self, checker):
        """测试按工具分别统计"""
        base_time = datetime.now()
        
        # search 调用 15 次（阈值 20）
        for i in range(15):
            tool_call = ToolCallInput(
                tool_name="search",
                arguments={"query": f"test{i}"},
                timestamp=base_time + timedelta(seconds=i)
            )
            checker.check("session1", tool_call)
        
        # shell 调用 2 次（阈值 3）
        for i in range(2):
            tool_call = ToolCallInput(
                tool_name="shell",
                arguments={"command": f"cmd{i}"},
                timestamp=base_time + timedelta(seconds=i)
            )
            result = checker.check("session1", tool_call)
        
        # shell 不应该检测到异常
        assert result["anomaly"] is False
    
    def test_per_session_tracking(self, checker):
        """测试按会话分别统计"""
        base_time = datetime.now()
        
        # session1 中 shell 调用 2 次
        for i in range(2):
            tool_call = ToolCallInput(
                tool_name="shell",
                arguments={"command": f"cmd{i}"},
                timestamp=base_time + timedelta(seconds=i)
            )
            checker.check("session1", tool_call)
        
        # session2 中 shell 调用 2 次
        for i in range(2):
            tool_call = ToolCallInput(
                tool_name="shell",
                arguments={"command": f"cmd{i}"},
                timestamp=base_time + timedelta(seconds=i)
            )
            result = checker.check("session2", tool_call)
        
        # session2 的 shell 不应该检测到异常（独立统计）
        assert result["anomaly"] is False
    
    def test_time_window_cleanup(self, checker):
        """测试时间窗口清理"""
        base_time = datetime.now()
        
        # 在时间窗口内调用 10 次
        for i in range(10):
            tool_call = ToolCallInput(
                tool_name="search",
                arguments={"query": f"test{i}"},
                timestamp=base_time + timedelta(seconds=i)
            )
            checker.check("session1", tool_call)
        
        # 在时间窗口外调用
        tool_call = ToolCallInput(
            tool_name="search",
            arguments={"query": "test"},
            timestamp=base_time + timedelta(seconds=120)  # 2 分钟后
        )
        result = checker.check("session1", tool_call)
        
        # 旧的调用应该被清理，不应该检测到异常
        assert result["anomaly"] is False
    
    def test_result_format(self, checker):
        """测试结果格式"""
        base_time = datetime.now()
        
        tool_call = ToolCallInput(
            tool_name="search",
            arguments={"query": "test"},
            timestamp=base_time
        )
        result = checker.check("session1", tool_call)
        
        assert "anomaly" in result
        assert isinstance(result["anomaly"], bool)
        
        if result["anomaly"]:
            assert "calls_in_window" in result
            assert "max_allowed" in result
            assert "tool_risk" in result
    
    def test_different_risk_levels(self, checker):
        """测试不同风险等级的工具"""
        base_time = datetime.now()
        
        # 测试不同风险等级的工具
        tools = [
            ("shell", "critical"),
            ("write_file", "high"),
            ("search", "medium"),
            ("parse_json", "low")
        ]
        
        for tool_name, expected_risk in tools:
            tool_call = ToolCallInput(
                tool_name=tool_name,
                arguments={},
                timestamp=base_time
            )
            result = checker.check(f"session_{tool_name}", tool_call)
            
            # 检查返回结果中包含工具风险等级
            if result.get("anomaly"):
                assert result.get("tool_risk") == expected_risk


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
