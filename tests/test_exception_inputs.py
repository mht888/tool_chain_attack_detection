"""
异常输入测试
测试各种异常和边界情况
"""
import pytest
from datetime import datetime
from src.core.detector import RealTimeDetector
from src.models.input import ToolCallInput
from src.core.chain_matcher import ChainMatcher
from src.core.permission_checker import PermissionChecker
from src.core.injection_checker import InjectionChecker
from src.core.frequency_checker import FrequencyChecker


class TestExceptionInputs:
    """异常输入测试类"""

    @pytest.fixture
    def detector(self):
        """创建检测器实例"""
        return RealTimeDetector(rules_dir="src/rules")

    # ========== 空值测试 ==========

    def test_empty_tool_name(self, detector):
        """测试空工具名"""
        tool_call = ToolCallInput(
            tool_name="",
            arguments={},
            timestamp=datetime.now(),
            session_id="test_empty",
            agent_name="test"
        )
        alerts = detector.on_tool_call(tool_call)
        # 不应该崩溃，应该正常返回
        assert isinstance(alerts, list)

    def test_empty_arguments(self, detector):
        """测试空参数"""
        tool_call = ToolCallInput(
            tool_name="read_file",
            arguments={},
            timestamp=datetime.now(),
            session_id="test_empty_args",
            agent_name="test"
        )
        alerts = detector.on_tool_call(tool_call)
        assert isinstance(alerts, list)

    def test_none_session_id(self, detector):
        """测试 None session_id"""
        tool_call = ToolCallInput(
            tool_name="read_file",
            arguments={"path": "/data"},
            timestamp=datetime.now(),
            session_id=None,
            agent_name="test"
        )
        alerts = detector.on_tool_call(tool_call)
        assert isinstance(alerts, list)

    # ========== 特殊字符测试 ==========

    def test_special_chars_in_tool_name(self, detector):
        """测试工具名中的特殊字符"""
        special_names = [
            "tool-with-dashes",
            "tool_with_underscores",
            "tool.with.dots",
            "tool/with/slashes",
            "tool with spaces",
            "工具中文",
            "tool\x00null",
        ]
        for name in special_names:
            tool_call = ToolCallInput(
                tool_name=name,
                arguments={},
                timestamp=datetime.now(),
                session_id="test_special",
                agent_name="test"
            )
            alerts = detector.on_tool_call(tool_call)
            assert isinstance(alerts, list), f"工具名 '{name}' 不应导致崩溃"

    def test_special_chars_in_arguments(self, detector):
        """测试参数中的特殊字符"""
        special_args = [
            {"path": "/data/../../etc/passwd"},
            {"query": "'; DROP TABLE users; --"},
            {"cmd": "$(rm -rf /)"},
            {"content": "<script>alert('xss')</script>"},
            {"data": "\x00\x01\x02\xff"},
            {"unicode": "\u0000\u2603\U0001F600"},
        ]
        for args in special_args:
            tool_call = ToolCallInput(
                tool_name="read_file",
                arguments=args,
                timestamp=datetime.now(),
                session_id="test_special_args",
                agent_name="test"
            )
            alerts = detector.on_tool_call(tool_call)
            assert isinstance(alerts, list), f"参数 {args} 不应导致崩溃"

    # ========== 超长输入测试 ==========

    def test_very_long_tool_name(self, detector):
        """测试超长工具名"""
        tool_call = ToolCallInput(
            tool_name="a" * 10000,
            arguments={},
            timestamp=datetime.now(),
            session_id="test_long_name",
            agent_name="test"
        )
        alerts = detector.on_tool_call(tool_call)
        assert isinstance(alerts, list)

    def test_very_long_arguments(self, detector):
        """测试超长参数"""
        tool_call = ToolCallInput(
            tool_name="read_file",
            arguments={"path": "/data/" + "a" * 10000},
            timestamp=datetime.now(),
            session_id="test_long_args",
            agent_name="test"
        )
        alerts = detector.on_tool_call(tool_call)
        assert isinstance(alerts, list)

    def test_deeply_nested_arguments(self, detector):
        """测试深层嵌套参数"""
        # 构建深层嵌套的 dict
        nested = {"value": "test"}
        for i in range(50):
            nested = {"level": i, "child": nested}

        tool_call = ToolCallInput(
            tool_name="read_file",
            arguments=nested,
            timestamp=datetime.now(),
            session_id="test_nested",
            agent_name="test"
        )
        alerts = detector.on_tool_call(tool_call)
        assert isinstance(alerts, list)

    def test_large_arguments_dict(self, detector):
        """测试大量参数的字典"""
        large_args = {f"param_{i}": f"value_{i}" for i in range(1000)}
        tool_call = ToolCallInput(
            tool_name="read_file",
            arguments=large_args,
            timestamp=datetime.now(),
            session_id="test_large_dict",
            agent_name="test"
        )
        alerts = detector.on_tool_call(tool_call)
        assert isinstance(alerts, list)

    # ========== 类型异常测试 ==========

    def test_numeric_arguments(self, detector):
        """测试数值类型参数"""
        tool_call = ToolCallInput(
            tool_name="calculate",
            arguments={"value": 12345, "rate": 3.14, "flag": True},
            timestamp=datetime.now(),
            session_id="test_numeric",
            agent_name="test"
        )
        alerts = detector.on_tool_call(tool_call)
        assert isinstance(alerts, list)

    def test_list_arguments(self, detector):
        """测试列表类型参数"""
        tool_call = ToolCallInput(
            tool_name="read_file",
            arguments={"paths": ["/a", "/b", "/c"], "ids": [1, 2, 3]},
            timestamp=datetime.now(),
            session_id="test_list",
            agent_name="test"
        )
        alerts = detector.on_tool_call(tool_call)
        assert isinstance(alerts, list)

    def test_mixed_type_arguments(self, detector):
        """测试混合类型参数"""
        tool_call = ToolCallInput(
            tool_name="read_file",
            arguments={
                "string": "text",
                "number": 42,
                "float": 3.14,
                "bool": True,
                "none": None,
                "list": [1, "two", 3.0],
                "dict": {"nested": "value"}
            },
            timestamp=datetime.now(),
            session_id="test_mixed",
            agent_name="test"
        )
        alerts = detector.on_tool_call(tool_call)
        assert isinstance(alerts, list)

    # ========== 并发 Session 测试 ==========

    def test_many_sessions(self, detector):
        """测试大量并发 session"""
        for i in range(100):
            tool_call = ToolCallInput(
                tool_name="read_file",
                arguments={"path": f"/data/file_{i}"},
                timestamp=datetime.now(),
                session_id=f"session_{i}",
                agent_name="test"
            )
            alerts = detector.on_tool_call(tool_call)
            assert isinstance(alerts, list)

    def test_same_tool_different_sessions(self, detector):
        """测试同一工具在不同 session 中的调用"""
        for i in range(10):
            tool_call = ToolCallInput(
                tool_name="shell",
                arguments={"command": "ls"},
                timestamp=datetime.now(),
                session_id=f"session_{i}",
                agent_name="test"
            )
            alerts = detector.on_tool_call(tool_call)
            assert isinstance(alerts, list)

    # ========== 清理机制测试 ==========

    def test_cleanup_old_sessions(self, detector):
        """测试 session 清理"""
        # 创建一些旧的 session
        old_time = datetime(2020, 1, 1, 0, 0, 0)
        for i in range(5):
            tool_call = ToolCallInput(
                tool_name="read_file",
                arguments={"path": f"/data/file_{i}"},
                timestamp=old_time,
                session_id=f"old_session_{i}",
                agent_name="test"
            )
            detector.on_tool_call(tool_call)

        # 创建一些新的 session
        for i in range(3):
            tool_call = ToolCallInput(
                tool_name="read_file",
                arguments={"path": f"/data/file_{i}"},
                timestamp=datetime.now(),
                session_id=f"new_session_{i}",
                agent_name="test"
            )
            detector.on_tool_call(tool_call)

        # 清理前
        assert len(detector.session_buffers) == 8

        # 执行清理
        detector.cleanup_old_sessions(max_age_seconds=3600)

        # 清理后，旧 session 应该被删除
        assert len(detector.session_buffers) == 3
        for i in range(3):
            assert f"new_session_{i}" in detector.session_buffers

    # ========== 边界值测试 ==========

    def test_chain_matcher_empty_buffer(self):
        """测试链模式匹配器空缓冲区"""
        matcher = ChainMatcher("src/rules/capability_chain_patterns.yaml")
        result = matcher.check([], {})
        assert result["matched"] is False
        assert result["capability_patterns"] == []

    def test_chain_matcher_single_tool(self):
        """测试链模式匹配器单工具"""
        matcher = ChainMatcher("src/rules/capability_chain_patterns.yaml")
        buffer = [ToolCallInput(
            tool_name="read_file",
            arguments={},
            timestamp=datetime.now()
        )]
        result = matcher.check(buffer, {})
        assert result["matched"] is False

    def test_injection_checker_empty_args(self):
        """测试注入检查器空参数"""
        checker = InjectionChecker("src/rules/param_grading.yaml")
        result = checker.check("read_file", {})
        assert result["detected"] is False

    def test_permission_checker_empty_tool_name(self):
        """测试权限检查器空工具名"""
        checker = PermissionChecker("src/rules/permission_policy.yaml")
        result = checker.check("")
        assert result["allowed"] is True  # 空工具名不在黑名单中

    def test_frequency_checker_rapid_calls(self, detector):
        """测试频率检查器快速调用"""
        base_time = datetime.now()
        # 快速调用 50 次
        for i in range(50):
            tool_call = ToolCallInput(
                tool_name="search",
                arguments={"query": f"test_{i}"},
                timestamp=base_time,
                session_id="test_rapid",
                agent_name="test"
            )
            alerts = detector.on_tool_call(tool_call)
            assert isinstance(alerts, list)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
