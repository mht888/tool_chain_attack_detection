"""
风险评分器单元测试
"""
import pytest
from src.core.risk_scorer import RiskScorer


class TestRiskScorer:
    """风险评分器测试类"""
    
    @pytest.fixture
    def scorer(self):
        """创建风险评分器实例"""
        return RiskScorer()
    
    def test_init(self, scorer):
        """测试初始化"""
        assert scorer is not None
        assert hasattr(scorer, "alert_weights")
        assert hasattr(scorer, "risk_weights")
    
    def test_permission_violation_score(self, scorer):
        """测试权限违规评分"""
        details = {
            "tool_name": "execute_code",
            "risk": "critical"
        }
        score = scorer.calculate("PERMISSION_VIOLATION", details)
        
        assert 0 <= score <= 100
        assert score >= 40  # 基础分 40
    
    def test_injection_detected_score(self, scorer):
        """测试注入检测评分"""
        details = {
            "risk": "critical",
            "attack_type": "sql_injection"
        }
        score = scorer.calculate("INJECTION_DETECTED", details)
        
        assert 0 <= score <= 100
        assert score >= 50  # 基础分 50
    
    def test_dangerous_chain_score(self, scorer):
        """测试危险链评分"""
        details = {
            "risk": "critical",
            "pattern": {
                "name": "data_exfiltration",
                "tools": ["read_file", "http_request"]
            }
        }
        score = scorer.calculate("DANGEROUS_CHAIN", details)
        
        assert 0 <= score <= 100
        assert score >= 45  # 基础分 45
    
    def test_frequency_anomaly_score(self, scorer):
        """测试频率异常评分"""
        details = {
            "calls_in_window": 15,
            "max_allowed": 10,
            "tool_risk": "medium"
        }
        score = scorer.calculate("FREQUENCY_ANOMALY", details)
        
        assert 0 <= score <= 100
        assert score >= 20  # 基础分 20
    
    def test_risk_level_critical(self, scorer):
        """测试 critical 风险等级"""
        level = scorer.get_risk_level(85)
        assert level == "critical"
    
    def test_risk_level_high(self, scorer):
        """测试 high 风险等级"""
        level = scorer.get_risk_level(60)
        assert level == "high"
    
    def test_risk_level_medium(self, scorer):
        """测试 medium 风险等级"""
        level = scorer.get_risk_level(40)
        assert level == "medium"
    
    def test_risk_level_low(self, scorer):
        """测试 low 风险等级"""
        level = scorer.get_risk_level(20)
        assert level == "low"
    
    def test_score_boundary_70(self, scorer):
        """测试 70 分边界"""
        level = scorer.get_risk_level(70)
        assert level == "critical"
    
    def test_score_boundary_50(self, scorer):
        """测试 50 分边界"""
        level = scorer.get_risk_level(50)
        assert level == "high"
    
    def test_score_boundary_30(self, scorer):
        """测试 30 分边界"""
        level = scorer.get_risk_level(30)
        assert level == "medium"
    
    def test_score_cap_at_100(self, scorer):
        """测试评分上限 100"""
        details = {
            "risk": "critical",
            "pattern": {
                "tools": ["a", "b", "c", "d", "e"]  # 长链
            }
        }
        score = scorer.calculate("DANGEROUS_CHAIN", details)
        assert score <= 100
    
    def test_score_floor_at_0(self, scorer):
        """测试评分下限 0"""
        details = {}
        score = scorer.calculate("UNKNOWN_TYPE", details)
        assert score >= 0
    
    def test_unknown_alert_type(self, scorer):
        """测试未知告警类型"""
        details = {"risk": "medium"}
        score = scorer.calculate("UNKNOWN_TYPE", details)
        
        assert 0 <= score <= 100
    
    def test_chain_length_bonus(self, scorer):
        """测试链长度加分"""
        # 短链
        details_short = {
            "risk": "medium",
            "pattern": {"tools": ["a", "b"]}
        }
        score_short = scorer.calculate("DANGEROUS_CHAIN", details_short)
        
        # 长链
        details_long = {
            "risk": "medium",
            "pattern": {"tools": ["a", "b", "c", "d", "e"]}
        }
        score_long = scorer.calculate("DANGEROUS_CHAIN", details_long)
        
        # 长链评分应该更高
        assert score_long > score_short
    
    def test_frequency_ratio_bonus(self, scorer):
        """测试频率比率加分"""
        # 轻微超限
        details_low = {
            "calls_in_window": 11,
            "max_allowed": 10
        }
        score_low = scorer.calculate("FREQUENCY_ANOMALY", details_low)
        
        # 严重超限
        details_high = {
            "calls_in_window": 30,
            "max_allowed": 10
        }
        score_high = scorer.calculate("FREQUENCY_ANOMALY", details_high)
        
        # 严重超限评分应该更高
        assert score_high > score_low


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
