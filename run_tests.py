#!/usr/bin/env python3
"""
测试运行脚本
运行所有单元测试和集成测试
"""
import pytest
import sys


def run_tests():
    """运行所有测试"""
    print("=" * 60)
    print("运行测试套件")
    print("=" * 60)
    print()
    
    # 运行所有测试
    exit_code = pytest.main([
        "tests/",
        "-v",
        "--tb=short",
        "-x"  # 遇到第一个失败就停止
    ])
    
    print()
    print("=" * 60)
    if exit_code == 0:
        print("✓ 所有测试通过")
    else:
        print("✗ 测试失败")
    print("=" * 60)
    
    return exit_code


def run_unit_tests():
    """只运行单元测试"""
    print("=" * 60)
    print("运行单元测试")
    print("=" * 60)
    print()
    
    exit_code = pytest.main([
        "tests/",
        "-v",
        "--tb=short",
        "-k", "not Integration"  # 排除集成测试
    ])
    
    return exit_code


def run_integration_tests():
    """只运行集成测试"""
    print("=" * 60)
    print("运行集成测试")
    print("=" * 60)
    print()
    
    exit_code = pytest.main([
        "tests/test_integration.py",
        "-v",
        "--tb=short"
    ])
    
    return exit_code


if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "unit":
            sys.exit(run_unit_tests())
        elif sys.argv[1] == "integration":
            sys.exit(run_integration_tests())
        else:
            print("用法: python run_tests.py [unit|integration]")
            print("  无参数: 运行所有测试")
            print("  unit: 只运行单元测试")
            print("  integration: 只运行集成测试")
            sys.exit(1)
    else:
        sys.exit(run_tests())
