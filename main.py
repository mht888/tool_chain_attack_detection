"""
工具调用链攻击检测系统 - 主程序入口

"""

import argparse
import json
from pathlib import Path
from datetime import datetime

from src.core.detector import RealTimeDetector
from src.models.input import ToolCallInput
from src.models.report import DetectionReport


def load_test_data(input_path: str) -> dict:
    """加载测试数据"""
    with open(input_path, "r", encoding="utf-8") as f:
        return json.load(f)


def run_detection(input_path: str, output_path: str, rules_dir: str = "src/rules"):
    """
    运行检测流程

    Args:
        input_path: 输入数据路径（JSON格式）
        output_path: 输出报告路径（Markdown格式）
        rules_dir: 规则配置目录
    """
    print("=" * 60)
    print("工具调用链安全检测系统")
    print("=" * 60)
    print()

    # 1. 加载测试数据
    print(f"[1/4] 加载测试数据: {input_path}")
    test_data = load_test_data(input_path)
    session_id = test_data.get("session_id", "unknown")
    agent_name = test_data.get("agent_name", "unknown")
    tool_calls_data = test_data.get("tool_calls", [])

    print(f"  - 会话ID: {session_id}")
    print(f"  - Agent名称: {agent_name}")
    print(f"  - 工具调用数: {len(tool_calls_data)}")
    print()

    # 2. 初始化检测器
    print(f"[2/4] 初始化检测器 (规则目录: {rules_dir})")
    detector = RealTimeDetector(rules_dir=rules_dir)
    report = DetectionReport(session_id=session_id)
    print("  - 检测器已就绪")
    print()

    # 3. 逐个处理工具调用
    print("[3/4] 开始检测...")
    print()

    for i, call_data in enumerate(tool_calls_data, 1):
        # 解析时间戳
        timestamp_str = call_data.get("timestamp")
        if timestamp_str:
            # 处理ISO格式时间戳
            timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        else:
            timestamp = datetime.now()

        # 创建工具调用输入
        tool_call = ToolCallInput(
            tool_name=call_data["tool_name"],
            arguments=call_data.get("arguments", {}),
            timestamp=timestamp,
            session_id=session_id,
            agent_name=agent_name,
            metadata=call_data.get("metadata", {})
        )

        # 执行检测
        alerts = detector.on_tool_call(tool_call)

        # 记录结果
        if alerts:
            report.add_tool_call(tool_call.tool_name, tool_call.arguments, blocked=True)

            print(f"  [{i}] 🚫 {tool_call.tool_name}")
            for alert in alerts:
                report.add_alert(alert)
                print(f"      告警类型: {alert.alert_type}")
                print(f"      风险等级: {alert.risk_level}")
                print(f"      风险评分: {alert.risk_score}/100")

                # 显示详细信息
                if alert.alert_type == "CAPABILITY_CHAIN":
                    pattern = alert.details.get("pattern", {})
                    print(f"      能力链模式: {pattern.get('name', 'unknown')}")
                    print(f"      描述: {pattern.get('description', '')}")
                elif alert.alert_type == "PERMISSION_VIOLATION":
                    print(f"      原因: {alert.details.get('reason', '')}")
                elif alert.alert_type == "INJECTION_DETECTED":
                    print(f"      攻击类型: {alert.details.get('attack_type', '')}")
                elif alert.alert_type == "FREQUENCY_ANOMALY":
                    print(f"      调用频率: {alert.details.get('calls_in_window', 0)}")
                print()
        else:
            report.add_tool_call(tool_call.tool_name, tool_call.arguments, blocked=False)
            print(f"  [{i}] ✓ {tool_call.tool_name}")

    print()

    # 4. 生成报告
    print(f"[4/4] 生成报告: {output_path}")

    # 确保输出目录存在
    output_dir = Path(output_path).parent
    output_dir.mkdir(parents=True, exist_ok=True)

    # 将跳过的链警告传递给报告
    for warning in detector.skipped_chain_warnings:
        report.add_skipped_chain_warning(warning)

    # 保存报告
    report.save(output_path)

    # 打印摘要
    print()
    print("=" * 60)
    print("检测完成")
    print("=" * 60)
    print()
    print(f"  会话ID: {session_id}")
    print(f"  工具调用总数: {report.total_tool_calls}")
    print(f"  告警数量: {len(report.alerts)}")

    if report.alerts:
        max_score = max(alert.risk_score for alert in report.alerts)
        print(f"  最高风险评分: {max_score}/100")

        if max_score >= 70:
            print(f"  风险判定: 🔴 MALICIOUS（恶意）")
        elif max_score >= 30:
            print(f"  风险判定: 🟡 SUSPICIOUS（可疑）")
        else:
            print(f"  风险判定: 🟢 SAFE（安全）")
    else:
        print(f"  风险判定: 🟢 SAFE（安全）")

    print()
    print(f"✓ 报告已保存到: {output_path}")


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description="工具调用链安全检测系统",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例：
    # 检测攻击场景
    python main.py --input examples/attack_session.json --output reports/attack_report.md

    # 检测正常场景
    python main.py --input examples/normal_session.json --output reports/normal_report.md

    # 使用自定义规则目录
    python main.py --input examples/attack_session.json --output reports/report.md --rules custom_rules/
        """
    )

    parser.add_argument(
        "--input",
        "-i",
        type=str,
        default="examples/attack_session.json",
        help="输入数据路径（JSON格式）"
    )

    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default="reports/security_report.md",
        help="输出报告路径（Markdown格式）"
    )

    parser.add_argument(
        "--rules",
        "-r",
        type=str,
        default="src/rules",
        help="规则配置目录"
    )

    args = parser.parse_args()

    run_detection(
        input_path=args.input,
        output_path=args.output,
        rules_dir=args.rules
    )


if __name__ == "__main__":
    main()
