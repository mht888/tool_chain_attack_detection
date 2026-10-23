"""
MVP 演示程序：从每个 examples 数据集文件夹各取一个文件，运行完整检测流程

运行方式：
    python run_mvp.py
"""

from pathlib import Path

from main import run_detection

# 每个数据集取的文件
DATASETS = {
    "dangerous_chains": "attack_session.json",
    "frequency_tests": "frequency_test.json",
    "injection_tests": "nested_injection_test.json",
    "long_chains": "test_010.json",
    "normal_chains": "test_010.json",
    "tool_classifier_tests": "unknown_tool_test.json",
    "whitelist_tests": "param_grading_test.json",
}

# 真实业务场景测试文件
REAL_WORLD_SCENARIOS = [
    "dangerous_01_data_exfiltration.json",
    "dangerous_02_sql_injection_email.json",
    "dangerous_03_privilege_escalation.json",
    "safe_01_normal_data_processing.json",
    "safe_02_normal_query_analysis.json",
]


def main():
    """遍历所有数据集，各取一个文件运行检测"""
    output_dir = Path("reports/mvp")
    output_dir.mkdir(parents=True, exist_ok=True)

    # 运行原有数据集
    for dataset, filename in DATASETS.items():
        input_path = f"examples/{dataset}/{filename}"
        output_path = output_dir / f"{dataset}_report.md"

        print()
        print("#" * 60)
        print(f"# 数据集: {dataset} ({filename})")
        print("#" * 60)
        print()

        run_detection(
            input_path=input_path,
            output_path=str(output_path)
        )

    # 运行真实业务场景测试（5个文件）
    for filename in REAL_WORLD_SCENARIOS:
        input_path = f"examples/real_world_scenarios/{filename}"
        # 生成报告名：dangerous_01_data_exfiltration.json -> real_world_dangerous_01_report.md
        scenario_name = filename.replace(".json", "")
        output_path = output_dir / f"real_world_{scenario_name}_report.md"

        print()
        print("#" * 60)
        print(f"# 真实业务场景: {scenario_name}")
        print("#" * 60)
        print()

        run_detection(
            input_path=input_path,
            output_path=str(output_path)
        )


if __name__ == "__main__":
    main()
