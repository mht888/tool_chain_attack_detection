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
    "whitelist_tests": "param_whitelist_test.json",
}


def main():
    """遍历所有数据集，各取一个文件运行检测"""
    output_dir = Path("reports/mvp")
    output_dir.mkdir(parents=True, exist_ok=True)

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


if __name__ == "__main__":
    main()
