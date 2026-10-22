# 测试套件

本目录包含工具调用链攻击检测系统的完整测试套件。

## 测试结构

```
tests/
├── __init__.py                  # 测试包初始化
├── test_chain_matcher.py        # 链模式匹配器单元测试
├── test_permission_checker.py   # 权限检查器单元测试
├── test_injection_checker.py    # 注入检查器单元测试
├── test_frequency_checker.py    # 频率检查器单元测试
├── test_risk_scorer.py          # 风险评分器单元测试
├── test_tool_classifier.py      # 工具分类器单元测试
└── test_integration.py          # 集成测试
```

## 测试模块说明

### 1. test_chain_matcher.py
测试链模式匹配器的功能：
- 模式加载
- 简单链匹配
- 三工具链匹配
- 间隔容忍度
- 参数合规映射
- 空缓冲区和单工具缓冲区

### 2. test_permission_checker.py
测试权限检查器的功能：
- 策略加载
- 允许工具检测
- 禁止工具检测
- 未知工具处理
- 工具风险等级配置

### 3. test_injection_checker.py
测试注入检查器的功能：
- 白名单加载
- 正常参数检测
- SQL 注入检测
- 命令注入检测
- 路径遍历检测
- 嵌套参数注入检测
- 高风险工具白名单检查

### 4. test_frequency_checker.py
测试频率检查器的功能：
- 配置加载
- 风险阈值配置
- 正常频率检测
- 高频异常检测
- 按工具分别统计
- 按会话分别统计
- 时间窗口清理

### 5. test_risk_scorer.py
测试风险评分器的功能：
- 权限违规评分
- 注入检测评分
- 危险链评分
- 频率异常评分
- 风险等级判定
- 评分边界测试
- 链长度加分
- 频率比率加分

### 6. test_tool_classifier.py
测试工具分类器的功能：
- 初始化
- critical 工具分类
- high 工具分类
- medium 工具分类
- low 工具分类
- 模式匹配
- 大小写不敏感
- 部分匹配
- 高风险工具判断

### 7. test_integration.py
集成测试，测试完整检测流程：
- 检测器初始化
- 正常会话测试
- 攻击会话测试
- 危险链模式检测
- 注入检测
- 权限违规检测
- 频率异常检测
- 参数白名单合规/不合规
- 多会话隔离
- 告警结构验证
- 长链检测
- 嵌套参数注入检测

## 运行测试

### 运行所有测试
```bash
python run_tests.py
```

### 只运行单元测试
```bash
python run_tests.py unit
```

### 只运行集成测试
```bash
python run_tests.py integration
```

### 使用 pytest 直接运行
```bash
# 运行所有测试
pytest tests/ -v

# 运行特定测试文件
pytest tests/test_chain_matcher.py -v

# 运行特定测试类
pytest tests/test_chain_matcher.py::TestChainMatcher -v

# 运行特定测试方法
pytest tests/test_chain_matcher.py::TestChainMatcher::test_match_simple_chain -v
```

## 测试数据

测试使用 `examples/` 目录下的测试数据：
- `examples/dangerous_chains/` - 危险链模式测试
- `examples/normal_chains/` - 正常链测试
- `examples/long_chains/` - 长链测试
- `examples/injection_tests/` - 注入检测测试
- `examples/whitelist_tests/` - 白名单测试
- `examples/frequency_tests/` - 频率检测测试

## 测试覆盖

### 单元测试覆盖
- ✅ 链模式匹配器
- ✅ 权限检查器
- ✅ 注入检查器
- ✅ 频率检查器
- ✅ 风险评分器
- ✅ 工具分类器

### 集成测试覆盖
- ✅ 完整检测流程
- ✅ 多模块协作
- ✅ 数据流验证
- ✅ 边界情况处理

## 注意事项

1. 运行测试前确保已安装依赖：
   ```bash
   pip install pytest
   ```

2. 测试数据需要先生成：
   ```bash
   python generate_test_data.py
   ```

3. 某些集成测试依赖于测试数据文件，如果文件不存在会被跳过

4. 测试不会修改任何源代码或配置文件
