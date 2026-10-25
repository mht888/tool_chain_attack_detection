import React, { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { apiGet, apiPost } from '../api/client'
import VerdictExplanation from '../components/VerdictExplanation'

// 告警类型中英文
const ALERT_TYPE_MAP = {
  CAPABILITY_CHAIN: '能力链告警',
  PERMISSION_VIOLATION: '权限违规',
  INJECTION_DETECTED: '注入检测',
  FREQUENCY_ANOMALY: '频率异常',
}

// 演示数据选择面板
function ExamplePicker({ open, onClose, onSelect }) {
  const [categories, setCategories] = useState(null)
  const [error, setError] = useState('')
  const [selectedCat, setSelectedCat] = useState(null)

  useEffect(() => {
    if (!open) return
    setSelectedCat(null)
    apiGet('/examples')
      .then((data) => {
        setCategories(data)
        if (data.length > 0) setSelectedCat(data[0].category)
        setError('')
      })
      .catch((e) => setError(e.message))
  }, [open])

  if (!open) return null

  const handleSelect = async (category, fileName) => {
    try {
      const data = await apiGet(
        `/examples/content?category=${encodeURIComponent(category)}&file=${encodeURIComponent(fileName)}`
      )
      onSelect(JSON.stringify(data, null, 2), fileName)
      onClose()
    } catch (e) {
      setError(`加载失败：${e.message}`)
    }
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <span>选择演示数据</span>
          <button className="modal-close" onClick={onClose}>✕</button>
        </div>
        {error && <div className="error-box" style={{ margin: 12 }}>{error}</div>}
        {!categories ? (
          <div className="empty-box">加载中...</div>
        ) : (
          <div className="modal-body">
            {/* 分类 tab */}
            <div className="example-tabs">
              {categories.map((cat) => (
                <button
                  key={cat.category}
                  className={`example-tab${selectedCat === cat.category ? ' active' : ''}`}
                  onClick={() => setSelectedCat(cat.category)}
                >
                  {cat.category_name}
                  <span className="example-tab-count">{cat.files.length}</span>
                </button>
              ))}
            </div>
            {/* 当前分类的文件列表 */}
            <div className="example-list">
              {categories
                .filter((c) => c.category === selectedCat)
                .map((cat) =>
                  cat.files.map((f) => (
                    <div
                      key={f.name}
                      className="example-item"
                      onClick={() => handleSelect(cat.category, f.name)}
                    >
                      <div className="example-item-main">
                        <div className="example-item-name">{f.name}</div>
                        {f.description && (
                          <div className="example-item-desc">{f.description}</div>
                        )}
                      </div>
                      <span className="example-item-count">{f.tool_count} 个工具</span>
                    </div>
                  ))
                )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default function Detect() {
  const [text, setText] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [pickerOpen, setPickerOpen] = useState(false)
  const [pickedName, setPickedName] = useState('')

  const onFileChange = (e) => {
    const file = e.target.files[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = () => {
      setText(reader.result)
      setPickedName(file.name)
      setError('')
    }
    reader.readAsText(file, 'utf-8')
  }

  // 从演示数据面板选择
  const onExampleSelect = (jsonStr, fileName) => {
    setText(jsonStr)
    setPickedName(fileName)
    setError('')
  }

  const onDetect = async () => {
    setError('')
    setResult(null)
    let parsed
    try {
      parsed = JSON.parse(text)
    } catch {
      setError('JSON 解析失败，请检查输入格式')
      return
    }
    if (!Array.isArray(parsed.tool_calls) || parsed.tool_calls.length === 0) {
      setError('缺少 tool_calls 数组或数组为空')
      return
    }
    setLoading(true)
    try {
      const res = await apiPost('/detect/session', parsed)
      setResult(res)
    } catch (e) {
      setError(`检测失败：${e.message}`)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <h1 className="page-title">在线检测</h1>
      <p className="page-desc">
        提交工具调用序列 JSON，系统将执行四层检测（权限 → 注入/定级 → 能力链 → 频率）并生成报告
      </p>

      <ExamplePicker
        open={pickerOpen}
        onClose={() => setPickerOpen(false)}
        onSelect={onExampleSelect}
      />

      <div className="card">
        <div className="card-title">输入数据</div>
        <div style={{ display: 'flex', gap: 10, marginBottom: 12, flexWrap: 'wrap' }}>
          <button className="btn secondary" onClick={() => setPickerOpen(true)}>
            🗂 演示数据
          </button>
          <label className="file-label" style={{ marginBottom: 0 }}>
            📎 上传 JSON 文件
            <input type="file" accept=".json" onChange={onFileChange} hidden />
          </label>
          {pickedName && (
            <span style={{ alignSelf: 'center', fontSize: 12, color: 'var(--text-muted)' }}>
              已选择：{pickedName}
            </span>
          )}
        </div>
        <textarea
          className="textarea"
          placeholder="选择演示数据、上传文件，或直接粘贴工具调用序列 JSON"
          value={text}
          onChange={(e) => {
            setText(e.target.value)
            setPickedName('')
          }}
        />
        <div style={{ marginTop: 12, display: 'flex', gap: 10 }}>
          <button className="btn" onClick={onDetect} disabled={loading || !text.trim()}>
            {loading ? '检测中...' : '开始检测'}
          </button>
        </div>
      </div>

      {error && <div className="error-box">{error}</div>}

      {result && (
        <>
          <div className="card">
            <div className="card-title">检测摘要</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 24, alignItems: 'center' }}>
              <span className={`verdict ${result.verdict.split('（')[0]}`}>{result.verdict}</span>
              <div>
                <div className="stat-value" style={{ fontSize: 26 }}>{result.overall_risk_score}</div>
                <div className="stat-label">综合风险评分</div>
              </div>
              <div>
                <div className="stat-value" style={{ fontSize: 26 }}>{result.total_tool_calls}</div>
                <div className="stat-label">工具调用数</div>
              </div>
              <div>
                <div className="stat-value" style={{ fontSize: 26, color: 'var(--high)' }}>
                  {result.alert_count}
                </div>
                <div className="stat-label">告警数</div>
              </div>
              <div style={{ marginLeft: 'auto' }}>
                <Link className="btn" to={`/reports/${result.report_id}`}>
                  查看完整报告
                </Link>
              </div>
            </div>
          </div>

          {/* SAFE 判定解释 */}
          <VerdictExplanation report={result} />

          <div className="card">
            <div className="card-title">工具调用链与逐步检测结果</div>
            <div className="step-list">
              {result.steps.map((step) => (
                <div key={step.index} className={`step-item${step.blocked ? ' blocked' : ''}`}>
                  <div className="step-index">{step.index}</div>
                  <div className="step-main">
                    <div className="step-tool">
                      {step.tool_name}
                      {step.blocked && <span style={{ color: 'var(--critical)', marginLeft: 8 }}>🚫 告警</span>}
                    </div>
                    <div className="step-args">{JSON.stringify(step.arguments)}</div>
                    {step.alerts.map((a) => (
                      <div key={a.alert_id} style={{ marginTop: 6 }}>
                        <span className={`badge ${a.risk_level}`}>
                          {ALERT_TYPE_MAP[a.alert_type] || a.alert_type}
                        </span>
                        <span style={{ marginLeft: 8, fontSize: 12, color: 'var(--text-muted)' }}>
                          评分 {a.risk_score}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  )
}
