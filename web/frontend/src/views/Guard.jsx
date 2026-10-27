import React, { useEffect, useRef, useState } from 'react'
import { apiPost } from '../api/client'
import ExamplePicker from '../components/ExamplePicker'

// 判决动作展示配置
const ACTION_META = {
  ALLOW: { icon: '✅', label: '放行', executed: '已执行' },
  REVIEW: { icon: '⏸', label: '挂起待审批', executed: '未执行 · 等待审批' },
  BLOCK: { icon: '⛔', label: '阻断', executed: '未执行 · 已拦截' },
}

const ALERT_TYPE_MAP = {
  CAPABILITY_CHAIN: '能力链告警',
  PERMISSION_VIOLATION: '权限违规',
  INJECTION_DETECTED: '注入检测',
  FREQUENCY_ANOMALY: '频率异常',
}

const LEVEL_CN = { low: '低', medium: '中', high: '高', critical: '严重' }

function newSessionId() {
  return `guard_${Date.now().toString(36)}`
}

// 解析输入 JSON，返回 tool_calls 数组；失败返回 null 并写入 error
function parseCalls(text, setError) {
  let parsed
  try {
    parsed = JSON.parse(text)
  } catch {
    setError('JSON 解析失败，请检查输入格式')
    return null
  }
  if (!Array.isArray(parsed.tool_calls) || parsed.tool_calls.length === 0) {
    setError('缺少 tool_calls 数组或数组为空')
    return null
  }
  return parsed.tool_calls
}

export default function Guard() {
  const [text, setText] = useState('')
  const [pickedName, setPickedName] = useState('')
  const [pickerOpen, setPickerOpen] = useState(false)
  const [sessionId, setSessionId] = useState(newSessionId)
  const [calls, setCalls] = useState(null)
  const [cursor, setCursor] = useState(0)
  const [results, setResults] = useState([])
  const [playing, setPlaying] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const busyRef = useRef(false)

  // 自动回放：每 1.2 秒推进一步，直到序列结束
  useEffect(() => {
    if (!playing || !calls) return
    if (cursor >= calls.length) {
      setPlaying(false)
      return
    }
    const timer = setTimeout(() => doStep(calls, cursor), 1200)
    return () => clearTimeout(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [playing, cursor, calls])

  const doStep = async (list, idx) => {
    if (busyRef.current) return
    busyRef.current = true
    setBusy(true)
    const call = list[idx]
    try {
      const decision = await apiPost('/guard/evaluate', {
        session_id: sessionId,
        agent_name: 'web_guard_demo',
        tool_name: call.tool_name,
        arguments: call.arguments || {},
        timestamp: call.timestamp || null,
      })
      setResults((prev) => [
        ...prev,
        {
          index: idx + 1,
          tool_name: call.tool_name,
          arguments: call.arguments || {},
          decision,
        },
      ])
      setCursor(idx + 1)
    } catch (e) {
      setError(`第 ${idx + 1} 步判决失败：${e.message}`)
      setPlaying(false)
    } finally {
      busyRef.current = false
      setBusy(false)
    }
  }

  const onTextChange = (value) => {
    setText(value)
    setPickedName('')
    // 输入变化后旧的解析结果作废
    setCalls(null)
    setResults([])
    setCursor(0)
    setPlaying(false)
    setError('')
  }

  const onFileChange = (e) => {
    const file = e.target.files[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = () => {
      onTextChange(reader.result)
      setPickedName(file.name)
      e.target.value = ''
    }
    reader.readAsText(file, 'utf-8')
  }

  const onExampleSelect = (jsonStr, fileName) => {
    onTextChange(jsonStr)
    setPickedName(fileName)
  }

  const onStart = () => {
    const list = parseCalls(text, setError)
    if (!list) return
    setError('')
    setCalls(list)
    setResults([])
    setCursor(0)
    setPlaying(true)
  }

  const onStep = () => {
    const list = calls || parseCalls(text, setError)
    if (!list) return
    if (!calls) setCalls(list)
    if (cursor >= list.length) return
    setError('')
    doStep(list, cursor)
  }

  const onReset = () => {
    setPlaying(false)
    setCalls(null)
    setResults([])
    setCursor(0)
    setError('')
    setSessionId(newSessionId())
  }

  const finished = calls !== null && cursor >= calls.length
  const compromised = results.some((r) => r.decision.session_compromised)
  const counts = results.reduce(
    (acc, r) => {
      acc[r.decision.action] = (acc[r.decision.action] || 0) + 1
      return acc
    },
    { ALLOW: 0, REVIEW: 0, BLOCK: 0 }
  )

  return (
    <div>
      <h1 className="page-title">实时拦截</h1>
      <p className="page-desc">
        模拟 Agent 逐个请求工具，每次调用先经过执行前闸口：放行 / 挂起待审批 / 阻断。
        命中阻断后会话标记失守，后续 critical 工具一律拦截。
      </p>

      <ExamplePicker
        open={pickerOpen}
        onClose={() => setPickerOpen(false)}
        onSelect={onExampleSelect}
      />

      <div className="card">
        <div className="card-title">输入数据</div>
        <div className="guard-toolbar">
          <button className="btn secondary" onClick={() => setPickerOpen(true)}>
            🗂 演示数据
          </button>
          <label className="file-label" style={{ marginBottom: 0 }}>
            📎 上传 JSON 文件
            <input type="file" accept=".json" onChange={onFileChange} hidden />
          </label>
          {pickedName && (
            <span className="guard-picked">已选择：{pickedName}</span>
          )}
          <span style={{ flex: 1 }} />
          <span className="guard-session-label">会话 ID</span>
          <input
            className="input"
            style={{ width: 190 }}
            value={sessionId}
            onChange={(e) => setSessionId(e.target.value)}
            disabled={results.length > 0}
          />
          <button
            className="btn secondary"
            onClick={() => setSessionId(newSessionId())}
            disabled={results.length > 0}
            title="重新生成会话 ID"
          >
            🎲
          </button>
        </div>
        <textarea
          className="textarea"
          style={{ minHeight: 180 }}
          placeholder="选择演示数据、上传文件，或直接粘贴工具调用序列 JSON"
          value={text}
          onChange={(e) => onTextChange(e.target.value)}
        />
        <div style={{ marginTop: 12, display: 'flex', gap: 10, flexWrap: 'wrap' }}>
          <button className="btn" onClick={onStart} disabled={!text.trim() || busy || playing}>
            {playing ? '回放中...' : '开始回放'}
          </button>
          <button
            className="btn secondary"
            onClick={onStep}
            disabled={!text.trim() || busy || playing || finished}
          >
            单步执行
          </button>
          <button
            className="btn secondary"
            onClick={onReset}
            disabled={results.length === 0 && !playing}
          >
            重置
          </button>
          {calls && (
            <span className="guard-progress">
              进度 {cursor} / {calls.length}
              {finished && ' · 回放结束'}
            </span>
          )}
        </div>
      </div>

      {error && <div className="error-box">{error}</div>}

      {results.length > 0 && (
        <div className="card">
          <div className="card-title">会话状态</div>
          <div className="guard-summary">
            <span className="verdict verdict-ALLOW">✅ 放行 {counts.ALLOW}</span>
            <span className="verdict verdict-REVIEW">⏸ 挂起 {counts.REVIEW}</span>
            <span className="verdict verdict-BLOCK">⛔ 阻断 {counts.BLOCK}</span>
          </div>
          {compromised && (
            <div className="session-alert">
              ⚠️ 会话已失守：此前命中了阻断判决，之后所有 critical 级工具都会被直接拦截。
            </div>
          )}
        </div>
      )}

      {results.length > 0 && (
        <div className="card">
          <div className="card-title">执行前判决时间线</div>
          <div className="step-list">
            {results.map((r) => {
              const d = r.decision
              const meta = ACTION_META[d.action] || ACTION_META.BLOCK
              return (
                <div key={r.index} className={`step-item guard-${d.action.toLowerCase()}`}>
                  <div className="step-index">{r.index}</div>
                  <div className="step-main">
                    <div className="step-tool">
                      {r.tool_name}
                      <span className={`verdict verdict-${d.action}`} style={{ marginLeft: 10 }}>
                        {meta.icon} {meta.label}
                      </span>
                      <span className="guard-executed">{meta.executed}</span>
                    </div>
                    <div className="step-args">{JSON.stringify(r.arguments)}</div>
                    <div className="guard-meta">
                      <span className={`badge ${d.risk_level}`}>
                        风险 {LEVEL_CN[d.risk_level] || d.risk_level}
                      </span>
                      <span>风险分 {d.risk_score}</span>
                      {d.matched_chain && (
                        <span>
                          命中链：<b>{d.matched_chain}</b>
                        </span>
                      )}
                      {d.alert_types.map((t) => (
                        <span key={t} className="guard-chip">
                          {ALERT_TYPE_MAP[t] || t}
                        </span>
                      ))}
                      {d.log_required && <span className="guard-chip">已留痕</span>}
                    </div>
                    <div className="guard-reason">{d.reason}</div>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
