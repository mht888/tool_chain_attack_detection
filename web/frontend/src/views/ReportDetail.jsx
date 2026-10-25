import React, { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { apiGet, markdownUrl } from '../api/client'
import VerdictExplanation from '../components/VerdictExplanation'

const ALERT_TYPE_MAP = {
  CAPABILITY_CHAIN: '能力链告警 (Capability Chain)',
  PERMISSION_VIOLATION: '权限违规 (Permission Violation)',
  INJECTION_DETECTED: '注入检测 (Injection Detected)',
  FREQUENCY_ANOMALY: '频率异常 (Frequency Anomaly)',
}

// 告警详情：按类型展示关键字段
function AlertDetails({ alert }) {
  const d = alert.details || {}
  switch (alert.alert_type) {
    case 'CAPABILITY_CHAIN': {
      const p = d.pattern || {}
      return (
        <div>
          <div><b>能力链模式：</b>{p.name}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: 12, margin: '2px 0' }}>{p.description}</div>
          {Array.isArray(p.capabilities) && (
            <div>
              <b>能力序列：</b>
              <code>{p.capabilities.join(' → ')}</code>
            </div>
          )}
          {Array.isArray(p.matched_indices) && p.matched_indices.length > 0 && (
            <div>
              <b>危险链范围：</b>第 {Math.min(...p.matched_indices) + 1} 步 → 第 {Math.max(...p.matched_indices) + 1} 步
            </div>
          )}
        </div>
      )
    }
    case 'PERMISSION_VIOLATION':
      return <div><b>原因：</b>{d.reason || d.message || '黑名单工具'}</div>
    case 'INJECTION_DETECTED':
      return (
        <div>
          <div><b>攻击类型：</b>{d.attack_type}</div>
          {d.malicious_param && <div><b>恶意参数：</b><code>{String(d.malicious_param).slice(0, 120)}</code></div>}
        </div>
      )
    case 'FREQUENCY_ANOMALY':
      return <div><b>调用频率：</b>{d.calls_in_window} 次 / {d.window_seconds || 60} 秒（阈值 {d.limit}）</div>
    default:
      return <code style={{ fontSize: 12 }}>{JSON.stringify(d)}</code>
  }
}

export default function ReportDetail() {
  const { reportId } = useParams()
  const [report, setReport] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    apiGet(`/reports/${reportId}`)
      .then(setReport)
      .catch((e) => setError(e.message))
  }, [reportId])

  if (error) return <div className="error-box">加载失败：{error}</div>
  if (!report) return <div className="empty-box">加载中...</div>

  return (
    <div>
      <h1 className="page-title">检测报告</h1>
      <p className="page-desc">
        <Link className="link" to="/reports">← 返回报告列表</Link>
        &nbsp;|&nbsp; 报告 ID：{report.report_id} &nbsp;|&nbsp; 会话：{report.session_id}
      </p>

      {/* 摘要 */}
      <div className="card">
        <div className="card-title">检测摘要</div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 24, alignItems: 'center' }}>
          <span className={`verdict ${report.verdict}`}>{report.verdict}</span>
          <div>
            <div className="stat-value" style={{ fontSize: 26 }}>{report.overall_risk_score}</div>
            <div className="stat-label">综合风险评分</div>
          </div>
          <div>
            <div className="stat-value" style={{ fontSize: 26 }}>{report.total_tool_calls}</div>
            <div className="stat-label">工具调用数</div>
          </div>
          <div>
            <div className="stat-value" style={{ fontSize: 26, color: 'var(--high)' }}>{report.alert_count}</div>
            <div className="stat-label">告警数</div>
          </div>
          <div style={{ marginLeft: 'auto' }}>
            <a
              className="btn secondary"
              href={markdownUrl(report.report_id)}
              download={`${report.report_id}.md`}
            >
              ⬇ 下载 Markdown 报告
            </a>
          </div>
        </div>
        {report.description && (
          <div style={{ marginTop: 10, fontSize: 13, color: 'var(--text-muted)' }}>
            场景描述：{report.description}
          </div>
        )}
      </div>

      {/* SAFE 判定解释 */}
      <VerdictExplanation report={report} />

      {/* 工具调用链 */}
      <div className="card">
        <div className="card-title">工具调用链（🚫 标记为触发告警的步骤）</div>
        <div className="step-list">
          {report.steps.map((step) => (
            <div key={step.index} className={`step-item${step.blocked ? ' blocked' : ''}`}>
              <div className="step-index">{step.index}</div>
              <div className="step-main">
                <div className="step-tool">
                  {step.tool_name}
                  {step.blocked && <span style={{ color: 'var(--critical)', marginLeft: 8 }}>🚫</span>}
                </div>
                <div className="step-args">{JSON.stringify(step.arguments)}</div>
                {step.alerts.map((a) => (
                  <div key={a.alert_id} style={{ marginTop: 6 }}>
                    <span className={`badge ${a.risk_level}`}>
                      {ALERT_TYPE_MAP[a.alert_type] || a.alert_type}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* 告警详情 */}
      <div className="card">
        <div className="card-title">告警详情</div>
        {report.alerts.length === 0 ? (
          <div className="empty-box">无告警</div>
        ) : (
          report.alerts.map((a, i) => (
            <div key={a.alert_id} style={{ padding: '14px 0', borderBottom: '1px dashed var(--border)' }}>
              <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 8 }}>
                <b>告警 {i + 1}</b>
                <span className={`badge ${a.risk_level}`}>{a.risk_level}</span>
                <span style={{ fontSize: 13 }}>{ALERT_TYPE_MAP[a.alert_type] || a.alert_type}</span>
                <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>评分 {a.risk_score}/100</span>
              </div>
              <AlertDetails alert={a} />
            </div>
          ))
        )}
      </div>

      {/* 跳过的链警告 */}
      {report.skipped_chain_warnings?.length > 0 && (
        <div className="card">
          <div className="card-title">初判有风险但参数低风险的记录（未告警）</div>
          {report.skipped_chain_warnings.map((w, i) => (
            <div key={i} style={{ padding: '8px 0', fontSize: 13, borderBottom: '1px dashed var(--border)' }}>
              ⚠️ {w.reason}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
