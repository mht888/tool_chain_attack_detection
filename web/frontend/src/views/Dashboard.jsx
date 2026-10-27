import React, { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { apiGet } from '../api/client'

// 判定对应的中文标签
function verdictLabel(v) {
  const map = { MALICIOUS: '恶意', SUSPICIOUS: '可疑', SAFE: '安全' }
  return map[v] || '未知'
}

export default function Dashboard() {
  const [reports, setReports] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    apiGet('/reports')
      .then(setReports)
      .catch((e) => setError(e.message))
  }, [])

  if (error) return <div className="error-box">加载失败：{error}</div>
  if (!reports) return <div className="empty-box">加载中...</div>

  const totalAlerts = reports.reduce((s, r) => s + r.alert_count, 0)
  const malicious = reports.filter((r) => r.verdict === 'MALICIOUS').length
  const suspicious = reports.filter((r) => r.verdict === 'SUSPICIOUS').length
  const safe = reports.length - malicious - suspicious
  const dist = [
    { key: 'MALICIOUS', label: '恶意', count: malicious },
    { key: 'SUSPICIOUS', label: '可疑', count: suspicious },
    { key: 'SAFE', label: '安全', count: safe },
  ]

  return (
    <div>
      <h1 className="page-title">仪表盘</h1>
      <p className="page-desc">工具调用链攻击检测系统 · 检测结果总览</p>

      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-label">检测报告总数</div>
          <div className="stat-value">{reports.length}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">告警总数</div>
          <div className="stat-value" style={{ color: 'var(--high)' }}>
            {totalAlerts}
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label">恶意判定</div>
          <div className="stat-value" style={{ color: 'var(--critical)' }}>
            {malicious}
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label">可疑判定</div>
          <div className="stat-value" style={{ color: 'var(--medium)' }}>
            {suspicious}
          </div>
        </div>
      </div>

      {reports.length > 0 && (
        <div className="card">
          <div className="card-title">判定分布</div>
          <div className="dist-bar">
            {dist
              .filter((d) => d.count > 0)
              .map((d) => (
                <div
                  key={d.key}
                  className={`dist-seg ${d.key}`}
                  style={{ width: `${(d.count / reports.length) * 100}%` }}
                  title={`${d.label} ${d.count}`}
                />
              ))}
          </div>
          <div className="dist-legend">
            {dist.map((d) => (
              <span key={d.key}>
                <span className={`dist-dot ${d.key}`} />
                {d.label} {d.count}
              </span>
            ))}
          </div>
        </div>
      )}

      <div className="card">
        <div className="card-title">最近检测报告</div>
        {reports.length === 0 ? (
          <div className="empty-box">
            暂无检测记录，前往 <Link className="link" to="/detect">在线检测</Link> 提交第一个测试场景
          </div>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>报告 ID</th>
                <th>会话</th>
                <th>判定</th>
                <th>风险评分</th>
                <th>工具调用数</th>
                <th>告警数</th>
                <th>时间</th>
              </tr>
            </thead>
            <tbody>
              {reports.slice(0, 10).map((r) => (
                <tr key={r.report_id}>
                  <td>
                    <Link className="link" to={`/reports/${r.report_id}`}>
                      {r.report_id}
                    </Link>
                  </td>
                  <td>{r.session_id}</td>
                  <td>
                    <span className={`verdict ${r.verdict}`}>{verdictLabel(r.verdict)}</span>
                  </td>
                  <td>{r.overall_risk_score}</td>
                  <td>{r.total_tool_calls}</td>
                  <td>{r.alert_count}</td>
                  <td>{r.created_at.replace('T', ' ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
