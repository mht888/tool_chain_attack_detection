import React, { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { apiDelete, apiGet } from '../api/client'

function verdictLabel(v) {
  const map = { MALICIOUS: '恶意', SUSPICIOUS: '可疑', SAFE: '安全' }
  return map[v] || '未知'
}

export default function ReportList() {
  const [reports, setReports] = useState(null)
  const [error, setError] = useState('')

  const load = () => {
    apiGet('/reports')
      .then((data) => {
        setReports(data)
        setError('')
      })
      .catch((e) => setError(e.message))
  }

  useEffect(load, [])

  const onDelete = async (reportId) => {
    if (!window.confirm(`确认删除报告 ${reportId}？`)) return
    try {
      await apiDelete(`/reports/${reportId}`)
      load()
    } catch (e) {
      setError(`删除失败：${e.message}`)
    }
  }

  if (error) return <div className="error-box">加载失败：{error}</div>
  if (!reports) return <div className="empty-box">加载中...</div>

  return (
    <div>
      <h1 className="page-title">报告列表</h1>
      <p className="page-desc">所有历史检测报告，点击查看详情</p>

      <div className="card">
        {reports.length === 0 ? (
          <div className="empty-box">
            暂无报告，前往 <Link className="link" to="/detect">在线检测</Link> 提交测试场景
          </div>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>报告 ID</th>
                <th>会话</th>
                <th>场景描述</th>
                <th>判定</th>
                <th>风险评分</th>
                <th>最高风险等级</th>
                <th>工具调用数</th>
                <th>告警数</th>
                <th>时间</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {reports.map((r) => (
                <tr key={r.report_id}>
                  <td>
                    <Link className="link" to={`/reports/${r.report_id}`}>
                      {r.report_id}
                    </Link>
                  </td>
                  <td>{r.session_id}</td>
                  <td>{r.description || '-'}</td>
                  <td>
                    <span className={`verdict ${r.verdict}`}>{verdictLabel(r.verdict)}</span>
                  </td>
                  <td>{r.overall_risk_score}</td>
                  <td>
                    <span className={`badge ${r.highest_risk_level}`}>
                      {r.highest_risk_level}
                    </span>
                  </td>
                  <td>{r.total_tool_calls}</td>
                  <td>{r.alert_count}</td>
                  <td>{r.created_at.replace('T', ' ')}</td>
                  <td>
                    <button className="btn secondary" style={{ padding: '4px 10px', fontSize: 12 }}
                      onClick={() => onDelete(r.report_id)}>
                      删除
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
