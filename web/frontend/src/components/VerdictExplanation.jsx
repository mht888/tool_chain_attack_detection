import React from 'react'

// 四层检测的逐层说明配置：alertType 用于从实际告警数据判断该层是否通过
const LAYERS = [
  {
    name: '权限检查',
    alertType: 'PERMISSION_VIOLATION',
    passText: (report, tools) =>
      `全部 ${report.total_tool_calls} 次调用所用工具（${tools.join('、') || '-'}）均不在黑名单中，未触发权限违规`,
  },
  {
    name: '注入检查',
    alertType: 'INJECTION_DETECTED',
    passText: () => '所有工具参数均未检出注入攻击特征（提示注入、命令拼接等）',
  },
  {
    name: '能力链检测',
    alertType: 'CAPABILITY_CHAIN',
    passText: (report, tools, skipped) =>
      skipped.length > 0
        ? `调用序列未匹配任何危险能力链模式（${skipped.length} 条链初判匹配、但相关参数均为低危，未构成实际威胁）`
        : '调用序列的能力组合未匹配任何危险能力链模式',
  },
  {
    name: '频率检查',
    alertType: 'FREQUENCY_ANOMALY',
    passText: () => '调用频率未超过配置的限制阈值，无频率异常',
  },
]

/**
 * SAFE 判定解释：报告显示"安全"时，逐层说明为什么安全
 *
 * 依据实际数据生成：
 * - 综合评分低于 30（SUSPICIOUS 阈值）才会判定 SAFE
 * - SAFE 报告仍可能带有低分告警，此时对应层展示告警情况而非"通过"
 * - verdict 兼容两种取值："SAFE"（报告详情）与 "SAFE（安全）"（检测响应）
 */
export default function VerdictExplanation({ report }) {
  const verdict = String(report.verdict || '').split('（')[0]
  if (verdict !== 'SAFE') return null

  const tools = [...new Set((report.steps || []).map((s) => s.tool_name))]
  const alerts = report.alerts || []
  const skipped = report.skipped_chain_warnings || []

  return (
    <div className="card">
      <div className="card-title">为何判定为安全</div>
      <div style={{ fontSize: 13, marginBottom: 10 }}>
        本次会话共 <b>{report.total_tool_calls}</b> 次工具调用，综合风险评分{' '}
        <b>{report.overall_risk_score}/100</b>（低于 30 分的可疑阈值），四层检测结论如下：
      </div>
      <ul style={{ fontSize: 13, lineHeight: 2, paddingLeft: 20 }}>
        {LAYERS.map((layer) => {
          const layerAlerts = alerts.filter((a) => a.alert_type === layer.alertType)
          if (layerAlerts.length === 0) {
            return (
              <li key={layer.name}>
                ✅ <b>{layer.name}：</b>{layer.passText(report, tools, skipped)}
              </li>
            )
          }
          const maxScore = Math.max(...layerAlerts.map((a) => a.risk_score))
          return (
            <li key={layer.name}>
              ⚠️ <b>{layer.name}：</b>
              记录了 {layerAlerts.length} 条告警，但单条风险评分最高仅 {maxScore} 分，
              加上告警数量加成后综合评分仍低于 30，未达到可疑级别（详见告警详情）
            </li>
          )
        })}
      </ul>
    </div>
  )
}
