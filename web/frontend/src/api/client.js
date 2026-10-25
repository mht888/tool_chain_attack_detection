// API 客户端：统一封装 fetch，开发模式经 vite 代理到后端

const BASE = '/api'

async function handle(res) {
  if (!res.ok) {
    let detail = `HTTP ${res.status}`
    try {
      const body = await res.json()
      detail = body.detail || JSON.stringify(body)
    } catch {
      /* ignore */
    }
    throw new Error(detail)
  }
  return res.json()
}

export async function apiGet(path) {
  return handle(await fetch(`${BASE}${path}`))
}

export async function apiPost(path, body) {
  return handle(
    await fetch(`${BASE}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
  )
}

export async function apiDelete(path) {
  return handle(await fetch(`${BASE}${path}`, { method: 'DELETE' }))
}

// 报告 Markdown 下载链接
export function markdownUrl(reportId) {
  return `${BASE}/reports/${reportId}/markdown`
}
