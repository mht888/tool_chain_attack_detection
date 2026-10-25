import React from 'react'
import { NavLink } from 'react-router-dom'

const NAV_ITEMS = [
  { to: '/', label: '仪表盘', icon: '📊', end: true },
  { to: '/detect', label: '在线检测', icon: '🔍' },
  { to: '/reports', label: '报告列表', icon: '📄' },
]

export default function Layout({ children }) {
  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <span className="brand-icon">🛡️</span>
          <div>
            <div className="brand-title">工具链攻击检测</div>
            <div className="brand-sub">Tool Chain Attack Detection</div>
          </div>
        </div>
        <nav className="sidebar-nav">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                `nav-item${isActive ? ' active' : ''}`
              }
            >
              <span className="nav-icon">{item.icon}</span>
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-footer">v0.1.0 · 课程项目演示</div>
      </aside>
      <main className="content">{children}</main>
    </div>
  )
}
