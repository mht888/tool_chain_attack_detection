import React, { useEffect, useState } from 'react'
import { apiGet } from '../api/client'

// 演示数据选择面板
export default function ExamplePicker({ open, onClose, onSelect }) {
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
