// 轻量通知系统：全局通知方法 + 顶部右侧弹出列表
import { useEffect, useState } from 'react'

const listeners = new Set()
let idSeq = 1

export const notify = {
  info(message) { emit({ id: idSeq++, type: 'info', message }) },
  success(message) { emit({ id: idSeq++, type: 'success', message }) },
  error(message) { emit({ id: idSeq++, type: 'error', message }) },
}

function emit(event) {
  listeners.forEach((fn) => {
    try { fn(event) } catch (_) {}
  })
}

export function Notifications() {
  const [items, setItems] = useState([])

  useEffect(() => {
    function onEvent(evt) {
      setItems((prev) => {
        const next = [...prev, { ...evt, ts: Date.now() }]
        return next
      })
      // 自动 3.2s 后移除
      const ttl = evt.type === 'error' ? 5000 : 3200
      setTimeout(() => {
        setItems((prev) => prev.filter((x) => x.id !== evt.id))
      }, ttl)
    }
    listeners.add(onEvent)
    return () => { listeners.delete(onEvent) }
  }, [])

  return (
    <div className="pointer-events-none fixed top-3 right-3 z-[9999] space-y-2">
      {items.map((it) => (
        <div key={it.id} className={`pointer-events-auto min-w-[220px] max-w-[360px] rounded border px-3 py-2 shadow-md text-sm bg-white ${
          it.type === 'success' ? 'border-green-300' : it.type === 'error' ? 'border-red-300' : 'border-gray-200'
        }`}>
          <div className="font-medium mb-0.5">
            {it.type === 'success' ? '成功' : it.type === 'error' ? '错误' : '提示'}
          </div>
          <div className="text-gray-700 break-words">{it.message}</div>
        </div>
      ))}
    </div>
  )
}


