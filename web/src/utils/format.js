// 展示格式化 / 状态与任务语义映射

export function pad2(n) {
  return String(n).padStart(2, '0')
}

export function fmtDateTime(s) {
  if (!s) return '-'
  const d = new Date(s)
  if (Number.isNaN(d.getTime())) return String(s)
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`
}

export function fmtShortTime(s) {
  if (!s) return '--:--:--'
  const d = new Date(s)
  if (Number.isNaN(d.getTime())) return String(s)
  return `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`
}

export function fmtCountdown(totalSec) {
  const s = Math.max(0, Math.floor(Number(totalSec) || 0))
  if (s <= 0) return '即将脉冲'
  const d = Math.floor(s / 86400)
  const h = Math.floor((s % 86400) / 3600)
  const m = Math.floor((s % 3600) / 60)
  const ss = s % 60
  if (d > 0) return `${d}天${h}时${m}分`
  if (h > 0) return `${h}:${pad2(m)}:${pad2(ss)}`
  return `${m}:${pad2(ss)}`
}

export function fmtUptime(sec) {
  const s = Math.max(0, Math.floor(Number(sec) || 0))
  const d = Math.floor(s / 86400)
  const h = Math.floor((s % 86400) / 3600)
  const m = Math.floor((s % 3600) / 60)
  if (d > 0) return `${d}天${h}小时${m}分`
  if (h > 0) return `${h}小时${m}分`
  return `${m}分钟`
}

/** 保活/脉冲周期自适应格式化：<60 → N 秒；<3600 → N 分钟；其余 → N 小时（21600 → 6 小时） */
export function formatInterval(totalSec) {
  const s = Math.max(0, Math.floor(Number(totalSec) || 0))
  if (s < 60) return `${s} 秒`
  if (s < 3600) return `${Math.round(s / 60)} 分钟`
  const h = s / 3600
  const hv = Number.isInteger(h) ? h : Math.round(h * 10) / 10
  return `${hv} 小时`
}

// ===== 状态徽章语义：在线(成功绿) / 会话失效(红) / 待扫码(橙) / 保活暂停(灰) =====
export const STATUS_META = {
  online: { label: '在线', cls: 'online' },
  expired: { label: '会话失效', cls: 'expired' },
  waitScan: { label: '待扫码', cls: 'waitScan' },
  paused: { label: '保活暂停', cls: 'paused' },
}

/**
 * AccountCard 只有 online(bool) / keepalive_enabled(bool) / status_text(string)，
 * 推导规则：status_text 含“扫码/扫描/scan” -> 待扫码；keepalive 关 -> 保活暂停；
 * online -> 在线；否则 -> 会话失效。
 */
export function statusOf(card) {
  const text = String(card?.statusText || '')
  if (/扫码|扫描|scan/i.test(text)) return 'waitScan'
  if (card?.keepaliveEnabled === false) return 'paused'
  if (card?.online) return 'online'
  return 'expired'
}

// ===== 任务三进度（TaskProgress.name -> 打卡/AI/挂机） =====
export function classifyTask(name) {
  const n = String(name || '').toLowerCase()
  if (/sign|打卡|签到/.test(n)) return 'sign'
  if (/ai|人工智能/.test(n)) return 'ai'
  if (/hang|挂机/.test(n)) return 'hang'
  return ''
}

export function taskOf(card, key) {
  const arr = card?.tasks || []
  return arr.find((t) => classifyTask(t?.name) === key) || null
}

export function taskPct(t) {
  if (!t || !t.total) return 0
  return Math.min(100, Math.round(((t.current || 0) / t.total) * 100))
}

export function errMsg(e) {
  return e?.friendly || e?.message || '未知错误'
}
