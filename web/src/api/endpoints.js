// 端点表封装 —— 与 proto/api.proto 底部端点表一一对应
import axios from 'axios'
import { rpc, kickToLogin } from './rpc'

export const PLATFORMS = [
  { key: 'ctyun', label: '天翼云' },
  { key: 'ydpc', label: '移动云' },
]

// 平台能力开关（依据 proto 端点表；ydpc 桌面/批量配置同构可用，暂无任务体系）
export const FEATURES = {
  ctyun: {
    password: true,
    qr: true,
    captcha: true,
    tasks: true,
    desktops: true,
    points: true,
    rewards: true,
    powerActions: ['poweron', 'awake', 'shutdown', 'reboot'],
  },
  ydpc: {
    password: true,
    qr: false,
    captcha: false, // soho 图形验证码仅随 add 响应返回（无独立刷新端点）；ecloud 走短信分支
    tasks: false,
    desktops: true,
    points: false,
    rewards: false,
    powerActions: ['shutdown', 'reboot'],
  },
}

export const POWER_LABELS = { poweron: '开机', awake: '唤醒', shutdown: '关机', reboot: '重启' }
export const TASK_LABELS = { sign: '打卡', ai: 'AI', hang: '挂机' }
export const TASK_KEYS = ['sign', 'ai', 'hang']

/**
 * 账号可用电源动作：ydpc 基础 shutdown|reboot，ecloud 账号额外有 poweron
 * （按 AccountCard.platform 容错判断，后端 power 端点最终校验）
 */
export function powerActionsFor(platform, card) {
  const base = FEATURES[platform]?.powerActions || ['shutdown', 'reboot']
  if (platform === 'ydpc' && /ecloud/i.test(String(card?.platform || ''))) {
    return ['poweron', ...base.filter((a) => a !== 'poweron')]
  }
  return base
}

/** 平台通用端点（platform = 'ctyun' | 'ydpc'） */
export function api(platform) {
  const base = platform === 'ydpc' ? '/api/ydpc' : '/api'
  return {
    accounts: () => rpc(`${base}/accounts`, null, null, 'AccountList', { method: 'GET' }),
    // 添加账号多态：code=0 成功 / code=1 失败 / code=2 附加验证（NeedCaptcha 或短信分支）
    // → acceptCodes 让 code=1/2 原样返回 envelope，由向导按 BoolReply / YdpcLoginBranch 分支解码
    addAccount: (payload) => rpc(`${base}/account/add`, 'AddAccountReq', payload, null, { acceptCodes: [1, 2] }),
    update: (d) => rpc(`${base}/account/${d.id}/update`, 'UpdateAccountReq', d, 'BoolReply'),
    remove: (id) => rpc(`${base}/account/${id}/delete`, 'IdReq', { id }, 'BoolReply'),
    relogin: (id) => rpc(`${base}/account/${id}/relogin`, 'IdReq', { id }, 'BoolReply'),
    sync: (id) => rpc(`${base}/account/${id}/sync`, 'IdReq', { id }, 'BoolReply'),
    power: (id, desktopId, action) =>
      rpc(`${base}/account/${id}/power`, 'PowerReq', { id, desktopId, action }, 'BoolReply'),
    prefs: (id, desktopId, patch) =>
      rpc(`${base}/account/${id}/prefs`, 'PrefsReq', { id, desktopId, ...patch }, 'BoolReply'),
    // 批量配置：desktopIds 空=全部桌面；set_* 标记本次写入哪些字段；BoolReply.detail=更新台数
    prefsBatch: (payload) =>
      rpc(`${base}/account/${payload.id}/prefs/batch`, 'PrefsBatchReq', payload, 'BoolReply'),
    taskRun: (id, task, desktopId = '') =>
      rpc(`${base}/account/${id}/task/run`, 'RunTaskReq', { id, task, desktopId }, 'BoolReply'),
    // 桌面列表（设备墙数据源）
    desktops: (id) => rpc(`${base}/account/${id}/desktops`, null, null, 'DesktopList', { method: 'GET' }),
  }
}

// ===== 仅天翼云：验证码 / 扫码 / 桌面 / 积分商城 =====
export const ctyunApi = {
  captcha: (user) =>
    rpc('/api/account/captcha', null, null, 'CaptchaImage', { method: 'GET', query: { user } }),
  qrGenerate: (name = '') =>
    rpc('/api/account/qrcode/generate', 'QrGenerateReq', { name }, 'QrGenerateReply'),
  qrStatus: (qrId) =>
    rpc('/api/account/qrcode/status', null, null, 'QrStatusReply', { method: 'GET', query: { qrId } }),
  desktops: (id) => rpc(`/api/account/${id}/desktops`, null, null, 'DesktopList', { method: 'GET' }),
  // 30060/30090 风控：验证码重新验证（statusText 含「需要图形验证码」时触发）
  reloginCaptcha: (id) =>
    rpc(`/api/account/${id}/relogin/captcha`, null, null, 'CaptchaImage', { method: 'GET' }),
  reloginCaptchaVerify: (id, captchaCode) =>
    rpc(`/api/account/${id}/relogin/captcha/verify`, 'CaptchaVerifyReq', { id, captchaCode }, 'BoolReply'),
  // 30060/30090 风控：短信验证设备绑定（与验证码重新验证同源触发信号）
  smsCaptcha: (id) => rpc(`/api/account/${id}/sms/captcha`, null, null, 'CaptchaImage', { method: 'GET' }),
  smsSend: (id, captchaCode) =>
    rpc(`/api/account/${id}/sms/send`, 'SmsSendReq', { id, captchaCode }, 'BoolReply'),
  smsVerify: (id, verificationCode) =>
    rpc(`/api/account/${id}/sms/verify`, 'SmsVerifyReq', { id, verificationCode }, 'BoolReply'),
  points: (id) => rpc(`/api/account/${id}/points`, null, null, 'PointsReply', { method: 'GET' }),
  rewards: (accId) => rpc('/api/rewards', null, null, 'RewardList', { method: 'GET', query: { accId } }),
  redeem: (p) => rpc('/api/redeem', 'RedeemReq', p, 'BoolReply'),
}

// ===== 移动云 ydpc：登录分支短信验证（ecloud need_* 流程） =====
export const ydpcApi = {
  // YdpcSmsReq { accId, branch, mobile, code, isTemporary } -> YdpcLoginBranch
  smsSend: (p) => rpc('/api/ydpc/account/sms/send', 'YdpcSmsReq', p, 'YdpcLoginBranch'),
  smsVerify: (p) => rpc('/api/ydpc/account/sms/verify', 'YdpcSmsReq', p, 'YdpcLoginBranch'),
}

// ===== 认证 / 用户 =====
export const authApi = {
  login: (username, password) =>
    rpc('/api/auth/login', 'LoginReq', { username, password }, 'UserReply'),
  logout: () => rpc('/api/auth/logout', 'Empty', {}),
  me: () => rpc('/api/auth/me', null, null, 'UserReply', { method: 'GET', silent401: true }),
  changePwd: (oldPwd, newPwd) =>
    rpc('/api/auth/changepwd', 'ChangePwdReq', { oldPwd, newPwd }, 'BoolReply'),
}

export const userApi = {
  list: () => rpc('/api/users', null, null, 'UserList', { method: 'GET' }),
  create: (username, password, role) =>
    rpc('/api/users', 'CreateUserReq', { username, password, role }, 'UserReply'),
  resetPwd: (id, password) =>
    rpc(`/api/users/${id}/resetpwd`, 'ResetPwdReq', { id, password }, 'BoolReply'),
  remove: (id) => rpc(`/api/users/${id}/delete`, 'IdReq', { id }, 'BoolReply'),
}

// ===== 设置 / 日志 / 系统 =====
export const settingsApi = {
  get: () => rpc('/api/settings', null, null, 'SettingsMsg', { method: 'GET' }),
  save: (s) => rpc('/api/settings', 'SettingsMsg', s, 'BoolReply'),
}

export const logApi = {
  recent: (q) => rpc('/api/logs/recent', 'LogQuery', q, 'LogList'),
  // SSE 例外：仍是 JSON 行，走 EventSource
  streamUrl: (q) => {
    const p = new URLSearchParams()
    for (const k of ['limit', 'level', 'scope', 'account']) {
      if (q[k] !== undefined && q[k] !== null && q[k] !== '') p.set(k, String(q[k]))
    }
    const qs = p.toString()
    return `/api/logs/stream${qs ? '?' + qs : ''}`
  },
}

export const systemApi = {
  info: () => rpc('/api/system/info', null, null, 'SystemInfo', { method: 'GET' }),
}

// ===== 免密直通（open 端点：天翼为 JSON 体系；ydpc 失败时可能返回 Envelope+BoolReply） =====
// POST /api[/ydpc]/account/{id}/open?desktopId=
// 成功 → { success, accId, desktopId, desktopName, authData, authExpiredAt, targetUrl, directViewUrl, displayConfig }
// ydpc 不支持网页直通 → code=1 + BoolReply{ok=false, detail=人话提示}
import { Envelope, tryDecode as tryDecodeMsg } from './proto'

function parseOpenBody(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf || [])
  // 1) 天翼 open 是 JSON 体系
  try {
    const text = new TextDecoder('utf-8').decode(bytes).trim()
    if (text.startsWith('{')) {
      const j = JSON.parse(text)
      const ok = j.success !== false && Number(j.code ?? 0) === 0
      return {
        success: ok,
        directViewUrl: j.directViewUrl || '',
        name: j.desktopName || '',
        detail: j.detail || (ok ? '' : j.msg || ''),
      }
    }
  } catch {
    /* 非 JSON，按 Protobuf Envelope 解 */
  }
  // 2) Envelope + BoolReply（ydpc 拒绝分支）
  const env = Envelope.decode(bytes)
  const code = Number(env.code)
  const br = tryDecodeMsg(env.data, 'BoolReply')
  return {
    success: code === 0,
    directViewUrl: '',
    name: '',
    detail: br?.detail || env.msg || '',
  }
}

async function openDirect(platform, accId, desktopId) {
  const path =
    platform === 'ydpc' ? `/api/ydpc/account/${accId}/open` : `/api/account/${accId}/open`
  const res = await axios.post(path, {}, {
    params: desktopId ? { desktopId } : {},
    withCredentials: true,
    timeout: 30000,
    responseType: 'arraybuffer',
  })
  return parseOpenBody(res.data)
}

/**
 * 打开远程桌面统一流程：优先免密直通（open → directViewUrl）。
 * 返回 via：
 *  - 'direct'      成功拿 directViewUrl（url/name）
 *  - 'blocked'     后端明确拒绝（detail 人话文案，如"移动云暂不支持网页免密直通"），不做 connectUrl 降级
 *  - 'connectUrl'  其它失败且有 connectUrl 兜底（url）
 *  - 'none'        失败且无兜底（err）
 */
export async function resolveDesktopOpenUrl(platform, accId, d) {
  try {
    const data = await openDirect(platform, accId, d?.desktopId || '')
    if (data.success && data.directViewUrl) {
      return { via: 'direct', url: data.directViewUrl, name: data.name }
    }
    if (data.detail) return { via: 'blocked', detail: data.detail }
    throw new Error('后端未返回 directViewUrl')
  } catch (e) {
    if (e?.response?.status === 401) kickToLogin()
    // ydpc 桌面 connect_url 本就为空，只有天翼等有值时才值得降级
    if (d?.connectUrl) return { via: 'connectUrl', url: d.connectUrl, err: e }
    return { via: 'none', err: e }
  }
}
