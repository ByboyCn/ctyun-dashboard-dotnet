// 全站统一的二进制 RPC 封装。
// 请求：消息 -> protobuf 二进制（Content-Type: application/x-protobuf）；
// 响应：Envelope{code,msg,data} 二进制，data 按端点表的 respMsgName 解码。
// 例外：GET /api/logs/stream 仍为 SSE（JSON 行），见 views/LogsView.vue。
// 认证：Cookie sid（withCredentials），HTTP 401 时清态跳登录。
import axios from 'axios'
import { Envelope, decodeData, encodeMsg } from './proto'

const http = axios.create({
  baseURL: '',
  timeout: 30000,
  withCredentials: true,
  responseType: 'arraybuffer',
})

let kicking = false
export function kickToLogin() {
  localStorage.removeItem('ctydash.user')
  if (kicking || location.hash.startsWith('#/login')) return
  kicking = true
  location.hash = '#/login'
  setTimeout(() => {
    kicking = false
  }, 1500)
}

http.interceptors.response.use(
  (res) => res,
  (err) => {
    const status = err.response?.status
    if (status === 401) {
      if (!err.config?.silent401) kickToLogin()
      err.friendly = '未登录或会话已过期'
    } else if (err.response) {
      err.friendly = `后端返回 HTTP ${status}`
    } else if (err.code === 'ECONNABORTED') {
      err.friendly = '请求超时，请确认后端服务是否在线'
    } else {
      err.friendly = '网络错误，无法连接后端'
    }
    return Promise.reject(err)
  },
)

/**
 * rpc(path, reqMsgName, reqObj, respMsgName, opts)
 * - reqMsgName 为 null：无体端点（GET，数据走 opts.query）
 * - respMsgName 为 null：返回原始 Envelope{code,msg,data:Uint8Array}，由调用方自行解码
 * - opts: { method = 'POST', query, silent401 = false, timeout, acceptCodes = [] }
 *   acceptCodes：非零但需调用方自行分支的 code（如 /api/account/add 的 code=2=需验证码），
 *   命中时不抛错，按 respMsgName 规则原样返回 envelope
 */
export async function rpc(path, reqMsgName, reqObj = null, respMsgName = null, opts = {}) {
  const { method = 'POST', query, silent401 = false, timeout, acceptCodes = [] } = opts
  const hasBody = !!(reqMsgName && method !== 'GET')
  // Blob：字节精确且不可变，绕开任何对 TypedArray 的默认转换
  const res = await http.request({
    url: path,
    method,
    data: hasBody ? new Blob([encodeMsg(reqMsgName, reqObj)], { type: 'application/x-protobuf' }) : undefined,
    params: query,
    headers: hasBody ? { 'Content-Type': 'application/x-protobuf' } : undefined,
    timeout,
    silent401,
  })

  let env
  try {
    env = Envelope.decode(new Uint8Array(res.data))
  } catch {
    throw errOf('响应不是合法的 Envelope，请确认后端为二进制协议')
  }
  const code = Number(env.code)
  if (code !== 0 && !acceptCodes.includes(code)) throw errOf(env.msg || `请求失败(code=${code})`)
  if (!respMsgName) return { code, msg: env.msg, data: env.data }
  try {
    return decodeData(env.data, respMsgName)
  } catch {
    throw errOf(`响应 data 解码失败（期望消息 ${respMsgName}）`)
  }
}

function errOf(msg) {
  const e = new Error(msg)
  e.friendly = msg
  return e
}
