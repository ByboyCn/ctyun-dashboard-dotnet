// 唯一契约源：CtyunDashboard/proto/api.proto
// 通过 Vite 的 `?raw` 在构建期把 proto 文本内联进产物，运行时用 protobufjs 解析，
// 前后端永远共用同一份消息定义。
import protobuf from 'protobufjs'
import protoText from '../../../proto/api.proto?raw'

const PKG = 'ctyun.api.'

const root = protobuf.parse(protoText, { keepCase: false }).root

const typeCache = new Map()

/** 按消息名取 Type，例如 msgType('AccountCard') -> ctyun.api.AccountCard */
export function msgType(name) {
  let t = typeCache.get(name)
  if (!t) {
    t = root.lookupType(PKG + name)
    typeCache.set(name, t)
  }
  return t
}

/** Envelope{code,msg,data} —— 所有响应的外层包裹 */
export const Envelope = root.lookupType(PKG + 'Envelope')

/** 把消息编码为二进制（请求体）。
 *  ⚠️ 必须 def copy：protobufjs Writer 底层使用共享缓冲池，浏览器端连续 encode 时
 *  finish() 返回的视图会被后续编码污染（表现为请求体逐次累加），因此强制拷贝一份。 */
export function encodeMsg(msgName, obj) {
  const T = msgType(msgName)
  const finished = T.encode(T.fromObject(obj || {})).finish()
  const copy = new Uint8Array(finished.length)
  copy.set(finished)
  return copy
}

/**
 * 把 Envelope.data 字节按指定消息解码为普通 JS 对象。
 * 字段名为 camelCase（parse 时 keepCase:false），int64 -> number，repeated 空时为 []。
 */
export function decodeData(bytes, msgName) {
  const T = msgType(msgName)
  return T.toObject(T.decode(bytes), {
    defaults: true,
    arrays: true,
    longs: Number,
    enums: Number,
    bytes: String,
  })
}

/** 宽松解码：失败返回 null（用于 /api/account/add 的多态响应 NeedCaptcha|BoolReply） */
export function tryDecode(bytes, msgName) {
  try {
    return decodeData(bytes, msgName)
  } catch {
    return null
  }
}
