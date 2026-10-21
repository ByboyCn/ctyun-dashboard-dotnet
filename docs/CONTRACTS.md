# CtyunDashboard 接口契约（前后端分离）

> 后端：.NET 10 NativeAOT（`ctyun-dashboard` 单文件二进制，默认端口 `8571`）
> 前端：Vue 3 + Vite + Element Plus（`web/` 独立工程，开发时 Vite proxy `/api` → `http://127.0.0.1:8571`）
> 认证：Cookie `sid`（也接受 `Authorization: Bearer <sid>`）。角色：`admin` / `user`。
> 响应统一包裹：`{"code":0,"msg":"ok","data":...}`；错误 `code!=0`。HTTP 状态码恒为 200（除 401 未登录）。

## 1. 认证与用户

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | /api/auth/login | `{username,password}` → data:`{id,username,role}`，Set-Cookie sid |
| POST | /api/auth/logout | 注销当前会话 |
| GET | /api/auth/me | data:`{id,username,role}` 或 401 |
| POST | /api/auth/changepwd | `{oldPwd,newPwd}` |
| GET | /api/users | admin：用户列表 |
| POST | /api/users | admin：`{username,password,role}` |
| DELETE | /api/users/{id} | admin |
| POST | /api/users/{id}/resetpwd | admin：`{password}` |

## 2. 天翼云账号

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | /api/accounts | 账号卡片列表（含实时 metrics：在线状态/积分/任务进度/桌面数/下次脉冲倒计时） |
| POST | /api/account/add | `{name?,user,password,captchaCode?,captchaKey?}`；需要验证码时 data:`{needCaptcha:true,captchaImage,captchaKey}` |
| GET | /api/account/captcha | `?user=` → `{captchaImage(dataURL), captchaKey}` |
| POST | /api/account/qrcode/generate | `{name?}` → `{qrId, qrUrl}`（qrUrl 前端渲染成二维码） |
| GET | /api/account/qrcode/status | `?qrId=` → `{status: waiting|scanned|confirmed|expired, accId?}` |
| POST | /api/account/{id}/delete | |
| POST | /api/account/{id}/update | `{name?,keepaliveEnabled?,pulseIntervalSeconds?,autoSign?,autoAi?,autoHang?,autoRedeem?,redeemStrategy?,redeemDay?}` |
| POST | /api/account/{id}/relogin | 用已存凭据重新登录 |
| GET | /api/account/{id}/desktops | data: 桌面数组（desktopId,name,status,规格,per-VM 开关,lastPulseAt） |
| POST | /api/account/{id}/sync | 立即刷新桌面列表+任务中心+积分 |
| POST | /api/account/{id}/power | `{desktopId,action}` action=poweron\|awake\|shutdown\|reboot |
| POST | /api/account/{id}/prefs | per-VM：`{desktopId,keepaliveEnabled?,taskEnabled?,keepaliveInterval?}` |
| POST | /api/account/{id}/task/run | `{task:"sign"\|"ai"\|"hang",desktopId?}` 立即执行一次 |
| GET | /api/account/{id}/points | `{points,willOutDate,tasks:[{name,current,total,status,points}]}` |
| GET | /api/rewards | `?accId=` 积分商城商品列表 |
| POST | /api/redeem | `{accId,prodId,prodName,costPoints,times,desktopId?,pointType?}` |

桌面对象（/api/account/{id}/desktops）：
```json
{"desktopId":"123","name":"办公机","useStatus":25,"useStatusText":"运行中",
 "spec":"4核8G","keepaliveEnabled":true,"taskEnabled":true,
 "keepaliveInterval":30,"lastPulseAt":"2026-10-20T16:00:00+08:00"}
```

## 3. 移动云（ydpc 前缀，同构）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | /api/ydpc/accounts | 卡片列表 |
| POST | /api/ydpc/account/add | `{platform:"soho"\|"ecloud",user,password,code?}`（ecloud 走侧车等价原生实现） |
| POST | /api/ydpc/account/{id}/delete · /update · /relogin · /sync · /power · /prefs · /task/run | 同天翼语义；power 仅 shutdown\|reboot |

## 4. 设置 / 日志 / 系统

| 方法 | 路径 | 说明 |
|---|---|---|
| GET/POST | /api/settings | admin。`{pulseIntervalSeconds,keepAliveSeconds,cron:{executeTime[],signCron,aiCron,hangCron,redeemCron},redeem:{mode:"monthly"\|"daily"\|"interval",day,stepDays},notify:{channels:[{type,url,secret,accScope}],notifyOnErrorOnly},branding:{title,subtitle}}` |
| GET | /api/logs/recent | `?limit=&scope=&level=&account=` → 日志数组 |
| GET | /api/logs/stream | SSE。事件名 `log` / `metrics`；查询参数同 recent 做服务端过滤 |
| GET | /api/system/info | `{version,startedAt,uptimeSec,runtime:"nativeaot",accountCount}` |

SSE `log` 事件负载：`{ts,level,scope,account,msg}`（level: info/success/warning/error）。

## 5. 前端（Vue）页面规格 — `web/`

技术栈：Vue 3 `<script setup>` + Vite + vue-router + pinia + Element Plus + axios。暗色主题现代控制台。

- `/login` 登录页
- `/` 仪表盘：平台 Tab（天翼/移动）+ 账号卡片网格（可拖拽排序留空位，localStorage 持久化）；卡片：名称、状态徽章、积分、任务三进度（打卡/AI/挂机）、脉冲倒计时、按钮（打开远程桌面 / 电源下拉 / 同步 / 任务立即执行）
- `/logs` 实时日志：SSE 控制台，按平台/级别/账号过滤，自动滚动锁定
- `/settings`（admin）：调度（执行时间点、分项 cron）、通知渠道 CRUD、品牌标题
- `/users`（admin）：用户管理
- 添加账号向导：账密(+图形验证码回显) / 扫码（qrcode 渲染 + 轮询状态）
- 生产构建 `npm run build` → `web/dist`；后端检测到该目录则直接托管（单体部署），分离部署走 nginx

## 6. 移动云驱动（C# `Ydpc/`）移植规格

参考源：`C:\Users\Byboy\AppData\Local\Temp\ctyun-dashboard-analysis\app\ydpc\`
- `SohoClient.cs` ← soho_client.js：`https://api.soho.komect.com` HMAC-SHA256 签名 + RSA 分段加密登录、心跳、官方关机/重启
- `CagClient.cs` ← cag_client.js + zte_cag_tls.js：ZTEC CAG TCP 三阶段握手（TLS + 动态公钥）
- `MqttClient.cs` ← mqtt_client.js：MQTT 3.1.1 over TLS (8883) 原生报文实现
- `YdpcAccountClient.cs` ← ydpc_client.js 的生命周期管理（登录态、VM 列表、保活轮询、熔断）
- 约束：AOT 安全（无反射序列化；DTO 全部进 AppJson source-gen）；HTTP 用 HttpClient，TCP 用 TcpClient+SslStream；不得引入第三方 NuGet 包
