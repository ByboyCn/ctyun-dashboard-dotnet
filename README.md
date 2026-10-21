# CtyunDashboard（.NET 10 NativeAOT 版）

功能完全对标 [muyicn/ctyun-dashboard](https://github.com/muyicn/ctyun-dashboard)（天翼云/移动云电脑多账号保活签到平台）的 .NET 10 重写版：

- **后端**：.NET 10 + NativeAOT 单文件二进制（纯 API，REST + Protobuf 二进制传输 + SSE 日志流）
- **前端**：Vue 3 + Vite + Element Plus（`web/` 独立工程，`proto/api.proto` 为前后端唯一契约源）
- **落盘**：SQLite（`data/ctyun.db`），敏感字段（账号密码/登录态）**国密 SM4-CBC + HMAC-SM3** 加密存储，口令散列 PBKDF2-HMAC-SM3
- **启动自检**：SM3/SM4 对齐 GB/T 32905/32907-2016 标准向量（含百万次迭代例 3），不过不启动

## 快速开始

```powershell
# 后端（Windows，需 .NET 10 SDK + VS C++ 工具集做 AOT）
dotnet publish CtyunDashboard.csproj -c Release -r win-x64 -o publish
./publish/ctyun-dashboard.exe            # http://127.0.0.1:8571

# 前端
cd web && pnpm install && pnpm run build # 产物 web/dist
# 单体部署：把 web/dist 放到 exe 同目录 web/dist 下即可由后端托管
# 分离部署：nginx 托管 web/dist，/api 反代到 8571
# 开发调试：cd web && pnpm dev（Vite 已代理 /api → 127.0.0.1:8571）
```

Docker（Linux AOT 镜像，多阶段含前端构建）：`docker compose up -d`

默认管理员：`admin / admin123`（首次登录后立即改密）。

## 目录

```
proto/api.proto        唯一契约源（Envelope 信封 + 全部消息 + 端点表）
Core/   Db(SQLite+SM4)  Auth(PBKDF2-SM3)  Logs(SSE+入库)  Scheduler(Cron)  Notify(8渠道+SSRF防御)  Gm(国密)
CtYun/  CyApi(官方API)  Clink(CLINK信令:118身份/112认领/7心跳/在席检测)  Engine(旁观者脉冲+挂机+任务)
Ydpc/   SohoClient(SOHO REST)  CagClient(ZTEC三阶段+TLS数据面)  MqttClient(MQTTnet)  YdpcAccountClient
web/    Vue3 控制台（docs/CONTRACTS.md 页面规格）
```

## 与原版（Node.js）的差异

| 项 | 原版 | 本版 |
|---|---|---|
| 运行时 | Node.js ≥18 | .NET 10 NativeAOT 单文件 |
| 传输 | JSON | Protobuf（SSE 日志除外） |
| 自有数据加密 | AES-256-GCM | 国密 SM4-CBC+HMAC-SM3、PBKDF2-SM3 |
| 存储 | JSON 文件 + 双备份 | SQLite |
| 前端 | 原生 JS | Vue 3 前后端分离 |
| 移动公众(ecloud) | Python 侧车 | 暂未移植（见 TODO） |

> 曾按需求引入 SqlSugar 做落盘，实测其查询物化依赖反射 emit（DynamicMethod），与 NativeAOT 硬冲突，已替换为 AOT 兼容的 Microsoft.Data.Sqlite 直连层（表结构与接口不变）。如需 SqlSugar 可改 JIT 发布（去掉 `PublishAot`）。

## 已知边界（TODO）

- 移动公众（ecloud）协议侧未移植（原版为 Python sidecar）
- 移动云 `connectStr` 解码器（cag_boot.js）未移植，CAG 拨号需先解出内层材料；SCG 数据面未移植（保留"SCG=跳过 CAG"语义）
- CLINK 剪贴板同步（原版亦未实现）——可基于本地 deskapp 的 ClinkClipboardBridge 研究做成差异化功能
- 打卡落账复检、兑换风控文案映射等细节以真机回归为准
