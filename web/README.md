# CtyunDashboard Web 前端

Vue 3 + Vite + Element Plus 的前后端分离控制台。传输协议为 **Protobuf 二进制**
（契约唯一源：`../proto/api.proto`，前端构建期用 Vite `?raw` 内联 + protobufjs 解析）。

## 开发

```bash
pnpm install        # 或 npm install
pnpm dev            # http://127.0.0.1:5173 ，/api 代理到 http://127.0.0.1:8571
pnpm build          # 产物输出 dist/ ，后端检测到该目录可直接托管（单体部署）
```

## 结构

```
src/
  api/
    proto.js        # api.proto 解析 / 消息编解码（唯一契约源）
    rpc.js          # 统一二进制 RPC：rpc(path, reqMsg, reqObj, respMsg, opts)
    endpoints.js    # 端点表封装 + 平台能力开关（ctyun / ydpc）
  stores/           # pinia：auth（会话）、theme（亮/暗主题）
  router/           # hash 路由 + 登录/admin 守卫
  views/            # 登录 / 仪表盘 / 实时日志(SSE) / 设置 / 用户管理
  components/       # 账号卡片（拖拽排序）/ 添加向导 / 桌面抽屉 / 积分兑换 / 账号设置
```

- 主题：默认暗色，顶栏可切换亮色，选择存 `localStorage('ctydash.theme')`
- 卡片拖拽顺序存 `localStorage('ctydash.order.<platform>')`，支持空位
- 日志页走 SSE（`GET /api/logs/stream`，JSON 行），其余全部二进制 RPC
