# ---------- 构建阶段：NativeAOT（需要 clang + zlib1g-dev） ----------
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
RUN apt-get update && apt-get install -y --no-install-recommends clang zlib1g-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src

COPY proto/ ./proto/
COPY CtyunDashboard.csproj ./
RUN dotnet restore

COPY . .
RUN dotnet publish CtyunDashboard.csproj -c Release -r linux-x64 \
    -p:PublishAot=true -p:StripSymbols=true -o /app/publish

# ---------- 前端（可选：构建 Vue 控制台并入单体镜像） ----------
FROM node:22-alpine AS web
WORKDIR /web
COPY web/package.json web/pnpm-lock.yaml* ./
RUN (corepack enable && pnpm install --frozen-lockfile) || npm install
COPY web/ .
RUN pnpm run build || npm run build

# ---------- 运行阶段 ----------
FROM mcr.microsoft.com/dotnet/runtime-deps:10.0
WORKDIR /app
COPY --from=build /app/publish .
# 单体部署：内置前端构建产物（前后端分离部署时可用 nginx 直接服务 web/dist，删掉此行）
COPY --from=web /web/dist ./web/dist

ENV PORT=8571 \
    TZ=Asia/Shanghai \
    CTYUN_DATA_DIR=/app/data
EXPOSE 8571
VOLUME ["/app/data"]
ENTRYPOINT ["/app/ctyun-dashboard"]
