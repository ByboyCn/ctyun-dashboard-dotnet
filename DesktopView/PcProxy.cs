// =============================================================================
// CtyunDashboard.DesktopView / PcProxy.cs
// =============================================================================
// 对齐参考实现（Node.js，只读）：dashboard-analysis/server.js
//   · 3420-3440  getCtyunIndexHtml()          → GetUpstreamIndexAsync()（1h 内存缓存 + 兜底壳 HTML）
//   · 3442-3489  proxyStaticAsset()           → 通用反代（此处不再缓存、直接流式转发）
//   · 3717-3739  /workers/ 、bbEncDecoder/.wasm、/ctyun-static/ 分发
//                                             → 统一路径透传反代（/static/x → pc.ctyun.cn/static/x）
//   · 3742-3816  /api/ctyun-proxy             → /ctyun-proxy（不得占用仪表盘 /api 命名空间）
//   · 3818-3837  / 与 /static/ 先本地后代理    → Program.cs 的 UseDefaultFiles/UseStaticFiles 在前，
//                                              本中间件在后：控制台已有文件被静态中间件短路，
//                                              未命中的路径才落入 pc.ctyun.cn 反代
//
// 路由边界（与现有管线不冲突）：
//   /api/*            → 永远属于仪表盘 Protobuf API（next()）
//   /desktop-view     → 免密直通引导页端点（next()，见 DesktopViewPage.cs）
//   / 与 /index.html  → 控制台入口（web/dist 存在时已被静态中间件接管；不存在则 404，不代理）
//   /ctyun-proxy      → 带显式 target 的官方接口代理（host 白名单 *.ctyun.cn）
//   其余全部          → https://pc.ctyun.cn + 原路径 反代（/workers/、/static/、*.wasm、manifest…）
//
// AOT：纯 Stream 流式拷贝 + 手工头处理，零反射、零序列化。
// =============================================================================

using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Primitives;

namespace CtyunDashboard.DesktopView;

public static class PcProxy
{
    public const string Upstream = "https://pc.ctyun.cn";
    public const string UpstreamHost = "pc.ctyun.cn";

    private static readonly HttpClient Http = CreateClient();
    private static readonly SemaphoreSlim IndexGate = new(1, 1);
    private static (string Html, DateTimeOffset At)? _indexCache;
    private static readonly TimeSpan IndexTtl = TimeSpan.FromHours(1);

    private const string FallbackIndexHtml =
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>天翼量子AI云电脑</title></head><body><div id=\"app\"></div></body></html>";

    /// <summary>逐跳头（RFC 7230）：不得在代理间转发。</summary>
    private static bool IsHopByHop(string headerName)
    {
        return headerName.ToLowerInvariant() is
            "connection" or "keep-alive" or "proxy-connection" or "transfer-encoding" or
            "upgrade" or "te" or "trailer";
    }

    private static HttpClient CreateClient()
    {
        var handler = new SocketsHttpHandler
        {
            UseCookies = false, // Cookie 双向透传：浏览器持有，禁用容器避免吞 Set-Cookie
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None, // 原样字节流转发（保留上游压缩与长度语义）
            ConnectTimeout = TimeSpan.FromSeconds(15),
        };
        return new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan }; // 生命周期由 RequestAborted 驱动
    }

    /// <summary>注册反代中间件。必须在 Routes.Map 末尾调用（晚于 UseDefaultFiles/UseStaticFiles 注册）。</summary>
    public static void Map(WebApplication app)
    {
        app.Use(async (ctx, next) =>
        {
            var path = ctx.Request.Path.Value ?? "/";
            if (path == "/api" || path.StartsWith("/api/", StringComparison.Ordinal) ||
                path.StartsWith("/desktop-view", StringComparison.Ordinal))
            {
                await next(); // 仪表盘 API 与免密直通引导页优先
                return;
            }
            if (path is "/" or "/index.html")
            {
                await next(); // 控制台入口（存在 web/dist 时已被静态中间件短路，不会到这里）
                return;
            }
            if (path == "/ctyun-proxy")
            {
                await ProxyNamedAsync(ctx);
                return;
            }
            await ProxyToPcAsync(ctx, path + ctx.Request.QueryString.Value);
        });
    }

    // -----------------------------------------------------------------------
    // pc.ctyun.cn 路径透传反代（/workers/、/static/、*.wasm、manifest.json、根页面…）
    // -----------------------------------------------------------------------
    internal static Task ProxyToPcAsync(HttpContext ctx, string targetPathAndQuery) =>
        ProxyCoreAsync(ctx, new Uri(Upstream + targetPathAndQuery), addCors: false);

    // -----------------------------------------------------------------------
    // /ctyun-proxy?target=<绝对地址>：官方 API 反代通道（host 白名单 *.ctyun.cn）
    // -----------------------------------------------------------------------
    private static async Task ProxyNamedAsync(HttpContext ctx)
    {
        if (HttpMethods.IsOptions(ctx.Request.Method))
        {
            ctx.Response.StatusCode = 204;
            ctx.Response.Headers["Access-Control-Allow-Origin"] = "*";
            ctx.Response.Headers["Access-Control-Allow-Headers"] = "*";
            ctx.Response.Headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS";
            return;
        }

        var target = ctx.Request.Query["target"].ToString();
        if (target == "")
        {
            ctx.Response.StatusCode = 400;
            ctx.Response.ContentType = "application/json; charset=utf-8";
            await ctx.Response.WriteAsync("{\"error\":\"Missing target\"}", ctx.RequestAborted);
            return;
        }
        if (!Uri.TryCreate(target, UriKind.Absolute, out var uri) ||
            !(uri.Scheme is "https" or "http") ||
            !uri.Host.EndsWith(".ctyun.cn", StringComparison.OrdinalIgnoreCase))
        {
            ctx.Response.StatusCode = 403;
            ctx.Response.ContentType = "application/json; charset=utf-8";
            await ctx.Response.WriteAsync("{\"error\":\"Invalid proxy target\"}", ctx.RequestAborted);
            return;
        }
        await ProxyCoreAsync(ctx, uri, addCors: true);
    }

    // -----------------------------------------------------------------------
    // 核心代理：请求头透传 + Host/Origin/Referer 改写 + 请求体流式转发 +
    //           响应头原样回传（Set-Cookie 透传）+ 响应体流式拷贝
    // -----------------------------------------------------------------------
    private static async Task ProxyCoreAsync(HttpContext ctx, Uri uri, bool addCors)
    {
        try
        {
            using var req = new HttpRequestMessage(new HttpMethod(ctx.Request.Method), uri);

            // 1. 透传请求头（剔除逐跳头与由 HttpClient/Kestrel 托管的头；Cookie 原样透传）
            foreach (var h in ctx.Request.Headers)
            {
                var lk = h.Key.ToLowerInvariant();
                if (lk is "host" or "content-length") continue;
                if (IsHopByHop(lk)) continue;
                if (lk is "origin" or "referer") continue; // 下面统一改写
                req.Headers.TryAddWithoutValidation(h.Key, h.Value.ToArray());
            }
            req.Headers.Host = uri.Host;                                    // Host 改写（pc.ctyun.cn / desk.ctyun.cn…）
            req.Headers.TryAddWithoutValidation("Origin", "https://" + UpstreamHost);   // 官方 Origin 防盗链
            req.Headers.TryAddWithoutValidation("Referer", Upstream + "/");

            // 2. 请求体流式转发
            if (ctx.Request.ContentLength is > 0 || ctx.Request.Headers.ContainsKey("Transfer-Encoding"))
            {
                var content = new StreamContent(ctx.Request.Body);
                if (!string.IsNullOrEmpty(ctx.Request.ContentType))
                    content.Headers.TryAddWithoutValidation("Content-Type", ctx.Request.ContentType);
                if (ctx.Request.ContentLength is > 0)
                    content.Headers.ContentLength = ctx.Request.ContentLength;
                req.Content = content;
            }

            using var resp = await Http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ctx.RequestAborted)
                .ConfigureAwait(false);

            // 3. 响应头原样回传（Set-Cookie 逐条透传；content-length 交给 Kestrel 托管）
            ctx.Response.StatusCode = (int)resp.StatusCode;
            foreach (var h in resp.Headers)
            {
                var lk = h.Key.ToLowerInvariant();
                if (IsHopByHop(lk) || lk == "set-cookie") continue;
                ctx.Response.Headers.Append(h.Key, new StringValues(h.Value.ToArray()));
            }
            foreach (var h in resp.Content.Headers)
            {
                if (h.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase)) continue;
                ctx.Response.Headers.Append(h.Key, new StringValues(h.Value.ToArray()));
            }
            if (resp.Headers.TryGetValues("Set-Cookie", out var cookies))
            {
                foreach (var c in cookies) ctx.Response.Headers.Append("Set-Cookie", c);
            }
            if (addCors)
            {
                ctx.Response.Headers["Access-Control-Allow-Origin"] = "*";
                ctx.Response.Headers["Access-Control-Allow-Headers"] = "*";
                ctx.Response.Headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS";
            }

            // 4. 响应体流式拷贝
            if (!HttpMethods.IsHead(ctx.Request.Method))
                await resp.Content.CopyToAsync(ctx.Response.Body, ctx.RequestAborted).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // 客户端断开/取消：连接由 Kestrel 收尾
        }
        catch (Exception ex)
        {
            if (!ctx.Response.HasStarted)
            {
                ctx.Response.StatusCode = 502;
                ctx.Response.ContentType = "application/json; charset=utf-8";
                await ctx.Response.WriteAsync(
                    "{\"error\":\"Proxy request failed: " + JsonEncodedText.Encode(ex.Message) + "\"}",
                    ctx.RequestAborted);
            }
        }
    }

    // -----------------------------------------------------------------------
    // 官方 SPA 首页（/desktop-view 引导页的宿主 HTML，1h 缓存，对齐 getCtyunIndexHtml）
    // -----------------------------------------------------------------------
    public static async Task<string> GetUpstreamIndexAsync(CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        var cached = _indexCache;
        if (cached.HasValue && now - cached.Value.At < IndexTtl) return cached.Value.Html;

        await IndexGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            cached = _indexCache;
            if (cached.HasValue && now - cached.Value.At < IndexTtl) return cached.Value.Html;
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, Upstream + "/");
                req.Headers.TryAddWithoutValidation("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/137.0.0.0");
                using var resp = await Http.SendAsync(req, ct).ConfigureAwait(false);
                if (resp.IsSuccessStatusCode)
                {
                    var html = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                    if (!string.IsNullOrEmpty(html))
                    {
                        _indexCache = (html, now);
                        return html;
                    }
                }
            }
            catch
            {
                // 上游失败 → 用缓存或兜底壳
            }
            return cached?.Html ?? FallbackIndexHtml;
        }
        finally
        {
            IndexGate.Release();
        }
    }
}
