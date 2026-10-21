// =============================================================================
// CtyunDashboard.DesktopView / DesktopViewPage.cs
// =============================================================================
// 对齐参考实现（Node.js，只读）：dashboard-analysis/server.js
//   · 5665-5746  GET /api/accounts/:id/web-launch（open 接口）
//                → POST /api/account/{id}/open（本文件 BuildOpenPayloadAsync，由 Routes 注册）
//                返回 authData（loginInfo 全量 + logined/bondedDevice/deviceType + timestamp）、
//                authExpiredAt(72h)、targetUrl、directViewUrl（对齐 5713-5741）
//   · 3517-3714  GET /desktop-view 引导页
//                → 免密注入脚本（对齐 3581-3695）：localStorage/sessionStorage 写入
//                  authData / web_device_code / authExpiredAt / judgeUserEId / loginAt，
//                  fetch+XHR API 代理拦截器（8810/8816/-deskmgr → /ctyun-proxy），
//                  Web Worker 拦截（bbenc.worker.js → /workers/），hash 路由锁定 #/desktop?id=，
//                  移动端横屏沉浸式 CSS
//   · 3556-3557  objId → base64：b64Id = base64(desktopId)，targetUrl = pc.ctyun.cn/#/desktop?id=<b64>
//
// loginInfo 等价物（AccountRuntime._api 为私有、Engine.cs 不可改）：
//   落盘登录态 row.EncSession（CyApi.ExportSession）中的 "profile" 字段 = 官方登录响应
//   data 全量对象 —— 即 JS 版 client.loginInfo；userId/tenantId/secretKey/userName 取会话
//   顶层字段。桌面列表用 Db.DesktopsOf（引擎 SyncDesktopsAsync 维护）。零在线调用；
//   仅当落盘态缺失/损坏时现场登录一次兜底（等价 JS if (!client.loginInfo) await client.login()）。
//
// AOT：JsonObject/JsonNode 手工组装 + AppJson source-gen（AppJson.Default.JsonObject）序列化；
//      内嵌 JSON 对 "</" 做 \u003c 转义（防 </script> 逃逸），并转义 U+2028/U+2029。
// =============================================================================

using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using CtyunDashboard.CtYun;
using CtyunDashboard.Persist;

namespace CtyunDashboard.DesktopView;

public static class DesktopViewPage
{
    private const long AuthTtlMs = 72L * 3600 * 1000; // 对齐 authExpiredAt = now + 72h

    // -----------------------------------------------------------------------
    // POST /api/account/{id}/open —— 返回现成 JSON（前端 web-dev 直接消费）
    // -----------------------------------------------------------------------
    internal static async Task<(JsonObject? Payload, string Error, int Status)> BuildOpenPayloadAsync(
        SmAccount row, string desktopId, string sessionToken, CancellationToken ct)
    {
        var (authDataJson, b64Id, desktopName, err) = await BuildAuthPackAsync(row, desktopId, ct).ConfigureAwait(false);
        if (err != "") return (null, err, 500);

        var picked = pickDesktop(row, desktopId);
        string objId = picked?.DesktopId ?? "";
        long nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        string expiredAt = (nowMs + AuthTtlMs).ToString();
        string targetUrl = "https://pc.ctyun.cn/#/desktop?id=" + Uri.EscapeDataString(b64Id);
        string directViewUrl = "/desktop-view?accId=" + Uri.EscapeDataString(row.Id) +
                               "&token=" + Uri.EscapeDataString(sessionToken) +
                               "&desktopId=" + Uri.EscapeDataString(objId);

        var payload = new JsonObject
        {
            ["success"] = true,
            ["user"] = row.User,
            ["deviceCode"] = "web",
            ["accId"] = row.Id,
            ["desktopId"] = objId,
            ["desktopName"] = desktopName,
            // 注意：不回传账号明文密码（JS 版返回了 acc.password，此处刻意省略）
            ["authData"] = JsonNode.Parse(authDataJson),
            ["authExpiredAt"] = expiredAt,
            ["targetUrl"] = targetUrl,
            ["directViewUrl"] = directViewUrl,
            ["desktopUrl"] = "https://pc.ctyun.cn/#/desktop-list",
            ["displayConfig"] = new JsonObject { ["width"] = 2560, ["height"] = 1440, ["scale"] = 150 },
        };
        return (payload, "", 0);
    }

    private static SmDesktop? pickDesktop(SmAccount row, string desktopId)
    {
        var desks = Svc.Db.DesktopsOf(row.Id);
        if (desks.Count == 0) return null;
        if (!string.IsNullOrEmpty(desktopId))
        {
            var m = desks.FirstOrDefault(d => d.DesktopId == desktopId);
            if (m != null) return m;
        }
        return desks[0];
    }

    // -----------------------------------------------------------------------
    // GET /desktop-view —— 免密直通引导页（后端直接返回 HTML）
    // -----------------------------------------------------------------------
    public static void Map(WebApplication app)
    {
        app.MapGet("/desktop-view", async ctx =>
        {
            // 鉴权：query token（directViewUrl 携带）或 Cookie sid，等价 getSessionFromReq(req, parsedUrl)
            var token = ctx.Request.Query["token"].ToString();
            if (token == "") token = ctx.Request.Cookies["sid"] ?? "";
            SmUser? user = null;
            if (token != "")
            {
                var session = Svc.Db.FindSession(token);
                if (session != null && string.Compare(session.ExpiresAt, Db.Now(), StringComparison.Ordinal) >= 0)
                    user = Svc.Db.UserById(session.UserId);
            }
            if (user == null)
            {
                ctx.Response.StatusCode = 401;
                ctx.Response.ContentType = "text/html; charset=utf-8";
                await ctx.Response.WriteAsync("<h3 style=\"font-family:sans-serif;padding:20px;\">未授权：请先在仪表盘登录后再访问云电脑</h3>", ctx.RequestAborted);
                return;
            }

            var accId = ctx.Request.Query["accId"].ToString();
            var row = accId != "" ? Svc.Db.AccountById(accId) : null;
            if (row == null)
            {
                ctx.Response.StatusCode = 404;
                ctx.Response.ContentType = "text/html; charset=utf-8";
                await ctx.Response.WriteAsync("<h3 style=\"font-family:sans-serif;padding:20px;\">云电脑账号不存在</h3>", ctx.RequestAborted);
                return;
            }
            if (user.Role != "admin" && row.Owner != user.Username)
            {
                ctx.Response.StatusCode = 403;
                ctx.Response.ContentType = "text/html; charset=utf-8";
                await ctx.Response.WriteAsync("<h3 style=\"font-family:sans-serif;padding:20px;\">权限不足：无权访问该云电脑</h3>", ctx.RequestAborted);
                return;
            }

            var desktopId = ctx.Request.Query["desktopId"].ToString();
            var (authDataJson, b64Id, _, err) = await BuildAuthPackAsync(row, desktopId, ctx.RequestAborted).ConfigureAwait(false);
            if (err != "")
            {
                ctx.Response.StatusCode = 500;
                ctx.Response.ContentType = "text/html; charset=utf-8";
                await ctx.Response.WriteAsync("<h3 style=\"font-family:sans-serif;padding:20px;\">连接云电脑服务异常: " + WebUtility.HtmlEncode(err) + "</h3>", ctx.RequestAborted);
                return;
            }

            string indexHtml = await PcProxy.GetUpstreamIndexAsync(ctx.RequestAborted).ConfigureAwait(false);
            string html = Inject(indexHtml, authDataJson, Uri.EscapeDataString(b64Id), string.IsNullOrEmpty(row.Name) ? row.User : row.Name);
            ctx.Response.ContentType = "text/html; charset=utf-8";
            ctx.Response.Headers["Cache-Control"] = "no-store";
            await ctx.Response.WriteAsync(html, ctx.RequestAborted);
        });
    }

    // -----------------------------------------------------------------------
    // authData 组装（对齐 server.js 5713-5727）+ 桌面选择 + b64Id
    // -----------------------------------------------------------------------
    internal static async Task<(string AuthDataJson, string B64Id, string DesktopName, string Error)> BuildAuthPackAsync(
        SmAccount row, string? desktopId, CancellationToken ct)
    {
        try
        {
            // 1. loginInfo 等价物：落盘登录态（ExportSession 的 profile = 官方登录响应 data 全量）
            JsonObject? loginInfo = null;
            long userId = 0, tenantId = 0;
            string secretKey = "", userName = "";
            if (row.EncSession != "")
            {
                try
                {
                    using var doc = JsonDocument.Parse(Svc.Db.Unprotect(row.EncSession));
                    var j = doc.RootElement;
                    if (j.TryGetProperty("profile", out var pf) && pf.ValueKind == JsonValueKind.String)
                    {
                        var pfRaw = pf.GetString();
                        if (!string.IsNullOrEmpty(pfRaw))
                        {
                            using var pd = JsonDocument.Parse(pfRaw);
                            if (pd.RootElement.ValueKind == JsonValueKind.Object)
                                loginInfo = JsonNode.Parse(pd.RootElement.GetRawText()) as JsonObject;
                        }
                    }
                    if (j.TryGetProperty("userId", out var ui) && ui.ValueKind == JsonValueKind.Number) userId = ui.GetInt64();
                    if (j.TryGetProperty("tenantId", out var ti) && ti.ValueKind == JsonValueKind.Number) tenantId = ti.GetInt64();
                    secretKey = GetStr(j, "secretKey");
                    userName = GetStr(j, "userName");
                }
                catch
                {
                    // 落盘态损坏 → 走现场登录兜底
                }
            }

            // 2. 落盘态缺失 → 现场登录一次（等价 JS：if (!client.loginInfo) await client.login()）
            if (loginInfo == null || userId == 0 || secretKey == "")
            {
                if (row.EncPassword == "")
                    return ("", "", "", "本地无登录凭据，请先在仪表盘重新验证该账号");
                using var api = new CyApi(row.User, (lv, acc, msg) => Svc.Logs.Write(lv, "DesktopView", row.Name, msg));
                var lr = await api.LoginAsync(row.User, Svc.Db.Unprotect(row.EncPassword), null);
                if (lr.Code != 0 || !api.LoggedIn)
                    return ("", "", "", "账号登录失败: " + lr.Code + " " + lr.Msg);
                if (api.Profile.ValueKind == JsonValueKind.Object)
                    loginInfo = JsonNode.Parse(api.Profile.GetRawText()) as JsonObject;
                userId = api.UserId;
                tenantId = api.TenantId;
                secretKey = api.SecretKey;
                userName = api.UserName;
            }

            // 3. 桌面选择：Db 落盘桌面表（引擎 SyncDesktopsAsync 维护），desktopId 缺省取第一台
            var desks = Svc.Db.DesktopsOf(row.Id);
            if (desks.Count == 0)
                return ("", "", "", "未检测到名下可用云电脑（请先在仪表盘执行一次同步）");
            var pick = desks[0];
            if (!string.IsNullOrEmpty(desktopId))
            {
                var m = desks.FirstOrDefault(d => d.DesktopId == desktopId);
                if (m != null) pick = m;
            }
            string objId = pick.DesktopId;
            string b64Id = Convert.ToBase64String(Encoding.UTF8.GetBytes(objId));

            // 4. authData（对齐 5713-5727：loginInfo 展开 + 固定覆盖字段）
            var auth = loginInfo?.DeepClone() as JsonObject ?? new JsonObject();
            auth["logined"] = true;
            auth["userId"] = userId;
            auth["userName"] = FirstNonEmpty(userName, GetNodeStr(auth, "userName"));
            auth["userEid"] = GetNodeStr(auth, "userEid");
            auth["userAccount"] = GetNodeStr(auth, "userAccount");
            auth["mobilephone"] = FirstNonEmpty(GetNodeStr(auth, "mobilephone"), row.User);
            auth["tenantId"] = tenantId;
            auth["secretKey"] = secretKey;
            auth["deviceType"] = "60"; // client.deviceType（CTG-DEVICETYPE 同源）
            auth["bondedDevice"] = true;
            auth["commonLoginReqHeader"] = GetNodeStr(auth, "commonLoginReqHeader");
            auth["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            var authDataJson = JsonSerializer.Serialize(auth, AppJson.Default.JsonObject);
            return (authDataJson, b64Id, string.IsNullOrEmpty(pick.Name) ? "云电脑" : pick.Name, "");
        }
        catch (Exception ex)
        {
            return ("", "", "", ex.Message);
        }
    }

    // -----------------------------------------------------------------------
    // 注入脚本（对齐 3581-3695）+ <head> 注入（对齐 3699）
    // -----------------------------------------------------------------------
    private const string InjectTemplate = """
<script>
(function() {
  // 1. 自动免密注入天翼官方认证凭据至 localStorage / sessionStorage
  var authData = __AUTHDATA__;
  var expiredAt = '__EXPIREDAT__';
  var b64Id = '__B64ID__';
  try {
    localStorage.setItem('web_device_code', 'web');
    localStorage.setItem('authExpiredAt', expiredAt);
    localStorage.setItem('authData', JSON.stringify(authData));
    localStorage.setItem('judgeUserEId', authData.userEid || '');
    localStorage.setItem('loginAt', Date.now().toString());
    sessionStorage.setItem('authExpiredAt', expiredAt);
    sessionStorage.setItem('authData', JSON.stringify(authData));
    sessionStorage.setItem('user_name', authData.userName || '');
    sessionStorage.setItem('userId', String(authData.userId || ''));
  } catch (e) {
    console.error('Failed to set localStorage', e);
  }

  // 2. API 请求代理拦截器（规避跨域与 Origin 防盗链；不得占用仪表盘 /api，走 /ctyun-proxy）
  var proxyBase = '/ctyun-proxy?target=';
  function rewriteUrl(u) {
    if (!u || typeof u !== 'string') return u;
    if (u.indexOf(proxyBase) === 0) return u;
    if (u.indexOf('.ctyun.cn:8810') >= 0 || u.indexOf('.ctyun.cn:8816') >= 0 || u.indexOf('-deskmgr.ctyun.cn') >= 0) {
      return proxyBase + encodeURIComponent(u);
    }
    return u;
  }
  var origFetch = window.fetch;
  window.fetch = function(resource, init) {
    try {
      if (typeof resource === 'string') {
        resource = rewriteUrl(resource);
      } else if (resource && resource.url) {
        resource = new Request(rewriteUrl(resource.url), resource);
      }
    } catch (e) {}
    return origFetch.call(this, resource, init);
  };
  var origOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function() {
    var args = Array.prototype.slice.call(arguments);
    try { args[1] = rewriteUrl(args[1]); } catch (e) {}
    return origOpen.apply(this, args);
  };

  // 3. Web Worker 拦截：bbenc 解码器走同源代理（画面解码正常通信）
  var OrigWorker = window.Worker;
  window.Worker = function(scriptUrl, options) {
    if (typeof scriptUrl === 'string' && scriptUrl.indexOf('bbenc.worker.js') >= 0) {
      scriptUrl = '/workers/bbenc.worker.js';
    }
    return new OrigWorker(scriptUrl, options);
  };

  // 4. 路由锁定进入云电脑操作界面
  //    （hash 不落服务端：本页路径 /desktop-view 已是同源 SPA 宿主，刷新后重新注入登录态）
  var targetHash = '#/desktop?id=' + b64Id;
  if (!window.location.hash || window.location.hash.indexOf('/login') >= 0 || window.location.hash.indexOf('/desktop-list') >= 0) {
    window.location.hash = targetHash;
  }

  // 5. 移动端横屏沉浸式全屏视图（CSS + 屏幕旋转自适应与触控手势防阻断）
  var isMobileView = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent) || window.innerWidth <= 768;
  if (isMobileView) {
    var mobileStyle = document.createElement('style');
    mobileStyle.innerHTML = 'html,body{width:100vw!important;height:100vh!important;margin:0!important;padding:0!important;overflow:hidden!important;background:#000!important;touch-action:none!important;-webkit-user-select:none!important;user-select:none!important}#app,.desktop-container,canvas,video{width:100vw!important;height:100vh!important;max-width:100vw!important;max-height:100vh!important;object-fit:contain!important}';
    document.head.appendChild(mobileStyle);
    try {
      if (screen.orientation && screen.orientation.lock) {
        screen.orientation.lock('landscape')['catch'](function() {});
      }
    } catch (e) {}
  }
})();
</script>
""";

    internal static string Inject(string indexHtml, string authDataJson, string b64IdEncoded, string accTitle)
    {
        // JSON 内嵌防逃逸："<" → \u003c（杜绝 </script> 截断），并转义 JS 保留控制字符
        var safeJson = authDataJson
            .Replace("<", "\\u003c", StringComparison.Ordinal)
            .Replace("\u2028", "\\u2028", StringComparison.Ordinal)
            .Replace("\u2029", "\\u2029", StringComparison.Ordinal);

        var script = InjectTemplate
            .Replace("__AUTHDATA__", safeJson, StringComparison.Ordinal)
            .Replace("__EXPIREDAT__", DateTimeOffset.UtcNow.Add(AuthTtl).ToUnixTimeMilliseconds().ToString(), StringComparison.Ordinal)
            .Replace("__B64ID__", b64IdEncoded, StringComparison.Ordinal);

        var head = "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover\">" +
                   "<title>天翼云电脑 - " + WebUtility.HtmlEncode(accTitle) + "</title>" + script;

        int idx = indexHtml.IndexOf("<head>", StringComparison.OrdinalIgnoreCase);
        if (idx >= 0) return indexHtml.Insert(idx + "<head>".Length, head);
        int bodyIdx = indexHtml.IndexOf("<body", StringComparison.OrdinalIgnoreCase);
        if (bodyIdx >= 0) return indexHtml.Insert(bodyIdx, head);
        return head + indexHtml;
    }

    private static readonly TimeSpan AuthTtl = TimeSpan.FromMilliseconds(AuthTtlMs);

    // ---------- 小工具 ----------
    private static string GetStr(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

    private static string GetNodeStr(JsonObject? o, string name)
    {
        if (o == null) return "";
        var n = o[name];
        return n is JsonValue v && v.TryGetValue<string>(out var s) ? s : "";
    }

    private static string FirstNonEmpty(string a, string b) => a != "" ? a : b;
}
