using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace CtyunDashboard.CtYun;

public class ApiResult
{
    public int Code { get; set; }
    public string Msg { get; set; } = "";
    public JsonElement Data { get; set; }
    public string Raw { get; set; } = "";
    public Dictionary<string, string> RespHeaders { get; set; } = new();
}

/// <summary>
/// 天翼云官方 API 客户端（移植自 realclient ApiClient，逐端点对齐 dashboard server.js）。
/// negotiationEncKey 密钥协商 + AES-CBC 载荷加密 + CTG-* 签名头。
/// </summary>
public class CyApi : IDisposable
{
    public const string ApiBase = "https://desk.ctyun.cn:8810";
    public const string Origin = "https://pc.ctyun.cn";
    private const string Version = "204000100";

    private readonly HttpClient _http;
    private readonly HttpClientHandler _handler;
    private readonly Action<string, string, string> _log; // level, account, msg
    private readonly string _account;
    private int _seq;

    public string Eid { get; private set; } = "";
    public string Evalue { get; private set; } = "";
    private RSA? _rsa;
    private string? _captchaKey;
    private long _offsetTime;

    public long UserId { get; private set; }
    public long TenantId { get; private set; }
    public string SecretKey { get; private set; } = "";
    public string UserName { get; private set; } = "";
    public string AccessToken { get; private set; } = "";
    public JsonElement Profile { get; private set; }
    public bool LoggedIn { get; private set; }

    /// <summary>服务端要求图形验证码登录（30060/30090 风控标记）；成功登录后清除。</summary>
    public bool NeedsCaptcha { get; private set; }

    /// <summary>供运行时在自动重登失败时标记需要验证码。</summary>
    public void MarkNeedsCaptcha() => NeedsCaptcha = true;

    /// <summary>登出当前内存会话（不清理 Cookie 池以外状态）。</summary>
    public void InvalidateSession() => LoggedIn = false;

    /// <summary>30090 重协商仍失败时的完整重登录回调（由 AccountRuntime 注入）。</summary>
    public Func<Task<bool>>? ReLoginHandler;

    public CyApi(string account, Action<string, string, string> log)
    {
        _account = account; _log = log;
        _handler = new HttpClientHandler { CookieContainer = new CookieContainer(), AutomaticDecompression = DecompressionMethods.All, UseCookies = true };
        _http = new HttpClient(_handler) { Timeout = TimeSpan.FromSeconds(45) };
        _http.DefaultRequestHeaders.Add("Origin", Origin);
        _http.DefaultRequestHeaders.Add("Referer", Origin + "/");
        _http.DefaultRequestHeaders.Add("User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36");
    }

    private CookieContainer Cookies => _handler.CookieContainer!;

    // ---------- 密钥协商 ----------
    public async Task NegotiateAsync()
    {
        var (spkiB64, rsa) = CyCrypto.GenRsaKeyPair();
        _rsa = rsa;
        var body = "{\"etype\":\"2\",\"certType\":\"2\",\"certData\":\"" + spkiB64 + "\"}";
        var resp = await PostPlainAsync("api/auth/client/negotiationEncKey", body);
        using var doc = JsonDocument.Parse(resp.Raw);
        var root = doc.RootElement;
        if (root.GetProperty("code").GetInt32() != 0)
            throw new Exception("negotiationEncKey 失败: " + root.GetProperty("msg").GetString());
        var d = root.GetProperty("data");
        var aesKey = Encoding.UTF8.GetString(CyCrypto.RsaDecryptFlexible(rsa, Convert.FromBase64String(d.GetProperty("encKey").GetString()!)));
        var dec = CyCrypto.AesCbcDecryptFromB64(d.GetProperty("encData").GetString()!, aesKey);
        using var encDoc = JsonDocument.Parse(dec);
        Eid = encDoc.RootElement.GetProperty("eid").GetString() ?? "";
        Evalue = encDoc.RootElement.GetProperty("evalue").GetString() ?? "";
        _log("info", _account, $"密钥协商成功 (AES key {aesKey.Length}B)");
    }

    // ---------- 通用请求 ----------
    private static string BaseFor(string url) =>
        url.StartsWith("selforder/") ? "https://desk.ctyun.cn" : ApiBase;   // 任务中心/积分/商城在 443，不在 :8810

    private HttpRequestMessage BuildRequest(string method, string url, string? jsonBody, Dictionary<string, string>? form)
    {
        var isGet = method == "GET";
        var req = new HttpRequestMessage(new HttpMethod(method), BaseFor(url) + "/" + url);
        var h = req.Headers;
        h.Add("CTG-DEVICECODE", "web");
        h.Add("CTG-DEVICETYPE", "60");
        var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var requestId = nowMs + ++_seq;
        var timestamp = nowMs - _offsetTime;
        h.Add("CTG-REQUESTID", requestId.ToString());
        h.Add("CTG-TIMESTAMP", timestamp.ToString());
        h.Add("CTG-VERSION", Version);
        h.Add("CTG-APPMODEL", "2");
        h.Add("CTG-SOFTWARECODE", "web_client");
        // 对齐原版 dashboard：登录后请求一律【明文体 + CTG 签名头】，不做 eParams 载荷加密
        // （不再声明 CTG-REQDATA-ETYPE / CTG-NEGO-EKEYID，声明了服务端就会尝试解密明文体 → 30090）
        if (LoggedIn)
        {
            h.Add("CTG-TENANTID", TenantId.ToString());
            h.Add("CTG-USERID", UserId.ToString());
            h.Add("CTG-SIGNATURESTR", CyCrypto.Md5Hex($"60{requestId}{TenantId}{timestamp}{UserId}{Version}{SecretKey}"));
        }

        if (form != null && !isGet)
        {
            req.Content = new FormUrlEncodedContent(form);
            req.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/x-www-form-urlencoded");
        }
        else if (jsonBody != null && !isGet)
        {
            req.Content = new StringContent(jsonBody, Encoding.UTF8, "application/json");
        }
        return req;
    }

    private bool _reloginBusy;
    private bool _renewBusy;

    /// <summary>会话被续期/重建后触发（用于落盘刷新，由 AccountRuntime 订阅）。</summary>
    public Action? SessionChanged;

    public async Task<ApiResult> ApiAsync(string method, string url, string? jsonBody = null,
        Dictionary<string, string>? form = null, Dictionary<string, string>? extraHeaders = null)
    {
        // 对齐原版：明文体 + 签名头，无需密钥协商前置
        var result = await SendOnce(method, url, jsonBody, form, extraHeaders);

        // 30060/30090 = 服务端要求图形验证码登录（风控标记）。
        // 这类错误不能自动化绕过——自动重试只会循环触发风控。置 NeedsCaptcha 标记，
        // 由界面引导用户完成一次「验证码重新验证」（对齐原版的重新验证登录入口）。
        if (result.Code == 30060 || result.Code == 30090 || result.Msg.Contains("登录失败，请重试"))
        {
            var first = !NeedsCaptcha;   // 只在状态翻转时提醒一次，避免每请求刷屏
            NeedsCaptcha = true;
            if (first) _log("warning", _account, "服务端要求图形验证码登录（30060/30090）——请在控制台对该账号完成「验证码重新验证」");
        }

        // 会话过期（40010/登录信息已过期）：优先免密续期（不输密码），失败再密码重登，然后重试一次
        if (IsAuthExpired(result.Code, result.Msg) && !_renewBusy && !_reloginBusy &&
            !url.Contains("login") && !url.Contains("genLoginToken"))
        {
            _renewBusy = true;
            try
            {
                _log("warning", _account, "会话已过期，尝试免密续期（genLoginToken→tokenLogin）...");
                try
                {
                    await RenewAsync();
                    _log("success", _account, "会话免密续期成功");
                    SessionChanged?.Invoke();
                }
                catch (Exception ex)
                {
                    _log("warning", _account, "免密续期失败(" + ex.Message + ")，改为密码重登...");
                    if (ReLoginHandler != null && await ReLoginHandler()) SessionChanged?.Invoke();
                }
                result = await SendOnce(method, url, jsonBody, form, extraHeaders);
            }
            finally { _renewBusy = false; }
        }
        return result;
    }

    private async Task<ApiResult> SendOnce(string method, string url, string? jsonBody,
        Dictionary<string, string>? form, Dictionary<string, string>? extraHeaders)
    {
        var req = BuildRequest(method, url, jsonBody, form);
        if (extraHeaders != null)
            foreach (var kv in extraHeaders) req.Headers.TryAddWithoutValidation(kv.Key, kv.Value);
        if (_captchaKey != null && url.Contains("login"))
            req.Headers.TryAddWithoutValidation("ctg-captcha-key", _captchaKey);
        return await SendAsync(req);
    }

    private async Task<(string Raw, Dictionary<string, string> Headers)> PostPlainAsync(string url, string jsonBody)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, ApiBase + "/" + url)
        {
            Content = new StringContent(jsonBody, Encoding.UTF8, "application/json"),
        };
        req.Headers.Add("CTG-DEVICECODE", "web");
        req.Headers.Add("CTG-DEVICETYPE", "60");
        req.Headers.Add("CTG-REQUESTID", (DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + ++_seq).ToString());
        req.Headers.Add("CTG-TIMESTAMP", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString());
        req.Headers.Add("CTG-VERSION", Version);
        req.Headers.Add("CTG-APPMODEL", "2");
        using var resp = await _http.SendAsync(req);
        var raw = await resp.Content.ReadAsStringAsync();
        return (raw, resp.Headers.ToDictionary(k => k.Key.ToLowerInvariant(), k => string.Join(",", k.Value)));
    }

    private async Task<ApiResult> SendAsync(HttpRequestMessage req)
    {
        using var resp = await _http.SendAsync(req);
        var raw = await resp.Content.ReadAsStringAsync();
        var headers = resp.Headers.ToDictionary(k => k.Key.ToLowerInvariant(), k => string.Join(",", k.Value));
        var result = new ApiResult { Raw = raw, RespHeaders = headers };
        var body = raw;
        if (headers.TryGetValue("ctg-rspdata-etype", out var etype) && etype == "2" && Evalue != "")
        {
            try
            {
                using var je = JsonDocument.Parse(raw);
                if (je.RootElement.TryGetProperty("edata", out var ed))
                    body = CyCrypto.AesCbcDecryptFromB64(ed.GetString()!, Evalue);
            }
            catch (Exception ex) { _log("warning", _account, "响应解密失败: " + ex.Message); }
        }
        try
        {
            using var j = JsonDocument.Parse(body);
            var root = j.RootElement;
            if (root.ValueKind == JsonValueKind.Object)
            {
                if (root.TryGetProperty("code", out var c))
                    result.Code = c.ValueKind == JsonValueKind.Number ? c.GetInt32() : int.TryParse(c.GetString(), out var cc) ? cc : -1;
                if (root.TryGetProperty("msg", out var m)) result.Msg = m.GetString() ?? "";
                if (root.TryGetProperty("data", out var d)) result.Data = d.Clone();
            }
            result.Raw = body;
        }
        catch { result.Raw = body; }
        return result;
    }

    public static bool IsAuthExpired(int code, string msg) =>
        code == 40010 || msg.Contains("登录信息已过期") || msg.Contains("会话已过期");

    // ---------- 登录（账密 + 挑战式回退） ----------
    public async Task<ApiResult> LoginAsync(string account, string password, string? captchaCode)
    {
        var form = new Dictionary<string, string>
        {
            ["userAccount"] = account,
            ["password"] = CyCrypto.Md5Hex(password),
            ["sha256Password"] = CyCrypto.Sha256Hex(password),
            ["deviceCode"] = "web",
            ["deviceName"] = Environment.MachineName,
            ["deviceType"] = "60",
            ["deviceModel"] = "Windows NT 10.0; Win64; x64",
            ["appVersion"] = "4.0.1",
            ["sysVersion"] = "Windows NT 10.0; Win64; x64",
            ["clientVersion"] = Version,
        };
        if (!string.IsNullOrEmpty(captchaCode)) form["captchaCode"] = captchaCode;

        var r = await ApiAsync("POST", "api/auth/client/login", form: form);
        if (r.Code != 0 && (r.Code is 40010 or 40123 || r.Msg.Contains("挑战")))
        {
            _log("info", _account, "触发挑战式登录，二次提交...");
            var ch = await ApiAsync("POST", "api/auth/client/genChallengeData", "{}");
            if (ch.Code == 0 && ch.Data.ValueKind == JsonValueKind.Object)
            {
                var cid = ch.Data.TryGetProperty("challengeId", out var ci) ? ci.GetString() : null;
                var code = ch.Data.TryGetProperty("challengeCode", out var cc) ? cc.GetString() : null;
                form["challengeId"] = cid ?? "";
                form["password"] = CyCrypto.Sha256Hex(password + code);
                form["sha256Password"] = CyCrypto.Sha256Hex(CyCrypto.Sha256Hex(password) + code);
                r = await ApiAsync("POST", "api/auth/client/login", form: form);
            }
        }
        if (r.Code == 0 && r.Data.ValueKind == JsonValueKind.Object) MarkLogin(r.Data);
        else _log("warning", _account, $"登录失败 code={r.Code} msg={r.Msg}");
        return r;
    }

    private void MarkLogin(JsonElement data)
    {
        Profile = data.Clone();
        NeedsCaptcha = false;   // 登录成功即解除风控标记
        UserId = GetLong(data, "userId");
        TenantId = GetLong(data, "tenantId");
        SecretKey = GetStr(data, "secretKey");
        UserName = GetStr(data, "userName");
        AccessToken = GetStr(data, "accessToken");
        LoggedIn = true;
        var srvTs = GetLong(data, "timestamp");
        if (srvTs > 0) _offsetTime = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - srvTs;
        var t = GetStr(data, "token");
        if (t != "") AccessToken = t;
        _log("info", _account, $"登录成功 userId={UserId} userName={UserName}");
    }

    // ---------- 会话导入/导出（重启免登录） ----------
    public string ExportSession()
    {
        var cookies = Cookies.GetCookies(new Uri(ApiBase)).Select(c => $"{c.Name}={c.Value};{c.Domain};{c.Path}").ToArray();
        var obj = new System.Text.Json.Nodes.JsonObject
        {
            ["userId"] = UserId, ["tenantId"] = TenantId, ["secretKey"] = SecretKey,
            ["userName"] = UserName, ["accessToken"] = AccessToken,
            ["profile"] = Profile.ValueKind == JsonValueKind.Undefined ? "" : Profile.GetRawText(),
            ["eid"] = Eid, ["evalue"] = Evalue, ["offsetTime"] = _offsetTime,
            ["cookies"] = new System.Text.Json.Nodes.JsonArray(cookies.Select(c => System.Text.Json.Nodes.JsonValue.Create(c)).ToArray()),
        };
        return System.Text.Json.JsonSerializer.Serialize(obj, AppJson.Default.JsonObject);
    }

    public bool ImportSession(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var j = doc.RootElement;
            UserId = GetLong(j, "userId");
            TenantId = GetLong(j, "tenantId");
            SecretKey = GetStr(j, "secretKey");
            UserName = GetStr(j, "userName");
            AccessToken = GetStr(j, "accessToken");
            var profile = GetStr(j, "profile");
            Profile = profile != "" ? JsonDocument.Parse(profile).RootElement.Clone() : default;
            Eid = GetStr(j, "eid");
            Evalue = GetStr(j, "evalue");
            _offsetTime = GetLong(j, "offsetTime");
            if (j.TryGetProperty("cookies", out var cs) && cs.ValueKind == JsonValueKind.Array)
                foreach (var c in cs.EnumerateArray())
                {
                    var parts = c.GetString()!.Split(';');
                    var sep = parts[0].IndexOf('=');
                    if (parts.Length == 3 && sep > 0)
                        Cookies.Add(new Cookie(parts[0][..sep], parts[0][(sep + 1)..]) { Domain = parts[1], Path = parts[2] });
                }
            LoggedIn = UserId != 0 && SecretKey != "";
            return LoggedIn;
        }
        catch { return false; }
    }

    // ---------- 图形验证码 ----------
    private static readonly HttpClient CaptchaHttp = new() { Timeout = TimeSpan.FromSeconds(20) };

    public async Task<(byte[] Image, string Key)> GetCaptchaAsync()
    {
        // ⚠️ 官方验证码接口必须【全新裸请求】：不带 CTG-* 头、不带 negotiate 协商 Cookie。
        // 真机实证（OVH）：裸 GET = 200 image/jpeg；带协商会话 Cookie = 30010 JSON 错误（假"验证码"）。
        // deskapp/Node 版成功同理（fetch 天然无 Cookie）。
        using var req = new HttpRequestMessage(HttpMethod.Get,
            $"{ApiBase}/api/auth/client/captcha?height=80&width=200&userInfo={Uri.EscapeDataString(_account)}&mode=auto&_t={DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}");
        req.Headers.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36");
        using var resp = await CaptchaHttp.SendAsync(req);
        var bytes = await resp.Content.ReadAsByteArrayAsync();
        var key = resp.Headers.TryGetValues("ctg-captcha-key", out var v) ? string.Join("", v) : "";
        _captchaKey = key;
        // 健壮性：图片响应必以 JPEG/PNG 魔数开头，否则把服务端错误文本抛给上层
        if (bytes.Length >= 2 && ((bytes[0] == 0xFF && bytes[1] == 0xD8) || (bytes[0] == 0x89 && bytes[1] == 0x50)))
            return (bytes, key);
        throw new Exception("验证码接口返回非图片: " + Encoding.UTF8.GetString(bytes, 0, Math.Min(120, bytes.Length)));
    }

    // ---------- 官方扫码登录 ----------
    public async Task<(string QrCodeId, string QrUrl)> GenQrCodeAsync()
    {
        var r = await ApiAsync("POST", "api/auth/client/qrCode/genData", form: []);
        if (r.Code != 0 || r.Data.ValueKind != JsonValueKind.Object) throw new Exception(r.Msg + "|获取二维码失败");
        var qrCodeId = r.Data.GetProperty("qrCodeId").GetString()!;
        var qrUrl = r.Data.TryGetProperty("qrCodeEndpoint", out var ep) && ep.ValueKind == JsonValueKind.String
            ? ep.GetString() + (ep.GetString()!.Contains('?') ? "&" : "?") + "qrCodeId=" + Uri.EscapeDataString(qrCodeId) + "&loginMode=1"
            : "https://desk.ctyun.cn/selforder/#/login-confirm?qrCodeId=" + Uri.EscapeDataString(qrCodeId) + "&loginMode=1";
        return (qrCodeId, qrUrl);
    }

    public async Task<(int CodeStatus, string? LoginToken)> GetQrStatusAsync(string qrCodeId)
    {
        var r = await ApiAsync("GET", "api/auth/client/qrCode/getStatus?qrCodeId=" + Uri.EscapeDataString(qrCodeId));
        if (r.Code != 0 || r.Data.ValueKind != JsonValueKind.Object) throw new Exception(r.Msg + "|查询扫码状态失败");
        return (
            r.Data.TryGetProperty("codeStatus", out var s) && s.ValueKind == JsonValueKind.Number ? s.GetInt32() : 0,
            r.Data.TryGetProperty("loginToken", out var t) && t.ValueKind == JsonValueKind.String ? t.GetString() : null);
    }

    public async Task<ApiResult> TokenLoginAsync(string accessToken)
    {
        var obj = new System.Text.Json.Nodes.JsonObject
        {
            ["accessToken"] = accessToken, ["osType"] = "Windows",
            ["deviceModel"] = "Windows NT 10.0; Win64; x64", ["appVersion"] = "3.2.0",
            ["deviceCode"] = "web", ["deviceName"] = "Chrome浏览器", ["deviceType"] = "60",
            ["sysVersion"] = "Windows NT 10.0; Win64; x64", ["clientVersion"] = Version,
        };
        var body = System.Text.Json.JsonSerializer.Serialize(obj, AppJson.Default.JsonObject);
        var r = await ApiAsync("POST", "api/auth/client/tokenLogin", jsonBody: body);
        if (r.Code == 0 && r.Data.ValueKind == JsonValueKind.Object) MarkLogin(r.Data);
        return r;
    }

    /// <summary>用当前会话签发免密登录票据（对齐 server.js genLoginToken，5 秒间隔重试一次）。</summary>
    public async Task<string> GenLoginTokenAsync(int effectiveSeconds = 300)
    {
        string lastErr = "";
        for (var attempt = 1; attempt <= 2; attempt++)
        {
            var r = await ApiAsync("POST", "api/auth/client/genLoginToken",
                jsonBody: "{\"authAppModel\":34,\"effectiveSeconds\":" + effectiveSeconds + "}");
            if (r.Code == 0 && r.Data.ValueKind == JsonValueKind.Object && r.Data.TryGetProperty("token", out var t))
                return t.GetString()!;
            lastErr = (r.Msg.Length > 0 ? r.Msg : "获取免密 Token 失败") + " (Code: " + r.Code + ")";
            if (attempt < 2) await Task.Delay(5000);
        }
        throw new Exception(lastErr);
    }

    /// <summary>无感续期：当前会话签发免密票据 → tokenLogin 换全新会话（对齐 server.js renewToken）。</summary>
    public async Task RenewAsync()
    {
        if (!LoggedIn) throw new Exception("账号尚未登录，无法续期");
        var loginToken = await GenLoginTokenAsync(300);
        var lr = await TokenLoginAsync(loginToken);
        if (lr.Code != 0 || !LoggedIn)
            throw new Exception("消费免密凭据被拒: " + lr.Code + " " + lr.Msg);
    }

    // ---------- CAS 票据（AI 对话 SSO 用） ----------
    public async Task<ApiResult> GetCasTicketAsync(string service)
    {
        return await ApiAsync("GET", "api/auth/client/getTicket?service=" + Uri.EscapeDataString(service));
    }

    // ---------- 短信设备绑定 ----------
    public async Task<(byte[] Image, string Key)> GetSmsCaptchaAsync()
    {
        using var req = new HttpRequestMessage(HttpMethod.Get,
            $"{ApiBase}/api/auth/client/validateCode/captcha?width=120&height=40&_t={DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}");
        CopySignedHeaders(req);
        using var resp = await _http.SendAsync(req);
        var bytes = await resp.Content.ReadAsByteArrayAsync();
        var key = resp.Headers.TryGetValues("ctg-captcha-key", out var v) ? string.Join("", v) : "";
        return (bytes, key);
    }

    public async Task<ApiResult> SendSmsCodeAsync(string phone, string captchaCode, string captchaKey)
    {
        var url = $"api/cdserv/client/device/getSmsCode?mobilePhone={Uri.EscapeDataString(phone)}&captchaCode={Uri.EscapeDataString(captchaCode)}";
        if (captchaKey != "") url += "&captchaCodeKey=" + Uri.EscapeDataString(captchaKey);
        return await ApiAsync("GET", url);
    }

    public async Task<ApiResult> BindDeviceAsync(string verificationCode, string smsCodeKey)
    {
        var form = new Dictionary<string, string>
        {
            ["verificationCode"] = verificationCode.Trim(), ["smsCodeKey"] = smsCodeKey.Trim(),
            ["deviceName"] = "Chrome浏览器", ["deviceCode"] = "web",
            ["deviceModel"] = "Windows NT 10.0; Win64; x64", ["sysVersion"] = "Windows NT 10.0; Win64; x64",
            ["appVersion"] = "3.2.0", ["hostName"] = "pc.ctyun.cn", ["deviceInfo"] = "Win32",
        };
        return await ApiAsync("POST", "api/cdserv/client/device/binding", form: form);
    }

    // ---------- 桌面 ----------
    public sealed record DesktopBrief(string Id, string Name, int UseStatus, string UseStatusText, string Spec, string RawJson);

    private static void CollectDesks(JsonElement data, Dictionary<string, DesktopBrief> merged)
    {
        void CollectItem(JsonElement it, string fallbackName)
        {
            var id = GetStr(it, "desktopId");
            if (id == "") id = GetStr(it, "objId");
            if (id == "") id = GetStr(it, "poolId");
            if (id == "") return;
            var name = GetStr(it, "desktopName");
            if (name == "") name = GetStr(it, "objName");
            if (name == "") name = GetStr(it, "poolName");
            if (name == "") name = fallbackName;
            var statusText = GetStr(it, "useStatusText");
            if (statusText == "") statusText = GetStr(it, "useStatus");
            if (statusText == "") statusText = "运行中";
            var useStatus = GetLong(it, "useStatus");
            var spec = GetStr(it, "flavorName");
            if (spec == "") spec = GetStr(it, "specStr");
            if (spec == "")
            {
                var cpu = GetLong(it, "cpu"); var mem = GetLong(it, "memory");
                if (cpu > 0) spec = cpu + "核" + mem + "G";
            }
            merged[id] = new DesktopBrief(id, name, (int)useStatus, statusText, spec, it.GetRawText());
        }

        switch (data.ValueKind)
        {
            case JsonValueKind.Array:
                foreach (var it in data.EnumerateArray()) CollectItem(it, "天翼云电脑");
                break;
            case JsonValueKind.Object:
                foreach (var section in new[] { "desktopList", "desktopPoolList", "preemptionDesktopList", "list" })
                {
                    if (data.TryGetProperty(section, out var arr) && arr.ValueKind == JsonValueKind.Array)
                        foreach (var it in arr.EnumerateArray()) CollectItem(it, "天翼云电脑");
                }
                break;
        }
    }

    /// <summary>pageDesktop（指定品类）+ client/list（全品类兜底，含 AI 云电脑）合并去重。</summary>
    public async Task<List<DesktopBrief>> GetAllDesktopsAsync()
    {
        var merged = new Dictionary<string, DesktopBrief>();

        var page = await ApiAsync("POST", "api/desktop/client/pageDesktop",
            jsonBody: "{\"getCnt\":50,\"desktopTypes\":[\"1\",\"2001\",\"2002\",\"2003\"],\"sortType\":\"createTimeV1\"}");
        if (page.Code == 0) CollectDesks(page.Data, merged);

        var all = await ApiAsync("GET", "api/desktop/client/list");
        if (all.Code == 0) CollectDesks(all.Data, merged);

        return [.. merged.Values];
    }

    public async Task<(JsonElement DesktopInfo, string Raw)> GetConnectInfoAsync(string desktopId)
    {
        var st = await ApiAsync("GET", $"api/desktop/client/status?desktopId={Uri.EscapeDataString(desktopId)}&specifiedCertCategory=1");
        if (st.Code == 0 && st.Data.ValueKind == JsonValueKind.Object && st.Data.TryGetProperty("desktopInfo", out var di))
            return (di.Clone(), st.Raw);
        var form = new Dictionary<string, string>
        {
            ["objId"] = desktopId, ["objType"] = "0", ["osType"] = "15", ["deviceId"] = "60",
            ["deviceCode"] = "web", ["deviceName"] = "Chrome浏览器", ["deviceType"] = "60",
            ["deviceModel"] = "Windows NT 10.0; Win64; x64", ["desktopId"] = desktopId,
            ["appVersion"] = "3.2.0", ["sysVersion"] = "Windows NT 10.0; Win64; x64",
            ["clientVersion"] = Version, ["specifiedCertCategory"] = "1", ["vdCommand"] = "",
            ["ipAddress"] = "", ["macAddress"] = "",
        };
        var conn = await ApiAsync("POST", "api/desktop/client/connect", form: form);
        if (conn.Code == 0)
        {
            if (conn.Data.ValueKind == JsonValueKind.Object && conn.Data.TryGetProperty("desktopInfo", out var d2))
                return (d2.Clone(), conn.Raw);
            return (default, conn.Raw);  // 关机中 goingRetry
        }
        throw new Exception("获取连接配置失败: " + conn.Code + " " + conn.Msg);
    }

    public async Task<ApiResult> OperateAsync(string desktopId, int operationType)
    {
        var form = new Dictionary<string, string> { ["desktopId"] = desktopId, ["operationType"] = operationType.ToString() };
        return await ApiAsync("POST", "api/desktop/client/operate", form: form);
    }

    public async Task<ApiResult> QuitConnectAsync(string desktopId)
    {
        var form = new Dictionary<string, string>
        {
            ["objId"] = desktopId, ["objType"] = "0", ["osType"] = "15", ["deviceId"] = "60",
            ["deviceCode"] = "web", ["deviceName"] = "Chrome浏览器", ["hostName"] = "pc.ctyun.cn",
            ["appVersion"] = "3.2.0", ["sysVersion"] = "Windows NT 10.0; Win64; x64", ["clientVersion"] = Version,
        };
        return await ApiAsync("POST", "api/desktop/client/quitConnect", form: form);
    }

    // ---------- 任务中心 / 积分 / 兑换 ----------
    public async Task<ApiResult> GetTaskListAsync() => await ApiAsync("GET", "selforder/api/marketing/userPoints/getTaskList");

    public async Task<ApiResult> GetUserPointsAsync() => await ApiAsync("GET", "selforder/api/marketing/userPoints/getUserPoints");

    public async Task<ApiResult> GetRewardsAsync() =>
        await ApiAsync("GET", "selforder/api/selforder/prod/get?prodId=17000000&prodCode=POINTS");

    public async Task<ApiResult> PlaceOrderAsync(string orderJson) =>
        await ApiAsync("POST", "selforder/api/selforder/paas/placeOrder", jsonBody: orderJson);

    // ---------- 工具 ----------
    private void CopyPlainHeaders(HttpRequestMessage req)
    {
        req.Headers.Add("Origin", Origin);
        req.Headers.Add("CTG-DEVICECODE", "web");
        req.Headers.Add("CTG-DEVICETYPE", "60");
        req.Headers.Add("CTG-REQUESTID", (DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + ++_seq).ToString());
        req.Headers.Add("CTG-TIMESTAMP", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString());
        req.Headers.Add("CTG-VERSION", Version);
        req.Headers.Add("CTG-APPMODEL", "2");
    }

    private void CopySignedHeaders(HttpRequestMessage req)
    {
        CopyPlainHeaders(req);
        if (!LoggedIn) return;
        var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var requestId = nowMs + ++_seq;
        var timestamp = nowMs - _offsetTime;
        req.Headers.TryAddWithoutValidation("CTG-TENANTID", TenantId.ToString());
        req.Headers.TryAddWithoutValidation("CTG-USERID", UserId.ToString());
        req.Headers.TryAddWithoutValidation("CTG-SIGNATURESTR", CyCrypto.Md5Hex($"60{requestId}{TenantId}{timestamp}{UserId}{Version}{SecretKey}"));
    }

    internal static string GetStr(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString()! : "";

    internal static long GetLong(JsonElement e, string name)
    {
        if (e.ValueKind != JsonValueKind.Object || !e.TryGetProperty(name, out var v)) return 0;
        return v.ValueKind switch
        {
            JsonValueKind.Number => v.TryGetInt64(out var l) ? l : 0,
            JsonValueKind.String => long.TryParse(v.GetString(), out var l) ? l : 0,
            _ => 0,
        };
    }

    public void Dispose()
    {
        _http.Dispose();
        _handler.Dispose();
        _rsa?.Dispose();
    }
}
