// =============================================================================
// CtyunDashboard.Ecloud / EcloudClient.cs
// =============================================================================
// 对齐参考实现（Python，只读）：app/ecloud_engine/
//   ecloud_client.py                          → 本文件
//   ────────────────────────────────────────────────────────────────────────
//   rsa_encrypt()/rsa_decrypt()（PKCS1 v1.5，117/128 分块，base64）
//                                             → EcloudCrypto.RsaEncrypt/RsaDecrypt
//   _sha256_hex()/_hmac_sha1_hex()             → EcloudCrypto.Sha256Hex/HmacSha1Hex
//   _build_signed_url()（getFullurl 同源：UTC+8 时间戳 + uuid4hex nonce +
//                        canonical=AccessKey&SignatureMethod&SignatureNonce&
//                        SignatureVersion&Timestamp + "POST\n<path>\n" + sha256(canonical)
//                        → HmacSHA1("BC_SIGNATURE&"+secret)）
//                                             → EcloudHttpUtil.BuildSignedUrl
//   EcloudError（errorCode/errorMessage/resp）  → EcloudException
//   EcloudHttpUtil.post/_handle_response        → PostAsync（params 解密 + state/errorMessage
//                        校验 + body 提取 + LOGIN_GET_TOKEN 自动存 accessToken）
//   post_with_failover()（LOGIN_PATHS 走 BACKUP_DOMAINS）→ PostWithFailoverAsync
//   set_token()（拒收空值/坏值，保留旧 token）  → SetToken
//   login.py                                   → 本文件 LoginXxx 系列
//   ────────────────────────────────────────────────────────────────────────
//   login_with_password()（/login/verify + NEED_* 三分支分类 + verifyAccessTicket）
//                                             → LoginWithPasswordAsync
//   send_sms()/send_two_factor_sms()           → SendSmsForBranchAsync（sidecar 三路分发）
//   verify_sms()/complete_device_trust()/complete_two_factor()/complete_enhanced_sms()
//   /_finish_after_ticket()                    → CompleteSmsBranchAsync
//   normalize_sms_code()（全角数字归一）        → NormalizeSmsCode
//   _extract_error()                           → ExtractError
//   logout()/get_user_info()                   → LogoutAsync/GetUserInfoAsync
//   login_rate_limit.py（10 分钟 3 次/用户，滑动窗）→ EcloudLoginRateLimiter（内存版；
//                                             Python 落盘 data/，此处进程内存即可，
//                                             见交付报告「简化项」）
//
// AOT：JSON 全部 JsonObject/JsonDocument；RSA 用 System.Security.Cryptography
//      RSA.ImportFromPem + RSAEncryptionPadding.Pkcs1；HMAC 用 HMACSHA1。
// =============================================================================

using System.Collections.Concurrent;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace CtyunDashboard.Ecloud;

/// <summary>服务端返回 state != OK / errorMessage / HTTP 非 200（对齐 ecloud_client.EcloudError）。</summary>
public sealed class EcloudException : Exception
{
    public string Code { get; }
    public string ServerMessage { get; }
    public JsonObject? Raw { get; }

    public EcloudException(string code, string message, JsonObject? raw = null) : base($"[{code}] {message}")
    {
        Code = code;
        ServerMessage = message;
        Raw = raw;
    }
}

// -----------------------------------------------------------------------------
// RSA / 摘要工具（ecloud_client.py 顶层函数）
// -----------------------------------------------------------------------------
public static class EcloudCrypto
{
    private static readonly object Gate = new();
    private static RSA? _pub;
    private static RSA? _priv;

    private static RSA PublicKey()
    {
        if (_pub != null) return _pub;
        lock (Gate)
        {
            if (_pub == null)
            {
                var rsa = RSA.Create();
                rsa.ImportFromPem(EcloudCredentials.Load().RsaPublicPem);
                _pub = rsa;
            }
            return _pub;
        }
    }

    private static RSA PrivateKey()
    {
        if (_priv != null) return _priv;
        lock (Gate)
        {
            if (_priv == null)
            {
                var rsa = RSA.Create();
                rsa.ImportFromPem(EcloudCredentials.Load().RsaPrivatePem);
                _priv = rsa;
            }
            return _priv;
        }
    }

    /// <summary>RSA-1024 PKCS1 v1.5 分块加密（117B/块）→ base64（对齐 rsa_encrypt）。</summary>
    public static string RsaEncrypt(string plaintext)
    {
        byte[] data = Encoding.UTF8.GetBytes(plaintext);
        var pub = PublicKey();
        using var ms = new MemoryStream();
        for (int i = 0; i < data.Length; i += EcloudConfig.RsaEncryptChunk)
        {
            int len = Math.Min(EcloudConfig.RsaEncryptChunk, data.Length - i);
            byte[] enc = pub.Encrypt(data.AsSpan(i, len).ToArray(), RSAEncryptionPadding.Pkcs1);
            ms.Write(enc);
        }
        return Convert.ToBase64String(ms.ToArray());
    }

    /// <summary>RSA-1024 PKCS1 v1.5 分块解密（128B/块）→ UTF-8（对齐 rsa_decrypt；坏块按空处理）。</summary>
    public static string RsaDecrypt(string ciphertextB64)
    {
        byte[] ct = Convert.FromBase64String(ciphertextB64);
        var priv = PrivateKey();
        using var ms = new MemoryStream();
        for (int i = 0; i < ct.Length; i += EcloudConfig.RsaDecryptChunk)
        {
            int len = Math.Min(EcloudConfig.RsaDecryptChunk, ct.Length - i);
            try
            {
                byte[] dec = priv.Decrypt(ct.AsSpan(i, len).ToArray(), RSAEncryptionPadding.Pkcs1);
                ms.Write(dec);
            }
            catch
            {
                // 对齐 PKCS1_v1_5.decrypt(block, b"")：解密失败该块按空处理
            }
        }
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    public static string Sha256Hex(string s)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(s));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    public static string HmacSha1Hex(string data, string key)
    {
        using var hmac = new HMACSHA1(Encoding.UTF8.GetBytes(key));
        byte[] hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    public static string Md5Hex(string s)
    {
        byte[] hash = MD5.HashData(Encoding.UTF8.GetBytes(s));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}

// -----------------------------------------------------------------------------
// HTTP 客户端（ecloud_client.EcloudHttpUtil）
// -----------------------------------------------------------------------------
public sealed class EcloudHttpUtil : IDisposable
{
    private readonly HttpClient _http;
    private readonly HttpClientHandler _handler;
    public JsonObject CommonParams { get; }
    public string? AccessToken { get; private set; }

    /// <summary>trust_env 默认关闭（Clash/VPN MITM 会打崩 cloudpc TLS；ECLOUD_TRUST_ENV=1 才启用系统代理）。</summary>
    public EcloudHttpUtil(JsonObject commonParams)
    {
        CommonParams = commonParams;
        bool trustEnv = string.Equals(Environment.GetEnvironmentVariable("ECLOUD_TRUST_ENV")?.Trim().ToLowerInvariant(), "1")
            || string.Equals(Environment.GetEnvironmentVariable("ECLOUD_TRUST_ENV")?.Trim().ToLowerInvariant(), "true");
        _handler = new HttpClientHandler
        {
            UseCookies = false,
            AutomaticDecompression = System.Net.DecompressionMethods.GZip | System.Net.DecompressionMethods.Deflate,
            Proxy = trustEnv ? System.Net.WebRequest.DefaultWebProxy : null,
            UseProxy = trustEnv,
        };
        _http = new HttpClient(_handler) { Timeout = TimeSpan.FromSeconds(EcloudConfig.ApiTimeoutSec + 10) };
        _http.DefaultRequestHeaders.TryAddWithoutValidation("Content-Type", "application/json");
        _http.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", EcloudConfig.UserAgent);
    }

    /// <summary>对齐 set_token：拒收空值/坏值，保留旧 token（历史缺陷：曾把 True 存成 token）。</summary>
    public void SetToken(string? token)
    {
        if (!string.IsNullOrWhiteSpace(token))
            AccessToken = token.Trim();
    }

    public void ClearToken() => AccessToken = null;

    /// <summary>构造带 HmacSHA1 签名的完整 URL（对齐 _build_signed_url / JS getFullurl 189-204）。</summary>
    public static string BuildSignedUrl(string endpoint)
    {
        // 时间戳：UTC+8 墙钟，格式 YYYY-MM-DDTHH:MM:SSZ（源码 now+8h 后取前 19 位 + 'Z'）
        string timestamp = DateTimeOffset.UtcNow
            .ToOffset(TimeSpan.FromHours(8))
            .ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);

        // querystring.stringify 插入顺序：AccessKey, SignatureMethod, SignatureNonce, SignatureVersion, Timestamp
        string nonce = Guid.NewGuid().ToString("N"); // uuid4 hex（去 '-'）
        string canonical =
            "AccessKey=" + Uri.EscapeDataString(EcloudCredentials.Load().AccessKey) +
            "&SignatureMethod=" + Uri.EscapeDataString(EcloudConfig.SignMethod) +
            "&SignatureNonce=" + Uri.EscapeDataString(nonce) +
            "&SignatureVersion=" + Uri.EscapeDataString(EcloudConfig.SignVersion) +
            "&Timestamp=" + Uri.EscapeDataString(timestamp);

        // stringToSign = "POST\n" + encodeURIComponent(apiPath + endpoint) + "\n" + sha256(canonical)
        string encodedPath = Uri.EscapeDataString(EcloudConfig.ApiPath + endpoint);
        string stringToSign = "POST\n" + encodedPath + "\n" + EcloudCrypto.Sha256Hex(canonical);
        string signature = EcloudCrypto.HmacSha1Hex(stringToSign, EcloudConfig.HmacKeyPrefix + EcloudCredentials.Load().SecretKey);

        return EcloudConfig.BaseUrl + EcloudConfig.ApiPath + endpoint + "?" + canonical + "&Signature=" + signature;
    }

    private static string Serialize(JsonObject o) => JsonSerializer.Serialize(o, AppJson.Default.JsonObject);

    /// <summary>发起已签名 POST 并返回解密后的 body（对齐 EcloudHttpUtil.post）。</summary>
    public async Task<JsonObject> PostAsync(string endpoint, JsonObject? payload = null, string? baseUrl = null, CancellationToken ct = default)
    {
        payload ??= new JsonObject();

        // 合并 body（ecloudHttpUtil.js:127-133）：{**payload, **common_params} + accessToken
        var merged = new JsonObject();
        foreach (var p in payload)
            merged[p.Key] = p.Value?.DeepClone();
        foreach (var p in CommonParams)
            merged[p.Key] = p.Value?.DeepClone();
        if (!string.IsNullOrEmpty(AccessToken))
            merged["accessToken"] = AccessToken;

        string encrypted = EcloudCrypto.RsaEncrypt(Serialize(merged));
        string httpBody = "{\"params\":\"" + encrypted + "\"}";

        string url = BuildSignedUrl(endpoint);
        if (!string.IsNullOrEmpty(baseUrl) && baseUrl != EcloudConfig.BaseUrl)
            url = url.Replace(EcloudConfig.BaseUrl, baseUrl, StringComparison.Ordinal);

        int timeoutSec = EcloudConfig.IsLoginPath(endpoint) ? EcloudConfig.LoginTimeoutSec : EcloudConfig.ApiTimeoutSec;
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(TimeSpan.FromSeconds(timeoutSec));

        using var req = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = new StringContent(httpBody, Encoding.UTF8, "application/json"),
        };
        using var resp = await _http.SendAsync(req, timeoutCts.Token).ConfigureAwait(false);
        string raw = await resp.Content.ReadAsStringAsync(timeoutCts.Token).ConfigureAwait(false);
        return HandleResponse(raw, (int)resp.StatusCode, endpoint);
    }

    /// <summary>登录类接口：主域名失败按 BACKUP_DOMAINS 重试（对齐 post_with_failover）。</summary>
    public async Task<JsonObject> PostWithFailoverAsync(string endpoint, JsonObject? payload = null, CancellationToken ct = default)
    {
        try
        {
            return await PostAsync(endpoint, payload, EcloudConfig.BaseUrl, ct).ConfigureAwait(false);
        }
        catch (Exception) when (EcloudConfig.IsLoginPath(endpoint))
        {
            Exception last = new EcloudException("FAILOVER", "全部域名均不可达");
            foreach (string backup in EcloudConfig.BackupDomains)
            {
                try
                {
                    return await PostAsync(endpoint, payload, backup, ct).ConfigureAwait(false);
                }
                catch (Exception e2)
                {
                    last = e2;
                }
            }
            throw last;
        }
    }

    /// <summary>响应处理（对齐 _handle_response / handleHttpOrOpError + handleServerError）。</summary>
    private JsonObject HandleResponse(string raw, int statusCode, string endpoint)
    {
        if (statusCode != 200 || raw.Length == 0)
            throw new EcloudException(statusCode.ToString(), $"HTTP {statusCode}: {Truncate(raw, 200)}");
        JsonObject envelope;
        try
        {
            envelope = JsonNode.Parse(raw) as JsonObject
                ?? throw new EcloudException("PARSE_ERROR", $"非 JSON 响应: {Truncate(raw, 200)}");
        }
        catch (JsonException)
        {
            throw new EcloudException("PARSE_ERROR", $"非 JSON 响应: {Truncate(raw, 200)}");
        }
        if (envelope["params"] is not JsonValue || envelope["params"]!.GetValueKind() != JsonValueKind.String)
            throw ToEcloudException(envelope);

        string plain = EcloudCrypto.RsaDecrypt(envelope["params"]!.GetValue<string>());
        JsonObject obj;
        try
        {
            obj = JsonNode.Parse(plain) as JsonObject
                ?? throw new EcloudException("PARSE_ERROR", $"解密后非 JSON: {Truncate(plain, 200)}");
        }
        catch (JsonException)
        {
            throw new EcloudException("PARSE_ERROR", $"解密后非 JSON: {Truncate(plain, 200)}");
        }

        // state 校验（ecloudHttpUtil.js:233）+ errorMessage 检查（Python 真值语义：空串不算错误）
        string? state = obj["state"] is JsonValue sv && sv.TryGetValue<string>(out var s2) ? s2 : null;
        if (!string.IsNullOrEmpty(state) && state != "OK")
            throw ToEcloudException(obj);
        if (obj["errorMessage"] is JsonNode errNode && errNode.GetValueKind() == JsonValueKind.String)
        {
            var msgText = errNode is JsonValue ev2 && ev2.TryGetValue<string>(out var es) ? es : "";
            if (msgText != "")
                throw ToEcloudException(obj);
        }

        // body 提取：obj["body"] ?? obj
        var body = obj["body"] as JsonObject ?? obj;

        // 登录换 token 接口：自动保存 accessToken（ecloudHttpUtil.js:163）
        if (endpoint == EcloudConfig.Endpoints.LoginGetToken)
        {
            var token = body["accessToken"] is JsonValue tv && tv.TryGetValue<string>(out var tok) ? tok : null;
            if (!string.IsNullOrEmpty(token)) SetToken(token);
        }
        return body;
    }

    private static EcloudException ToEcloudException(JsonObject resp)
    {
        string code = resp["errorCode"] is JsonValue cv && cv.TryGetValue<string>(out var c) ? c : "";
        string msg = resp["errorMessage"] is JsonValue mv && mv.TryGetValue<string>(out var m) ? m : resp.ToJsonString();
        return new EcloudException(code, msg, resp);
    }

    private static string Truncate(string s, int limit) => s.Length <= limit ? s : s[..limit] + "...";

    public void Dispose()
    {
        _http.Dispose();
        _handler.Dispose();
    }
}

// -----------------------------------------------------------------------------
// 登录（login.py 1:1 移植）
// -----------------------------------------------------------------------------

/// <summary>登录分支常量（login.LoginResult）。</summary>
public static class EcloudLoginStatus
{
    public const string Success = "success";
    public const string NeedDeviceTrust = "need_device_trust";   // 30002009
    public const string NeedTwoFactor = "need_two_factor";       // 30002060
    public const string NeedEnhancedSms = "need_enhanced_sms";   // 30002063
    public const string Need4A = "need_4a";
    public const string Failed = "failed";
    public const string Locked = "locked";

    public static bool IsInteractive(string? status) => status is
        NeedDeviceTrust or NeedTwoFactor or NeedEnhancedSms or Need4A;
}

/// <summary>一次登录尝试的结构化结果（对齐 login_with_password 返回 dict）。</summary>
public sealed record EcloudLoginResult(
    string Status,
    string AccessToken = "",
    string Mobile = "",
    string? LoginCode = null,
    string ErrorCode = "",
    string Error = "",
    string? UserId = null);

public static class EcloudLogin
{
    /// <summary>密码登录（login_with_password）：成功 → accessTicket → verifyAccessTicket 换 token。</summary>
    public static async Task<EcloudLoginResult> LoginWithPasswordAsync(EcloudHttpUtil http, string username, string password, CancellationToken ct = default)
    {
        JsonObject resp;
        try
        {
            resp = await http.PostWithFailoverAsync(EcloudConfig.Endpoints.LoginCheckUserPassword, new JsonObject
            {
                ["username"] = username,
                ["password"] = password,
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["clientNeedTwoFactor"] = true,
            }, ct).ConfigureAwait(false);
        }
        catch (EcloudException e)
        {
            // 业务错误（未授信设备/二次验证等）—— errorCode 在异常里，按分支分类
            return ClassifyError(e, e.Raw);
        }

        // 直接拿到 accessTicket（已授信设备 + 无需二次验证）
        var ticket = resp["accessTicket"] is JsonValue tv && tv.TryGetValue<string>(out var t) ? t : null;
        if (!string.IsNullOrEmpty(ticket))
        {
            string? token = await ExchangeTicketAsync(http, ticket, ct).ConfigureAwait(false);
            return new EcloudLoginResult(EcloudLoginStatus.Success, AccessToken: token ?? "");
        }

        // 没 ticket 也没异常：按 errorCode 分类；两者皆无 → FAILED（绝不假装成功）
        var errCode = resp["errorCode"] is JsonValue ev && ev.TryGetValue<string>(out var ec) ? ec : "";
        if (errCode != "")
            return ClassifyDictError(resp);
        return new EcloudLoginResult(EcloudLoginStatus.Failed, Error: "登录响应缺少 accessTicket/accessToken");
    }

    /// <summary>EcloudError → 分支状态（对齐 _classify_login_error）。</summary>
    private static EcloudLoginResult ClassifyError(EcloudException e, JsonObject? resp)
    {
        resp ??= new JsonObject();
        var (mobile, loginCode) = ExtractBodyFields(resp);
        string code = e.Code;
        var common = new { mobile, loginCode };

        switch (code)
        {
            case EcloudConfig.LoginError.UntrustedDevice:
                return new EcloudLoginResult(EcloudLoginStatus.NeedDeviceTrust, Mobile: mobile, LoginCode: loginCode, ErrorCode: code, Error: e.ServerMessage);
            case EcloudConfig.LoginError.TwoFactorAuth:
                return new EcloudLoginResult(EcloudLoginStatus.NeedTwoFactor, Mobile: mobile, LoginCode: loginCode, ErrorCode: code, Error: e.ServerMessage);
            case EcloudConfig.LoginError.EnhancedStrategy:
                return new EcloudLoginResult(EcloudLoginStatus.NeedEnhancedSms, Mobile: mobile, LoginCode: loginCode, ErrorCode: code, Error: e.ServerMessage);
        }
        var userId = resp["userId"] is JsonValue uv && uv.TryGetValue<string>(out var uid) ? uid : null;
        if (!string.IsNullOrEmpty(userId))
            return new EcloudLoginResult(EcloudLoginStatus.Need4A, Mobile: mobile, LoginCode: loginCode, ErrorCode: code, Error: e.ServerMessage, UserId: userId);
        return new EcloudLoginResult(EcloudLoginStatus.Failed, Mobile: mobile, LoginCode: loginCode, ErrorCode: code, Error: e.ServerMessage);
    }

    /// <summary>OK 响应里带 errorCode 的分类（对齐 _classify_dict_error）。</summary>
    private static EcloudLoginResult ClassifyDictError(JsonObject resp)
    {
        string code = resp["errorCode"] is JsonValue cv && cv.TryGetValue<string>(out var c) ? c : "";
        var (mobile, loginCode) = ExtractBodyFields(resp);
        switch (code)
        {
            case EcloudConfig.LoginError.UntrustedDevice:
                return new EcloudLoginResult(EcloudLoginStatus.NeedDeviceTrust, Mobile: mobile, LoginCode: loginCode, ErrorCode: code);
            case EcloudConfig.LoginError.TwoFactorAuth:
                return new EcloudLoginResult(EcloudLoginStatus.NeedTwoFactor, Mobile: mobile, LoginCode: loginCode, ErrorCode: code);
            case EcloudConfig.LoginError.EnhancedStrategy:
                return new EcloudLoginResult(EcloudLoginStatus.NeedEnhancedSms, Mobile: mobile, LoginCode: loginCode, ErrorCode: code);
        }
        var userId = resp["userId"] is JsonValue uv && uv.TryGetValue<string>(out var uid) ? uid : null;
        if (!string.IsNullOrEmpty(userId))
            return new EcloudLoginResult(EcloudLoginStatus.Need4A, Mobile: mobile, LoginCode: loginCode, ErrorCode: code, UserId: userId);
        var err = resp["errorMessage"] is JsonValue ev && ev.TryGetValue<string>(out var em) ? em : "";
        return new EcloudLoginResult(EcloudLoginStatus.Failed, Mobile: mobile, LoginCode: loginCode, ErrorCode: code, Error: err);
    }

    /// <summary>body.code / body.mobile 提取（body 可能是字符串化 JSON，对齐 _classify_login_error）。</summary>
    private static (string Mobile, string? LoginCode) ExtractBodyFields(JsonObject resp)
    {
        JsonObject? body = resp["body"] as JsonObject;
        if (body == null && resp["body"] is JsonValue bv && bv.TryGetValue<string>(out var bs))
        {
            try { body = JsonNode.Parse(bs) as JsonObject; } catch { /* 非对象体 */ }
        }
        if (body == null) return ("", null);
        string mobile = body["mobile"] is JsonValue mv && mv.TryGetValue<string>(out var m) ? m : "";
        string? loginCode = body["code"] is JsonValue cv && cv.TryGetValue<string>(out var c) ? c : null;
        return (mobile, loginCode);
    }

    /// <summary>accessTicket 换 accessToken（verifyAccessTicket；HttpUtil 自动存 token）。</summary>
    private static async Task<string?> ExchangeTicketAsync(EcloudHttpUtil http, string accessTicket, CancellationToken ct)
    {
        var body = await http.PostAsync(EcloudConfig.Endpoints.LoginGetToken, new JsonObject
        {
            ["accessTicket"] = accessTicket,
        }, ct: ct).ConfigureAwait(false);
        return body["accessToken"] is JsonValue v && v.TryGetValue<string>(out var t) ? t : null;
    }

    /// <summary>发短信：按登录分支三路分发（对齐 sidecar op_login_send_sms；codeType 必须与校验场景一致）。</summary>
    public static Task<JsonObject> SendSmsForBranchAsync(EcloudHttpUtil http, string branch, string mobile, string username, CancellationToken ct = default)
    {
        return branch switch
        {
            EcloudLoginStatus.NeedTwoFactor => http.PostAsync(EcloudConfig.Endpoints.LoginAuthTwoFactorGet, new JsonObject
            {
                ["mobile"] = mobile,
                ["userName"] = username,
            }, ct: ct),
            EcloudLoginStatus.NeedDeviceTrust => http.PostAsync(EcloudConfig.Endpoints.LoginSendSms, new JsonObject
            {
                ["mobile"] = mobile,
                ["codeType"] = "trust",
            }, ct: ct),
            EcloudLoginStatus.NeedEnhancedSms => http.PostAsync(EcloudConfig.Endpoints.LoginSendSms, new JsonObject
            {
                ["mobile"] = mobile,
                ["codeType"] = "login",
            }, ct: ct),
            EcloudLoginStatus.Need4A => throw new InvalidOperationException("4A 短信验证暂未实现（平台侧尚未开放），无法发码"),
            _ => throw new InvalidOperationException($"未知的短信分支: '{branch}'（应为 need_* 值）"),
        };
    }

    /// <summary>完成短信类登录分支（对齐 op_login_sms + complete_device_trust/two_factor/enhanced_sms）。</summary>
    public static async Task<EcloudLoginResult> CompleteSmsBranchAsync(
        EcloudHttpUtil http, string branch, string mobile, string username, string password,
        string verificationCode, string? loginCode, bool isTemporary, CancellationToken ct = default)
    {
        string code = NormalizeSmsCode(verificationCode);
        JsonObject resp;
        switch (branch)
        {
            case EcloudLoginStatus.NeedDeviceTrust:
            {
                // 官方 payload：code 来自密码登录 body.code，可为 null（不可因缺失硬失败）
                var payload = new JsonObject
                {
                    ["mobile"] = mobile,
                    ["verificationCode"] = code,
                    ["isNeedTemporaryDeviceSelection"] = true,
                    ["code"] = loginCode == null ? null : JsonValue.Create(loginCode),
                };
                if (username != "") payload["loginUserName"] = username;
                resp = await http.PostAsync(EcloudConfig.Endpoints.LoginTrustDevice, payload, ct: ct).ConfigureAwait(false);
                break;
            }
            case EcloudLoginStatus.NeedTwoFactor:
            {
                var payload = new JsonObject
                {
                    ["mobile"] = mobile,
                    ["userName"] = username,
                    ["verificationCode"] = code,
                    ["password"] = password,
                };
                if (!string.IsNullOrEmpty(loginCode)) payload["code"] = loginCode;
                resp = await http.PostAsync(EcloudConfig.Endpoints.LoginAuthTwoFactor, payload, ct: ct).ConfigureAwait(false);
                break;
            }
            case EcloudLoginStatus.NeedEnhancedSms:
            {
                var payload = new JsonObject
                {
                    ["mobile"] = mobile,
                    ["verificationCode"] = code,
                    ["userName"] = username,
                };
                if (!string.IsNullOrEmpty(loginCode)) payload["code"] = loginCode;
                resp = await http.PostAsync(EcloudConfig.Endpoints.LoginEnhanceSms, payload, ct: ct).ConfigureAwait(false);
                break;
            }
            case EcloudLoginStatus.Need4A:
                throw new InvalidOperationException("4A 短信验证暂未实现（平台侧尚未开放）");
            default:
                throw new InvalidOperationException($"未知的短信分支: '{branch}'（应为 need_* 值）");
        }

        var ticket = resp["accessTicket"] is JsonValue tv && tv.TryGetValue<string>(out var t) ? t : null;
        if (!string.IsNullOrEmpty(ticket))
            return await FinishAfterTicketAsync(http, ticket, isTemporary, ct).ConfigureAwait(false);

        var userId = resp["userId"] is JsonValue uv && uv.TryGetValue<string>(out var uid) ? uid : null;
        if (!string.IsNullOrEmpty(userId))
            return new EcloudLoginResult(EcloudLoginStatus.Need4A, UserId: userId);
        return new EcloudLoginResult(EcloudLoginStatus.Failed, Error: ExtractError(resp) + "（信任设备后未返回 accessTicket）");
    }

    /// <summary>trust/twoFactor 拿到 accessTicket 后：temporaryDevice → exchange token（_finish_after_ticket）。</summary>
    private static async Task<EcloudLoginResult> FinishAfterTicketAsync(EcloudHttpUtil http, string ticket, bool isTemporary, CancellationToken ct)
    {
        await http.PostAsync(EcloudConfig.Endpoints.LoginTemporaryDevice, new JsonObject
        {
            ["accessTicket"] = ticket,
            ["isTemporary"] = isTemporary ? 1 : 0,
        }, ct: ct).ConfigureAwait(false);
        string? token = await ExchangeTicketAsync(http, ticket, ct).ConfigureAwait(false);
        return new EcloudLoginResult(EcloudLoginStatus.Success, AccessToken: token ?? "");
    }

    /// <summary>登出（login.py logout）：失败吞掉，必清 token。</summary>
    public static async Task LogoutAsync(EcloudHttpUtil http, CancellationToken ct = default)
    {
        try
        {
            await http.PostAsync(EcloudConfig.Endpoints.Logout, ct: ct).ConfigureAwait(false);
        }
        catch (EcloudException)
        {
            // 登出失败不影响本地清理
        }
        finally
        {
            http.ClearToken();
        }
    }

    /// <summary>登录后拉取用户信息（get_user_info；勿调 /client/getSysConfig —— 强制 type 会 9999100）。</summary>
    public static Task<JsonObject> GetUserInfoAsync(EcloudHttpUtil http, CancellationToken ct = default) =>
        http.PostAsync(EcloudConfig.Endpoints.UserGetInfo, ct: ct);

    /// <summary>全角数字归一 + 去空白（normalize_sms_code；真网实测全角 ３６５３３۶ 会判 30002004）。</summary>
    public static string NormalizeSmsCode(string? code)
    {
        if (string.IsNullOrEmpty(code)) return "";
        var sb = new StringBuilder();
        foreach (var ch in code.Trim())
        {
            if (char.IsWhiteSpace(ch)) continue;
            sb.Append(ch is >= '\uFF10' and <= '\uFF19' ? (char)(ch - '\uFF10' + '0') : ch);
        }
        return sb.ToString();
    }

    /// <summary>从解密响应中提取有用的服务端错误文本（对齐 _extract_error）。</summary>
    public static string ExtractError(JsonObject? resp)
    {
        if (resp == null) return "";
        foreach (var key in new[] { "errorMessage", "message", "msg", "resultMsg", "resultMessage", "returnMessage", "desc", "description" })
        {
            if (resp[key] is JsonValue v && v.TryGetValue<string>(out var s) && s != "") return s;
        }
        if (resp["body"] is JsonObject body)
        {
            var nested = ExtractError(body);
            if (nested != "" && nested != "{}") return nested;
        }
        return Truncate(resp.ToJsonString(), 500);
    }

    private static string Truncate(string s, int limit) => s.Length <= limit ? s : s[..limit] + "...";
}

// -----------------------------------------------------------------------------
// 交互式登录限流（login_rate_limit.py：滑动窗 600s 内每用户最多 3 次）
// 进程内存版（Python 落盘 data/ 以便 Docker 重启共享；本服务长驻，内存即可 —— 简化项）。
// -----------------------------------------------------------------------------
public static class EcloudLoginRateLimiter
{
    private const int WindowSec = 600;
    private const int MaxAttempts = 3;
    private static readonly object Gate = new();
    private static readonly Dictionary<string, List<DateTimeOffset>> State = new();

    public static (bool Locked, string Error, int UnlockInSec) Guard(string username)
    {
        username = username.Trim();
        lock (Gate)
        {
            var now = DateTimeOffset.UtcNow;
            if (!State.TryGetValue(username, out var ts)) State[username] = ts = new List<DateTimeOffset>();
            ts.RemoveAll(t => (now - t).TotalSeconds > WindowSec);
            if (ts.Count >= MaxAttempts)
            {
                int unlockIn = Math.Max(0, (int)((ts[0].AddSeconds(WindowSec) - now).TotalSeconds) + 1);
                int mins = Math.Max(1, (unlockIn + 59) / 60);
                return (true,
                    $"账号已锁定：10 分钟内重登不得超过 {MaxAttempts} 次，请约 {mins} 分钟后再试（剩余约 {unlockIn}s）",
                    unlockIn);
            }
            ts.Add(now);
            return (false, "", 0);
        }
    }

    /// <summary>后台重登也记账（对齐 op_session_relogin 的 record_attempt；不拦截，由冷却期把关）。</summary>
    public static void RecordAttempt(string username) => Guard(username);
}
