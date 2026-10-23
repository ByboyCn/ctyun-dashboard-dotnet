// =============================================================================
// CtyunDashboard.Ydpc / SohoClient.cs
// =============================================================================
// 对齐参考实现（Node.js，只读）：app/ydpc/soho_client.js
//
// 逐函数对齐清单：
//   soho_client.js                         → 本文件
//   ─────────────────────────────────────────────────────────────────────────
//   APP_KEY / APP_SECRET_HEX / BASE_URL    → 常量 AppKey/AppSecret/BaseUrl
//   genUuid()                              → YdpcIds.GenUuid()
//   genDeviceId()                          → YdpcIds.GenDeviceId()
//   nowMs()                                → YdpcIds.NowMs()
//   buildSign()                            → SohoClient.BuildSign()
//   rsaNoPaddingEncryptBlock()             → SohoClient.RsaNoPaddingEncryptBlock()
//   rsaEncryptBody()                       → SohoClient.RsaEncryptBody()
//   rsaEncryptPassword()                   → SohoClient.RsaEncryptPassword()
//   fetchApi()                             → SohoClient.FetchApiAsync()（含 4001/4003/未登录 自动重登）
//   bootstrapPublicKey()                   → SohoClient.BootstrapPublicKeyAsync()
//   getLoginPublicKey()                    → SohoClient.GetLoginPublicKeyAsync()
//   getVerificationCode()                  → SohoClient.GetVerificationCodeAsync()
//   login()                                → SohoClient.LoginAsync()（主号→子号智能回退）
//   listCloudPcs()                         → SohoClient.ListCloudPcsAsync()
//   getFirmAuth()                          → SohoClient.GetFirmAuthAsync()
//   heartbeat()                            → SohoClient.HeartbeatAsync()
//   getMqttConnectInfo()                   → SohoClient.GetMqttConnectInfoAsync()
//   pointEvent()                           → SohoClient.PointEventAsync()
//   bootVm()                               → SohoClient.BootAsync()
//   rebootVm()                             → SohoClient.RebootAsync()
//   shutdownVm()                           → SohoClient.PowerOffAsync()
//   fetchWithTimeout()/SOHO_TIMEOUT_MS     → 每个 HTTP 请求挂主动超时 CTS（默认 15s）
//
// 算法细节全部以 JS 源码为准：
//   · HMAC-SHA256 签名：HEADER_ORDER 固定字段序，空值字段**不参与**签名也**不外发**；
//     signSrc = `${method}&${path}&${k=v&...}` + (有 body 时 `&body=<RSA密文b64>`)，
//     HMAC 密钥为 APP_SECRET_HEX 的 hex 解码字节，输出小写 hex。
//   · RSA：公钥为服务端动态下发的 "BEGIN PUBLIC KEY"（SPKI），加密是 **NoPadding**
//     左侧零填充到模长（1024bit→128B），c = m^e mod n。.NET BCL 的 RSA.Encrypt
//     不支持 NoPadding，故与 JS 的 BigInt 回退分支完全同源：BigInteger.ModPow 手算。
//     明文分块 117B（JS 固定值 = 128 - 11）→ 每块密文 128B → 顺序拼接 → base64。
//   · 密码：password utf8 单块 NoPadding 加密 → base64。
//
// NativeAOT 约束：
//   · 禁止反射序列化。响应一律 JsonDocument/JsonElement 解析（反射安全）；
//     请求体为手工拼接的 JSON 字符串（字段顺序与 JS 对象字面量一致）。
//   · TODO(lead 合入 AppJson source-gen)：若后续需要把 SohoVm / CagFirmAuth 等
//     DTO 直接序列化落盘，请在 AppJson.JsonSerializerContext 登记
//     [JsonSerializable(typeof(CtyunDashboard.Ydpc.SohoVm))] 等条目；本文件自身
//     不做任何反射序列化，无需改动。
// =============================================================================

using System.Globalization;
using System.Numerics;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace CtyunDashboard.Ydpc;

// -----------------------------------------------------------------------------
// 共享小工具（仅限 CtyunDashboard.Ydpc 程序集内使用；四个 Ydpc 文件共用）
// -----------------------------------------------------------------------------
internal static class YdpcBin
{
    public static void W16LE(byte[] b, int off, ushort v) { b[off] = (byte)v; b[off + 1] = (byte)(v >> 8); }
    public static void W32LE(byte[] b, int off, uint v)
    {
        b[off] = (byte)v; b[off + 1] = (byte)(v >> 8); b[off + 2] = (byte)(v >> 16); b[off + 3] = (byte)(v >> 24);
    }
    public static ushort U16LE(ReadOnlySpan<byte> b, int off) => (ushort)(b[off] | (b[off + 1] << 8));
    public static uint U32LE(ReadOnlySpan<byte> b, int off) =>
        (uint)(b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24));
    public static void W16BE(byte[] b, int off, ushort v) { b[off] = (byte)(v >> 8); b[off + 1] = (byte)v; }

    public static string HexLower(ReadOnlySpan<byte> bytes)
    {
        var sb = new StringBuilder(bytes.Length * 2);
        foreach (byte b in bytes) sb.Append(b.ToString("x2", CultureInfo.InvariantCulture));
        return sb.ToString();
    }

    public static byte[] Concat(params byte[][] parts)
    {
        int total = 0;
        foreach (var p in parts) total += p.Length;
        var outBuf = new byte[total];
        int off = 0;
        foreach (var p in parts) { Buffer.BlockCopy(p, 0, outBuf, off, p.Length); off += p.Length; }
        return outBuf;
    }

    /// <summary>从流里读满恰好 n 字节（不足即 EOF 抛错），带超时与取消。</summary>
    public static async Task ReadExactAsync(Stream stream, byte[] buffer, int count, int timeoutMs, CancellationToken ct)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(timeoutMs);
        int off = 0;
        while (off < count)
        {
            int n = await stream.ReadAsync(buffer.AsMemory(off, count - off), timeoutCts.Token).ConfigureAwait(false);
            if (n <= 0) throw new EndOfStreamException($"对端在读取 {count} 字节时关闭连接（已读 {off}）");
            off += n;
        }
    }
}

internal static class YdpcIds
{
    /// <summary>对齐 soho_client.js genUuid()：32 位大写 hex，第 12 位固定 '4'，第 16 位为 variant 位。</summary>
    public static string GenUuid()
    {
        string s = RandomNumberGenerator.GetHexString(32, lowercase: false); // '0'..'9','A'..'F'
        char variant = "0123456789ABCDEF"[(HexVal(s[16]) & 0x3) | 0x8];
        return "uuid_" + s[..12] + '4' + s.Substring(13, 3) + variant + s[17..];
    }

    private static int HexVal(char c) => c switch
    {
        >= '0' and <= '9' => c - '0',
        >= 'A' and <= 'F' => c - 'A' + 10,
        >= 'a' and <= 'f' => c - 'a' + 10,
        _ => 0
    };

    /// <summary>对齐 soho_client.js nowMs()。</summary>
    public static string NowMs() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(CultureInfo.InvariantCulture);

    /// <summary>对齐 soho_client.js genDeviceId()：`SN(11位大写hex)-AA:BB:CC:DD:EE:FF`。</summary>
    public static string GenDeviceId()
    {
        string sn = GenUuid()["uuid_".Length..][..11].ToUpperInvariant();
        byte[] mac = RandomNumberGenerator.GetBytes(6);
        string macText = string.Join(':', mac.Select(b => b.ToString("x2", CultureInfo.InvariantCulture)));
        return $"{sn}-{macText}";
    }

    /// <summary>北京时间（Asia/Shanghai 固定 +08:00，无夏令时）"yyyy-MM-dd HH:mm:ss"，对齐 sv-SE 本地化输出。</summary>
    public static string BeijingTimeString() =>
        DateTimeOffset.UtcNow.ToOffset(TimeSpan.FromHours(8)).ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

    public static string BeijingTimeOnlyString() =>
        DateTimeOffset.UtcNow.ToOffset(TimeSpan.FromHours(8)).ToString("HH:mm:ss", CultureInfo.InvariantCulture);
}

// -----------------------------------------------------------------------------
// 结果 DTO（仅做承载，禁止反射序列化；如需落盘见文件头 TODO）
// -----------------------------------------------------------------------------
public sealed record SohoLoginResult(bool Success, string UserId, string SohoToken, string AccountType, JsonElement Raw);

public sealed record PowerOpResult(bool Success, string Message);

/// <summary>listCloudPcs/v6 单机条目（字段名与 JS listCloudPcs 返回值一一对应）。</summary>
public sealed class SohoVm
{
    public long UserServiceId { get; init; }
    public string UserServiceIdText { get; init; } = "";
    public string VmName { get; init; } = "中国移动云电脑";
    /// <summary>状态文字（优先官方 vmStatusShow；否则按 vmStatus 数值映射）。</summary>
    public string VmStatus { get; init; } = "未知";
    /// <summary>原始 vmStatus 数值文本（JS: vmStatusCode）。</summary>
    public string VmStatusCode { get; init; } = "";
    public string SpuCode { get; init; } = "";
    public string SkuName { get; init; } = "";
    public string Cpu { get; init; } = "";
    public string Memory { get; init; } = "";
    public string ExpireAt { get; init; } = "";
    /// <summary>'permanent' | 'limited'（与 JS durationMode 同值域）。</summary>
    public string DurationMode { get; init; } = "permanent";
    public double RemainHours { get; init; }
    public string RemainText { get; init; } = "♾️ 永久使用";
    public string RawRemainDuration { get; init; } = "";
    public JsonElement Raw { get; init; }
}

// -----------------------------------------------------------------------------
// SOHO REST 客户端
// -----------------------------------------------------------------------------
public sealed class SohoClient : IDisposable
{
    // ⚠ 密钥常量位置：与 soho_client.js 第 4-10 行逐字对齐（BASE_URL 以 JS 为准）。
    public const string AppKey = "ef80482854c2a2a36311a46011f3303f144bdf69b4b4223cf916f4c7f0f55135";
    private const string AppSecretHex = "cd58cf413dc43b07993f82f532b0f8e83d259d3ae2305de76811ccd1303853f7";
    public const string BaseUrl = "https://soho.komect.com";
    public const string PointBaseUrl = "https://point.soho.komect.com/point";
    public const string Version = "2.18.21";
    public const string VersionNum = "2182100";
    public const string UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
    public const int DefaultTimeoutMs = 15000;

    private static readonly byte[] AppSecret = HexToBytes(AppSecretHex);

    /// <summary>签名参与的 X-SOHO-* 头固定顺序（对齐 HEADER_ORDER）。</summary>
    private static readonly string[] HeaderOrder =
    {
        "X-SOHO-AppKey",
        "X-SOHO-AppType",
        "X-SOHO-ClientVersion",
        "X-SOHO-DeviceId",
        "X-SOHO-RomVersion",
        "X-SOHO-SohoToken",
        "X-SOHO-Timestamp",
        "X-SOHO-UserId",
        "X-SOHO-Uuid",
        "X-SOHO-VersionNum"
    };

    private const string PlatShort = "windows";
    private const string Release = "10.0.19045";
    private const string Model = "x64";

    public string DeviceId { get; }
    public string UserId { get; set; } = "";
    public string SohoToken { get; set; } = "";
    /// <summary>'main'（和家亲主号）| 'sub'（独立子号）。</summary>
    public string AccountType { get; set; }
    public string? PublicKeyPem { get; private set; }

    private string? _savedUsername;
    private string? _savedPassword;

    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly int _timeoutMs;
    private readonly Action<string, string>? _log;

    private (BigInteger N, BigInteger E, int ModulusLen)? _cachedPublicKey;

    public SohoClient(
        Action<string, string>? log = null,
        string? deviceId = null,
        string? userId = null,
        string? sohoToken = null,
        string? publicKeyPem = null,
        string accountType = "main",
        HttpMessageHandler? handler = null,
        int timeoutMs = DefaultTimeoutMs)
    {
        _log = log;
        DeviceId = string.IsNullOrEmpty(deviceId) ? YdpcIds.GenDeviceId() : deviceId!;
        UserId = userId ?? "";
        SohoToken = sohoToken ?? "";
        AccountType = string.IsNullOrEmpty(accountType) ? "main" : accountType!;
        PublicKeyPem = publicKeyPem;
        _timeoutMs = Math.Max(1000, timeoutMs);
        if (handler != null) { _http = new HttpClient(handler, disposeHandler: true); _ownsHttp = true; }
        else { _http = new HttpClient(); _ownsHttp = true; }
        _http.Timeout = TimeSpan.FromMilliseconds(_timeoutMs + 5000); // 兜底；逐请求另有 CTS 超时
    }

    private void Log(string level, string msg) => _log?.Invoke(level, msg);

    // -----------------------------------------------------------------------
    // 拼请求体（手工 JSON，字段顺序对齐 JS 对象字面量；NativeAOT 反射安全）
    // -----------------------------------------------------------------------
    internal static string JsonString(string s) => JsonEncodedText.Encode(s ?? "").ToString();

    internal static string JsonObj(params (string Key, string EncodedValue)[] fields)
    {
        var sb = new StringBuilder();
        sb.Append('{');
        for (int i = 0; i < fields.Length; i++)
        {
            if (i > 0) sb.Append(',');
            sb.Append('"').Append(JsonString(fields[i].Key)).Append("\":").Append(fields[i].EncodedValue);
        }
        sb.Append('}');
        return sb.ToString();
    }

    // -----------------------------------------------------------------------
    // 签名（对齐 buildSign：HEADER_ORDER 固定序，空值不参与；body 只在密文存在时追加）
    // -----------------------------------------------------------------------
    private static string BuildSign(string method, string path, ReadOnlySpan<(string K, string V)> headers, string? bodyPayload)
    {
        var parts = new List<string>(HeaderOrder.Length);
        foreach (var k in HeaderOrder)
        {
            string v = "";
            for (int i = 0; i < headers.Length; i++)
            {
                if (string.Equals(headers[i].K, k, StringComparison.Ordinal)) { v = headers[i].V ?? ""; break; }
            }
            if (v.Length > 0) parts.Add($"{k}={v}");
        }
        string signSrc = $"{method}&{path}&{string.Join('&', parts)}";
        if (!string.IsNullOrEmpty(bodyPayload)) signSrc += $"&body={bodyPayload}";
        return HmacSha256Hex(AppSecret, signSrc);
    }

    internal static string HmacSha256Hex(byte[] key, string message)
    {
        using var hmac = new HMACSHA256(key);
        byte[] hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(message));
        return YdpcBin.HexLower(hash);
    }

    private (string AppType, string RomVersion) BuildPlatformHeaders()
    {
        // appType = `windows|10.0.19045|x64|0|-1|<deviceId>|`；romVersion = `-10.0.19045`
        string appType = $"{PlatShort}|{Release}|{Model}|0|-1|{DeviceId}|";
        string romVersion = $"-{Release}";
        return (appType, romVersion);
    }

    // -----------------------------------------------------------------------
    // RSA（NoPadding，BigInteger 手算 m^e mod n —— 与 JS BigInt 回退分支同源）
    // -----------------------------------------------------------------------
    private static byte[] HexToBytes(string hex)
    {
        var bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
            bytes[i] = byte.Parse(hex.AsSpan(i * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        return bytes;
    }

    private (BigInteger N, BigInteger E, int ModulusLen) ParsePublicKey(string publicKeyPem)
    {
        if (_cachedPublicKey.HasValue && string.Equals(_lastPem, publicKeyPem, StringComparison.Ordinal))
            return _cachedPublicKey.Value;
        _lastPem = publicKeyPem;

        // "-----BEGIN PUBLIC KEY-----\n<b64>\n-----END PUBLIC KEY-----" → DER(SPKI)
        string b64 = publicKeyPem
            .Replace("-----BEGIN PUBLIC KEY-----", "", StringComparison.Ordinal)
            .Replace("-----END PUBLIC KEY-----", "", StringComparison.Ordinal)
            .Replace("\r", "", StringComparison.Ordinal)
            .Replace("\n", "", StringComparison.Ordinal)
            .Trim();
        byte[] der = Convert.FromBase64String(b64);
        using RSA rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(der, out _);
        RSAParameters p = rsa.ExportParameters(false);
        BigInteger n = FromUnsignedBigEndian(p.Modulus!);
        BigInteger e = FromUnsignedBigEndian(p.Exponent!);
        var parsed = (n, e, p.Modulus!.Length);
        _cachedPublicKey = parsed;
        return parsed;
    }

    private string? _lastPem;

    private static BigInteger FromUnsignedBigEndian(ReadOnlySpan<byte> be)
    {
        // BigInteger(byte[]) 是小端补码；前置一个 0 字节保证为正数。
        var tmp = new byte[be.Length + 1];
        for (int i = 0; i < be.Length; i++) tmp[be.Length - 1 - i] = be[i];
        return new BigInteger(tmp);
    }

    private static byte[] ToUnsignedBigEndian(BigInteger value, int minLength)
    {
        byte[] le = value.ToByteArray(); // 小端、带符号位
        int len = le.Length;
        if (len > 1 && le[len - 1] == 0) len--; // 去掉符号 0 字节
        var be = new byte[Math.Max(len, minLength)];
        for (int i = 0; i < len; i++) be[be.Length - 1 - i] = le[i];
        return be;
    }

    /// <summary>对齐 rsaNoPaddingEncryptBlock：左侧零填充到模长，c = m^e mod n，返回模长字节。</summary>
    private byte[] RsaNoPaddingEncryptBlock((BigInteger N, BigInteger E, int ModulusLen) key, byte[] block)
    {
        if (block.Length > key.ModulusLen) throw new InvalidOperationException("RSA block too long");
        var padded = new byte[key.ModulusLen];
        Buffer.BlockCopy(block, 0, padded, key.ModulusLen - block.Length, block.Length);
        BigInteger m = FromUnsignedBigEndian(padded);
        BigInteger c = BigInteger.ModPow(m, key.E, key.N);
        return ToUnsignedBigEndian(c, key.ModulusLen);
    }

    /// <summary>对齐 rsaEncryptBody：117B/块（128-11）→ 每块 128B 密文 → 拼接 → base64。空明文产出一个空块（与 JS 循环首块语义一致）。</summary>
    private string RsaEncryptBody((BigInteger N, BigInteger E, int ModulusLen) key, byte[] plain)
    {
        int chunkSize = key.ModulusLen == 128 ? 117 : key.ModulusLen - 11; // JS 固定 117
        var blocks = new List<byte[]>();
        if (plain.Length == 0)
        {
            blocks.Add(RsaNoPaddingEncryptBlock(key, Array.Empty<byte>()));
        }
        else
        {
            for (int i = 0; i < plain.Length; i += chunkSize)
            {
                int len = Math.Min(chunkSize, plain.Length - i);
                var chunk = new byte[len];
                Buffer.BlockCopy(plain, i, chunk, 0, len);
                blocks.Add(RsaNoPaddingEncryptBlock(key, chunk));
            }
        }
        return Convert.ToBase64String(YdpcBin.Concat(blocks.ToArray()));
    }

    /// <summary>对齐 rsaEncryptPassword：password utf8 单块 NoPadding 加密 → base64。</summary>
    private string RsaEncryptPassword(string publicKeyPem, string password)
    {
        byte[] block = Encoding.UTF8.GetBytes(password ?? "");
        return Convert.ToBase64String(RsaNoPaddingEncryptBlock(ParsePublicKey(publicKeyPem), block));
    }

    // -----------------------------------------------------------------------
    // HTTP（fetchApi / bootstrapPublicKey，全部带主动超时）
    // -----------------------------------------------------------------------
    private void SetSohoHeaders(HttpRequestMessage req, string method, string path, string? bodyPayload, string? sohoTokenOverride = null)
    {
        (string appType, string romVersion) = BuildPlatformHeaders();
        // 顺序即签名顺序；值为空的字段参与签名判断时跳过、外发时剔除（与 JS 两处逻辑一致）
        var headers = new (string, string)[]
        {
            ("X-SOHO-AppKey", AppKey),
            ("X-SOHO-AppType", appType),
            ("X-SOHO-ClientVersion", Version),
            ("X-SOHO-DeviceId", DeviceId),
            ("X-SOHO-RomVersion", romVersion),
            ("X-SOHO-SohoToken", sohoTokenOverride ?? SohoToken ?? ""),
            ("X-SOHO-Timestamp", YdpcIds.NowMs()),
            ("X-SOHO-UserId", UserId ?? ""),
            ("X-SOHO-Uuid", YdpcIds.GenUuid()),
            ("X-SOHO-VersionNum", VersionNum),
        };
        string signature = BuildSign(method, path, headers, bodyPayload);

        foreach (var (k, v) in headers)
        {
            if (!string.IsNullOrEmpty(v)) req.Headers.TryAddWithoutValidation(k, v);
        }
        req.Headers.TryAddWithoutValidation("X-SOHO-Signature", signature);
        req.Headers.TryAddWithoutValidation("Content-Type", "application/json");
        req.Headers.TryAddWithoutValidation("User-Agent", UserAgent);
    }

    private static async Task<HttpResponseMessage> SendWithTimeoutAsync(HttpClient http, HttpRequestMessage req, int timeoutMs, CancellationToken ct)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(timeoutMs);
        try
        {
            return await http.SendAsync(req, HttpCompletionOption.ResponseContentRead, timeoutCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new TimeoutException($"移动爱家网关请求超时 ({timeoutMs}ms，未收到响应): {req.RequestUri}");
        }
    }

    private static JsonElement ParseJsonElement(string rawText)
    {
        using var doc = JsonDocument.Parse(rawText);
        return doc.RootElement.Clone();
    }

    private static bool GetNumberProp(JsonElement el, string name, out int value)
    {
        value = 0;
        if (el.ValueKind != JsonValueKind.Object) return false;
        if (!el.TryGetProperty(name, out JsonElement p)) return false;
        if (p.ValueKind != JsonValueKind.Number) return false;
        return p.TryGetInt32(out value);
    }

    private static string? GetStringProp(JsonElement el, string name)
    {
        if (el.ValueKind != JsonValueKind.Object) return null;
        if (!el.TryGetProperty(name, out JsonElement p)) return null;
        return p.ValueKind switch
        {
            JsonValueKind.String => p.GetString(),
            JsonValueKind.Number => p.GetRawText(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            _ => null
        };
    }

    /// <summary>对齐 fetchApi()：dataJson 非空时先取公钥、RSA 分段加密包成 {"data":"..."}，签名后 POST /terminal{path}。</summary>
    public async Task<JsonElement> FetchApiAsync(string path, string? dataJson, string method = "POST", bool isRetry = false, CancellationToken ct = default)
    {
        string? bodyPayload = null;
        StringContent? content = null;
        if (dataJson != null)
        {
            if (string.IsNullOrEmpty(PublicKeyPem)) await BootstrapPublicKeyAsync(ct).ConfigureAwait(false);
            byte[] plain = Encoding.UTF8.GetBytes(dataJson);
            var key = ParsePublicKey(PublicKeyPem!);
            bodyPayload = RsaEncryptBody(key, plain);
            content = new StringContent("{\"data\":\"" + bodyPayload + "\"}", Encoding.UTF8, "application/json");
            // StringContent 会写入自己的 Content-Type，这里覆盖为无 charset 的 application/json
            content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
        }

        var url = new Uri(BaseUrl + "/terminal" + path);
        using var req = new HttpRequestMessage(new HttpMethod(method), url);
        if (content != null) req.Content = content;
        SetSohoHeaders(req, method, path, bodyPayload);

        using HttpResponseMessage res = await SendWithTimeoutAsync(_http, req, _timeoutMs, ct).ConfigureAwait(false);
        string rawText = await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

        JsonElement result;
        try
        {
            result = ParseJsonElement(rawText);
        }
        catch (JsonException)
        {
            throw new InvalidOperationException($"移动爱家网关响应异常 (HTTP {(int)res.StatusCode})");
        }

        // 自动重登：code 4001/4003 或 msg 含「未登录 / 已失效」→ 用保存的凭据重登一次再重放（isRetry 防递归）
        if (!isRetry && HasLoginExpired(result))
        {
            if (!string.IsNullOrEmpty(_savedUsername) && !string.IsNullOrEmpty(_savedPassword))
            {
                await LoginAsync(_savedUsername!, _savedPassword!, AccountType, cancellationToken: ct).ConfigureAwait(false);
                return await FetchApiAsync(path, dataJson, method, isRetry: true, ct).ConfigureAwait(false);
            }
        }

        return result;
    }

    private static bool HasLoginExpired(JsonElement result)
    {
        if (GetNumberProp(result, "code", out int code) && (code == 4001 || code == 4003)) return true;
        string? msg = GetStringProp(result, "msg");
        return msg != null && (msg.Contains("未登录", StringComparison.Ordinal) || msg.Contains("已失效", StringComparison.Ordinal));
    }

    /// <summary>对齐 bootstrapPublicKey()：POST /login/encryptKey/v1（无 body），缓存 PEM。</summary>
    public async Task<string> BootstrapPublicKeyAsync(CancellationToken ct = default)
    {
        string path = "/login/encryptKey/v1";
        using var req = new HttpRequestMessage(HttpMethod.Post, BaseUrl + "/terminal" + path);
        SetSohoHeaders(req, "POST", path, null);

        using HttpResponseMessage res = await SendWithTimeoutAsync(_http, req, _timeoutMs, ct).ConfigureAwait(false);
        string rawText = await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        JsonElement data;
        try { data = ParseJsonElement(rawText); }
        catch (JsonException) { throw new InvalidOperationException($"SOHO 网关响应异常 (HTTP {(int)res.StatusCode})"); }

        if (!GetNumberProp(data, "code", out int code) || code != 2000 || !TryGetChild(data, "data", out JsonElement pkEl))
        {
            string msg = GetStringProp(data, "msg") ?? data.GetRawText();
            throw new InvalidOperationException($"SOHO bootstrap publicKey 失败: {msg}");
        }
        string pk = pkEl.ValueKind == JsonValueKind.String ? pkEl.GetString()! : pkEl.GetRawText();
        PublicKeyPem = $"-----BEGIN PUBLIC KEY-----\n{pk}\n-----END PUBLIC KEY-----";
        return PublicKeyPem;
    }

    private static bool TryGetChild(JsonElement el, string name, out JsonElement child)
    {
        child = default;
        return el.ValueKind == JsonValueKind.Object && el.TryGetProperty(name, out child) && child.ValueKind != JsonValueKind.Null && child.ValueKind != JsonValueKind.Undefined;
    }

    /// <summary>对齐 getLoginPublicKey()：POST /login/publicKey/v1 {"type":1}。</summary>
    public async Task<string> GetLoginPublicKeyAsync(CancellationToken ct = default)
    {
        JsonElement res = await FetchApiAsync("/login/publicKey/v1", "{\"type\":1}", ct: ct).ConfigureAwait(false);
        if (!IsCode2000WithData(res, out JsonElement dataEl))
        {
            string msg = GetStringProp(res, "msg") ?? res.GetRawText();
            throw new InvalidOperationException($"获取登录公钥失败: {msg}");
        }
        string pk = dataEl.ValueKind == JsonValueKind.String ? dataEl.GetString()! : dataEl.GetRawText();
        return $"-----BEGIN PUBLIC KEY-----\n{pk}\n-----END PUBLIC KEY-----";
    }

    private static bool IsCode2000WithData(JsonElement res, out JsonElement data)
    {
        data = default;
        if (!GetNumberProp(res, "code", out int code) || code != 2000) return false;
        return TryGetChild(res, "data", out data);
    }

    /// <summary>对齐 getVerificationCode()：官方图形验证码（安全风控时用）。</summary>
    public async Task<(string Image, string RandomCode)> GetVerificationCodeAsync(CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(PublicKeyPem)) await BootstrapPublicKeyAsync(ct).ConfigureAwait(false);
        JsonElement res = await FetchApiAsync("/login/verificationCode/v1", "{}", ct: ct).ConfigureAwait(false);
        if (GetNumberProp(res, "code", out int code) && code == 2000 && TryGetChild(res, "data", out JsonElement data))
        {
            string image = GetStringProp(data, "verificationCode") ?? "";
            string randomCode = GetStringProp(data, "randomCode") ?? "";
            return (image, randomCode);
        }
        throw new InvalidOperationException(GetStringProp(res, "msg") ?? "获取移动爱家验证码失败");
    }

    /// <summary>
    /// 对齐 login()：bootstrap → 登录公钥 → RSA 加密密码 → 主号接口，失败且非验证码错误时
    /// 自动回退子号接口。accountType='sub' 时直接走子号接口。
    /// </summary>
    public Task<SohoLoginResult> LoginAsync(
        string phone,
        string password,
        string accountType = "main",
        string verificationCode = "",
        string randomCode = "",
        CancellationToken cancellationToken = default)
    {
        return LoginAsyncCore(phone, password, accountType, verificationCode, randomCode, cancellationToken);
    }

    private async Task<SohoLoginResult> LoginAsyncCore(
        string username,
        string password,
        string accountType,
        string verificationCode,
        string randomCode,
        CancellationToken ct)
    {
        _savedUsername = username;
        _savedPassword = password;
        AccountType = string.IsNullOrEmpty(accountType) ? "main" : accountType;

        await BootstrapPublicKeyAsync(ct).ConfigureAwait(false);
        string loginPk = await GetLoginPublicKeyAsync(ct).ConfigureAwait(false);
        string encPwd = RsaEncryptPassword(loginPk, password);

        string ver = verificationCode ?? "";
        string rnd = randomCode ?? "";

        // 1. 显式子账号：SOHO 独立子账号接口（subAccount）
        if (AccountType == "sub")
        {
            JsonElement subRes = await FetchApiAsync("/login/home/namePwdLogin/v1",
                JsonObj(("subAccount", "\"" + JsonString(username) + "\""),
                       ("password", "\"" + JsonString(encPwd) + "\""),
                       ("verificationCode", "\"" + JsonString(ver) + "\""),
                       ("randomCode", "\"" + JsonString(rnd) + "\"")), ct: ct).ConfigureAwait(false);
            if (IsCode2000WithData(subRes, out JsonElement subData))
            {
                UserId = ExtractAsString(subData, "userId");
                SohoToken = ExtractAsString(subData, "sohoToken");
                AccountType = "sub";
                return new SohoLoginResult(true, UserId, SohoToken, "sub", subData);
            }
            string subMsg = GetStringProp(subRes, "msg") ?? $"子账号登录失败 (code {GetCodeText(subRes)})";
            throw new InvalidOperationException(subMsg);
        }

        // 2. 主账号：主号接口失败且非验证码错误 → 智能回退子号接口
        JsonElement mainRes = await FetchApiAsync("/login/namePwdLogin/v1",
            JsonObj(("username", "\"" + JsonString(username) + "\""),
                   ("password", "\"" + JsonString(encPwd) + "\""),
                   ("verificationCode", "\"" + JsonString(ver) + "\""),
                   ("randomCode", "\"" + JsonString(rnd) + "\"")), ct: ct).ConfigureAwait(false);

        if (IsCode2000WithData(mainRes, out JsonElement mainData))
        {
            UserId = ExtractAsString(mainData, "userId");
            SohoToken = ExtractAsString(mainData, "sohoToken");
            AccountType = "main";
            return new SohoLoginResult(true, UserId, SohoToken, "main", mainData);
        }

        string mainMsg = GetStringProp(mainRes, "msg") ?? "";
        bool isCaptchaErr = mainMsg.Contains("验证码", StringComparison.Ordinal);
        if (!isCaptchaErr)
        {
            try
            {
                JsonElement subFallback = await FetchApiAsync("/login/home/namePwdLogin/v1",
                    JsonObj(("subAccount", "\"" + JsonString(username) + "\""),
                           ("password", "\"" + JsonString(encPwd) + "\""),
                           ("verificationCode", "\"" + JsonString(ver) + "\""),
                           ("randomCode", "\"" + JsonString(rnd) + "\"")), ct: ct).ConfigureAwait(false);
                if (IsCode2000WithData(subFallback, out JsonElement fbData))
                {
                    UserId = ExtractAsString(fbData, "userId");
                    SohoToken = ExtractAsString(fbData, "sohoToken");
                    AccountType = "sub";
                    return new SohoLoginResult(true, UserId, SohoToken, "sub", fbData);
                }
            }
            catch
            {
                // 与 JS 一致：回退失败吞掉，走统一的登录失败抛错
            }
        }

        throw new InvalidOperationException(string.IsNullOrEmpty(mainMsg)
            ? $"移动爱家登录失败 (code {GetCodeText(mainRes)})"
            : mainMsg);
    }

    private static string ExtractAsString(JsonElement el, string name)
    {
        if (el.ValueKind == JsonValueKind.Object && el.TryGetProperty(name, out JsonElement p))
        {
            return p.ValueKind switch
            {
                JsonValueKind.String => p.GetString() ?? "",
                JsonValueKind.Number => p.GetRawText(),
                _ => ""
            };
        }
        return "";
    }

    private static string GetCodeText(JsonElement res) =>
        GetNumberProp(res, "code", out int code) ? code.ToString(CultureInfo.InvariantCulture) : res.GetRawText();

    /// <summary>对齐 listCloudPcs()：POST /cc/cloudPc/list/v6 {"pageNum":1}，解析状态文字与限时/永久时长。</summary>
    public async Task<List<SohoVm>> ListCloudPcsAsync(CancellationToken ct = default)
    {
        JsonElement res = await FetchApiAsync("/cc/cloudPc/list/v6", "{\"pageNum\":1}", ct: ct).ConfigureAwait(false);
        if (!IsCode2000WithData(res, out JsonElement data))
        {
            throw new InvalidOperationException(GetStringProp(res, "msg") ?? $"获取移动爱家电脑列表失败 (code {GetCodeText(res)})");
        }

        var list = new List<SohoVm>();
        if (!TryGetChild(data, "list", out JsonElement arrEl) || arrEl.ValueKind != JsonValueKind.Array)
            return list;

        foreach (JsonElement vm in arrEl.EnumerateArray())
        {
            // ---- 状态文字（优先官方 vmStatusShow）----
            string vmStatusText = "";
            string? show = GetStringProp(vm, "vmStatusShow");
            if (!string.IsNullOrEmpty(show)) vmStatusText = show!;
            if (string.IsNullOrEmpty(vmStatusText))
            {
                string rawStatus = ExtractAsString(vm, "vmStatus");
                if (long.TryParse(rawStatus, NumberStyles.Integer, CultureInfo.InvariantCulture, out long statusCode))
                {
                    vmStatusText = statusCode switch
                    {
                        1 => "运行中",
                        23 or 16 => "已关机",
                        0 => "未开机",
                        _ => $"状态({rawStatus})"
                    };
                }
                else if (rawStatus.Length == 0)
                {
                    vmStatusText = "未知";
                }
                else
                {
                    vmStatusText = $"状态({rawStatus})";
                }
            }

            // ---- 限时/永久时长（对齐 JS remainDurationTime 解析）----
            string rawRemain = ExtractRawRemain(vm);
            string durationMode = "permanent";
            double remainHours = 0;
            string remainText = "♾️ 永久使用";
            if (!string.IsNullOrEmpty(rawRemain) && rawRemain != "None")
            {
                long? sec = JsParseLeadingInt(rawRemain);
                if (sec.HasValue)
                {
                    durationMode = "limited";
                    remainHours = Math.Round(sec.Value / 3600.0, 1, MidpointRounding.AwayFromZero);
                    remainText = sec.Value <= 0 ? "⏱️ 0小时" : $"⏱️ 剩余 {remainHours.ToString("0.#", CultureInfo.InvariantCulture)} 小时";
                }
            }

            list.Add(new SohoVm
            {
                UserServiceIdText = ExtractAsString(vm, "userServiceId"),
                UserServiceId = JsParseLeadingInt(ExtractAsString(vm, "userServiceId")) ?? 0,
                VmName = string.IsNullOrEmpty(ExtractAsString(vm, "vmName")) ? "中国移动云电脑" : ExtractAsString(vm, "vmName"),
                VmStatus = vmStatusText,
                VmStatusCode = ExtractAsString(vm, "vmStatus"),
                SpuCode = ExtractAsString(vm, "spuCode"),
                SkuName = ExtractAsString(vm, "skuName"),
                Cpu = ExtractAsString(vm, "cpu"),
                Memory = ExtractAsString(vm, "memory"),
                ExpireAt = FirstNonEmpty(ExtractAsString(vm, "expireTime"), ExtractAsString(vm, "expireAt")),
                DurationMode = durationMode,
                RemainHours = remainHours,
                RemainText = remainText,
                RawRemainDuration = rawRemain,
                Raw = vm.Clone()
            });
        }
        return list;
    }

    private static string ExtractRawRemain(JsonElement vm)
    {
        if (vm.ValueKind != JsonValueKind.Object || !vm.TryGetProperty("remainDurationTime", out JsonElement p)) return "";
        return p.ValueKind switch
        {
            JsonValueKind.String => p.GetString() ?? "",
            JsonValueKind.Number => p.GetRawText(),
            _ => ""
        };
    }

    /// <summary>parseInt 语义：取前导整数（含可选负号），失败返回 null。</summary>
    internal static long? JsParseLeadingInt(string s)
    {
        if (string.IsNullOrEmpty(s)) return null;
        int i = 0;
        while (i < s.Length && (s[i] == ' ' || s[i] == '\t')) i++;
        bool neg = false;
        if (i < s.Length && (s[i] == '-' || s[i] == '+')) { neg = s[i] == '-'; i++; }
        long v = 0;
        bool any = false;
        while (i < s.Length && s[i] >= '0' && s[i] <= '9')
        {
            v = checked(v * 10 + (s[i] - '0'));
            any = true;
            i++;
        }
        return any ? (neg ? -v : v) : null;
    }

    private static string FirstNonEmpty(params string[] vals)
    {
        foreach (string v in vals) if (!string.IsNullOrEmpty(v)) return v;
        return "";
    }

    /// <summary>对齐 getFirmAuth()：POST /cc/getFirmAuth/v1 {"userServiceId":N} → data（CAG/SCG 底层凭据）。</summary>
    public async Task<JsonElement> GetFirmAuthAsync(string userServiceId, CancellationToken ct = default)
    {
        long usid = JsParseLeadingInt(userServiceId) ?? throw new ArgumentException($"userServiceId 非数字: {userServiceId}", nameof(userServiceId));
        JsonElement res = await FetchApiAsync("/cc/getFirmAuth/v1", "{\"userServiceId\":" + usid.ToString(CultureInfo.InvariantCulture) + "}", ct: ct).ConfigureAwait(false);
        if (!IsCode2000WithData(res, out JsonElement data))
        {
            string msg = GetStringProp(res, "msg") ?? $"获取底层 CAG 凭据失败: {GetCodeText(res)}";
            throw new InvalidOperationException(msg);
        }
        return data;
    }

    /// <summary>对齐 heartbeat()：POST /cc/cloudPc/heartbeat/v2 {"userServiceId":N}（JS 不校验返回 code，成功=不抛）。</summary>
    public Task<JsonElement> HeartbeatAsync(string userServiceId, CancellationToken ct = default) =>
        HeartbeatAsync(JsParseLeadingInt(userServiceId) ?? throw new ArgumentException($"userServiceId 非数字: {userServiceId}"), ct);

    public async Task<JsonElement> HeartbeatAsync(long userServiceId, CancellationToken ct = default)
    {
        return await FetchApiAsync("/cc/cloudPc/heartbeat/v2",
            "{\"userServiceId\":" + userServiceId.ToString(CultureInfo.InvariantCulture) + "}", ct: ct).ConfigureAwait(false);
    }

    /// <summary>对齐 getMqttConnectInfo()：POST /system/mqttConnect/v1 {} → 官方 MQTT Broker 凭据。</summary>
    public async Task<JsonElement> GetMqttConnectInfoAsync(CancellationToken ct = default)
    {
        return await FetchApiAsync("/system/mqttConnect/v1", "{}", ct: ct).ConfigureAwait(false);
    }

    /// <summary>对齐 pointEvent()：官方活跃度埋点上报（point.soho.komect.com；失败返回 {"code":-1,"msg":...} 不抛）。</summary>
    public async Task<JsonElement> PointEventAsync(string eventName, string? extraDataJson = null, CancellationToken ct = default)
    {
        try
        {
            if (string.IsNullOrEmpty(PublicKeyPem)) await BootstrapPublicKeyAsync(ct).ConfigureAwait(false);

            string clientTime = YdpcIds.BeijingTimeString();
            string phone = _savedUsername ?? "";
            string accountTypeText = AccountType == "sub" ? "Sub_account" : "Main_account";
            // payloadData = {clientTime, phone, Account, Account_type, ...extraData}
            string extraInner = string.IsNullOrWhiteSpace(extraDataJson)
                ? ""
                : extraDataJson!.Trim().TrimStart('{').TrimEnd('}');
            string payloadData = JsonObj(
                ("clientTime", "\"" + JsonString(clientTime) + "\""),
                ("phone", "\"" + JsonString(phone) + "\""),
                ("Account", "\"" + JsonString(phone) + "\""),
                ("Account_type", "\"" + JsonString(accountTypeText) + "\""))[..^1]
                + (extraInner.Length > 0 ? "," + extraInner : "") + "}";

            // bodyObj = {eventName, data: JSON.stringify(payloadData)}（data 是「字符串化的 JSON」）
            string bodyObj = JsonObj(
                ("eventName", "\"" + JsonString(eventName) + "\""),
                ("data", "\"" + JsonString(payloadData) + "\""));

            byte[] plain = Encoding.UTF8.GetBytes(bodyObj);
            var key = ParsePublicKey(PublicKeyPem!);
            string bodyPayload = RsaEncryptBody(key, plain);
            string sendBody = "{\"data\":\"" + bodyPayload + "\"}";

            string path = "/custom/cc/v1";
            using var req = new HttpRequestMessage(HttpMethod.Post, PointBaseUrl + path);
            req.Content = new StringContent(sendBody, Encoding.UTF8, "application/json");
            SetSohoHeaders(req, "POST", path, bodyPayload);

            using HttpResponseMessage res = await SendWithTimeoutAsync(_http, req, _timeoutMs, ct).ConfigureAwait(false);
            string rawText = await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            try { return ParseJsonElement(rawText); }
            catch (JsonException) { return ParseJsonElement("{\"code\":-1,\"msg\":\"point 响应非 JSON\"}"); }
        }
        catch (Exception e)
        {
            return ParseJsonElement("{\"code\":-1,\"msg\":" + "\"" + JsonString(e.Message) + "\"}");
        }
    }

    /// <summary>对齐 bootVm()：POST /cc/activate/v1 {"userServiceId":N}（官方开机/激活）。</summary>
    public async Task<PowerOpResult> BootAsync(string vmId, CancellationToken ct = default)
    {
        try
        {
            long usid = JsParseLeadingInt(vmId) ?? throw new ArgumentException($"vmId 非数字: {vmId}");
            JsonElement res = await FetchApiAsync("/cc/activate/v1",
                "{\"userServiceId\":" + usid.ToString(CultureInfo.InvariantCulture) + "}", ct: ct).ConfigureAwait(false);
            if (GetNumberProp(res, "code", out int code) && (code == 2000 || code == 0))
                return new PowerOpResult(true, "开机/激活指令已生效");
            string? errMsg = GetStringProp(res, "errMsg") ?? GetStringProp(res, "msg");
            if (errMsg != null) throw new InvalidOperationException(errMsg);
            throw new InvalidOperationException($"开机请求被拒绝 (code {GetCodeText(res)})");
        }
        catch (Exception e) when (e is not ArgumentException)
        {
            throw new InvalidOperationException(string.IsNullOrEmpty(e.Message) ? "开机指令下发失败" : e.Message);
        }
    }

    /// <summary>对齐 rebootVm()：POST /cc/getRebootAuth/v1 {"userServiceId":N}。</summary>
    public async Task<PowerOpResult> RebootAsync(string vmId, CancellationToken ct = default)
    {
        try
        {
            long usid = JsParseLeadingInt(vmId) ?? throw new ArgumentException($"vmId 非数字: {vmId}");
            JsonElement res = await FetchApiAsync("/cc/getRebootAuth/v1",
                "{\"userServiceId\":" + usid.ToString(CultureInfo.InvariantCulture) + "}", ct: ct).ConfigureAwait(false);
            if (GetNumberProp(res, "code", out int code) && (code == 2000 || code == 0))
                return new PowerOpResult(true, "重启指令已成功下达！");
            string? errMsg = GetStringProp(res, "errMsg") ?? GetStringProp(res, "msg");
            if (errMsg != null) throw new InvalidOperationException(errMsg);
            throw new InvalidOperationException($"重启请求被拒绝 (code {GetCodeText(res)})");
        }
        catch (Exception e) when (e is not ArgumentException)
        {
            throw new InvalidOperationException(string.IsNullOrEmpty(e.Message) ? "重启指令下发失败" : e.Message);
        }
    }

    /// <summary>对齐 shutdownVm()：POST /cc/cloudPc/logout/v2 {"userServiceId":N}（官方关机/断开）。</summary>
    public async Task<PowerOpResult> PowerOffAsync(string vmId, CancellationToken ct = default)
    {
        try
        {
            long usid = JsParseLeadingInt(vmId) ?? throw new ArgumentException($"vmId 非数字: {vmId}");
            JsonElement res = await FetchApiAsync("/cc/cloudPc/logout/v2",
                "{\"userServiceId\":" + usid.ToString(CultureInfo.InvariantCulture) + "}", ct: ct).ConfigureAwait(false);
            if (GetNumberProp(res, "code", out int code) && (code == 2000 || code == 0))
                return new PowerOpResult(true, "关机/断开指令已生效！");
            string? errMsg = GetStringProp(res, "errMsg") ?? GetStringProp(res, "msg");
            if (errMsg != null) throw new InvalidOperationException(errMsg);
            throw new InvalidOperationException($"关机请求被拒绝 (code {GetCodeText(res)})");
        }
        catch (Exception e) when (e is not ArgumentException)
        {
            throw new InvalidOperationException(string.IsNullOrEmpty(e.Message) ? "关机指令下发失败" : e.Message);
        }
    }

    /// <summary>桌面登出（cmcc-cloud-alive logout.py desktop_logout）：POST /cc/cloudPc/logout/v2
    /// {"userServiceId":N} 释放会话锁。与 PowerOffAsync 同端点但语义不同：**不设 code 成功门槛**，
    /// 响应原样返回（母本明确不做 listClouds 校验，避免 token 过期被前置硬失败）。</summary>
    public async Task<JsonElement> LogoutDesktopAsync(string userServiceId, CancellationToken ct = default)
    {
        long usid = JsParseLeadingInt(userServiceId) ?? throw new ArgumentException($"userServiceId 非数字: {userServiceId}");
        return await FetchApiAsync("/cc/cloudPc/logout/v2",
            "{\"userServiceId\":" + usid.ToString(CultureInfo.InvariantCulture) + "}", ct: ct).ConfigureAwait(false);
    }

    /// <summary>账号登出（logout.py account_logout）：POST /login/logout/v1 + 清本地 sohoToken/userId。</summary>
    public async Task<JsonElement> AccountLogoutAsync(CancellationToken ct = default)
    {
        var res = await FetchApiAsync("/login/logout/v1", null, ct: ct).ConfigureAwait(false);
        SohoToken = "";
        UserId = "";
        return res;
    }

    // -----------------------------------------------------------------------
    // 桌面会话 HTTP 保活（cmcc-cloud-alive desktop_keepalive.py 对齐，简化移植）
    // -----------------------------------------------------------------------

    /// <summary>锁屏态心跳码：desktop_keepalive.LOCK_SCREEN_CODES {4039,4040,4041,4042}（仍算受理）。</summary>
    public static readonly int[] LockScreenCodes = { 4039, 4040, 4041, 4042 };
    /// <summary>desktop_keepalive.OTHER_LOGIN_CODE 4043：云电脑在别处登录/已被回收。</summary>
    public const int HeartbeatOtherLoginCode = 4043;

    /// <summary>心跳码是否算受理（code ∈ {2000} ∪ LOCK_SCREEN_CODES；对齐 candidateAccepted 判据）。</summary>
    public static bool IsHeartbeatAccepted(int code) => code == 2000 || Array.IndexOf(LockScreenCodes, code) >= 0;

    /// <summary>断连时间消息提取（desktop_keepalive._disconnect_time_message：data.message → message → 原文）。</summary>
    public static string DisconnectTimeMessage(JsonElement resp)
    {
        if (resp.ValueKind == JsonValueKind.Object)
        {
            if (resp.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Object &&
                data.TryGetProperty("message", out var dm) && dm.ValueKind == JsonValueKind.String)
                return dm.GetString() ?? "";
            if (resp.TryGetProperty("message", out var m) && m.ValueKind == JsonValueKind.String)
                return m.GetString() ?? "";
        }
        return resp.GetRawText();
    }

    /// <summary>信息上报（desktop_keepalive.info_report）：POST /cc/cloudPc/infoReport/v2。
    /// 载荷为简化版设备信息（母本 device_info.collect_device_info 的合理默认子集）。</summary>
    public async Task<JsonElement> InfoReportAsync(CancellationToken ct = default)
    {
        string body = JsonObj(
            ("deviceName", "\"" + JsonString(Environment.MachineName) + "\""),
            ("deviceType", "\"pc\""),
            ("osVersion", "\"Windows 10 64-bit\""),
            ("appVersion", "\"" + JsonString(Version) + "\""),
            ("clientVersion", "\"" + JsonString(Version) + "\""));
        return await FetchApiAsync("/cc/cloudPc/infoReport/v2", body, ct: ct).ConfigureAwait(false);
    }

    /// <summary>断连时长（desktop_keepalive.disconnect_time）：POST /cc/cloudPc/getDisconnectTime/v1。</summary>
    public async Task<JsonElement> DisconnectTimeAsync(string userServiceId, CancellationToken ct = default)
    {
        long usid = JsParseLeadingInt(userServiceId) ?? throw new ArgumentException($"userServiceId 非数字: {userServiceId}");
        return await FetchApiAsync("/cc/cloudPc/getDisconnectTime/v1",
            "{\"userServiceId\":" + usid.ToString(CultureInfo.InvariantCulture) + "}", ct: ct).ConfigureAwait(false);
    }

    /// <summary>日志上报配置（desktop_keepalive.log_report_config）：POST /system/logReport/config/v2。</summary>
    public Task<JsonElement> LogReportConfigAsync(CancellationToken ct = default) =>
        FetchApiAsync("/system/logReport/config/v2", null, ct: ct);

    public void Dispose()
    {
        if (_ownsHttp) _http.Dispose();
    }
}
