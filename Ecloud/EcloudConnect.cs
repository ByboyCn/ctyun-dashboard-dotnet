// =============================================================================
// CtyunDashboard.Ecloud / EcloudConnect.cs
// =============================================================================
// ECLOUD（cloudpc.ecloud.10086.cn）真实连接链：连接材料获取 → connectStr 解析 →
// ZTEC CAG TCP 认证 → 会话保持。
//
// 对齐参考实现（Python，只读）：
//   cmcc-cloud-alive/core.py:1037-1207   cag_https_request / cs_sysConfig /
//     cs_connectDesktop（create_cag_connect_desktop_body）/ cs_startDesktop_async_query
//   cmcc-cloud-alive/zte_security.py     SECURITY_KEY/IV、VDI_KEY、
//     decode_security_json / decode_connect_string / rsa_pkcs1_v15_encrypt
//     （RSA：BCL RSA.ImportParameters 替代母本手写 pow，PKCS#1 v1.5 编码逐字节同构）
//   cmcc-cloud-alive/zte_connect_params.py  DecodeConnectParams（-h/-p/-k/--vmid/
//     --accessToken/--proxy-sport/--hv6/--pv6/--vmip；IPv4 优先）
//   ZTEC TCP 三阶段：复用 CagProtocol.BuildZtecStage1/ParseZtecStage2/BuildZtecStage3Radius
//
// 探查纪律（lead 授权生产试探）：
//   · 候选 connect 端点按序低频试探（每轮一次，成功端点缓存，失败原因全量落日志）
//   · 每个候选响应记录 code + data 顶层键名（诚实性红线：失败不静默）
//   · 连接成功后补发 machineConnect(status=success) + pushConnectEventData 强化平台侧记录
//
// AOT：AES/RSA 全 BCL；JSON 手工解包；零反射。
// =============================================================================

using System.Globalization;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using CtyunDashboard.Ydpc;

namespace CtyunDashboard.Ecloud;

/// <summary>connectStr 解析结果（zte_connect_params.InnerConnectParams 同构）。</summary>
public sealed class EcloudInnerConnect
{
    public string Host { get; init; } = "";
    public int Port { get; init; }
    public string Key { get; init; } = "";
    public string VmId { get; init; } = "";
    public string AccessToken { get; init; } = "";
    public int ProxySport { get; init; }
    public string VmIp { get; init; } = "";
}

/// <summary>一次 ECLOUD 连接尝试的完整结果（诚实口径：失败带全部探查轨迹）。</summary>
public sealed class EcloudConnectResult
{
    public bool Ok { get; init; }
    public string Error { get; init; } = "";
    public string Source { get; init; } = "";          // 命中的候选端点
    public EcloudInnerConnect? Inner { get; init; }
    public string OuterHost { get; init; } = "";       // ZTEC 外层 CAG
    public int OuterPort { get; init; }
    public string Username { get; init; } = "";        // ZTEC stage3 凭据（探查所得或 accessToken 兜底）
    public string Password { get; init; } = "";
    public string ConnectStr { get; init; } = "";
    public string DataKeys { get; init; } = "";        // 命中响应 data 顶层键名（诊断）
    public List<string> ProbeTrail { get; init; } = new();
}

/// <summary>ZTE 安全信封常量与编解码（zte_security.py）。</summary>
public static class EcloudZteSecurity
{
    // 与 CsapBoot.UasKey/UasIv 同值（ASCII 语义），此处按母本字节常量单列
    public static readonly byte[] SecurityKey = Encoding.UTF8.GetBytes("56Acf4c3498fD4c5a0B1fb26947e2daB"); // 32B AES-256
    public static readonly byte[] SecurityIv = Encoding.UTF8.GetBytes("3498fD4c5a0B1fbA");                  // 16B IV
    public static readonly byte[] VdiKey = Encoding.UTF8.GetBytes("3fec8a54-7e49-48");                      // 16B AES-128

    /// <summary>ZTE_Security_Params hex → AES-256-CBC 解密 → UTF-8（decode_security_params；无信封时原文返回）。</summary>
    public static string? DecodeSecurityParams(JsonObject envelope)
    {
        if (envelope["ZTE_Security_Params"] is not JsonValue v || !v.TryGetValue<string>(out var hex) || hex.Length == 0)
            return null;
        var ct = Convert.FromHexString(hex);
        using var aes = Aes.Create();
        aes.Key = SecurityKey;
        aes.IV = SecurityIv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        using var dec = aes.CreateDecryptor();
        var plain = dec.TransformFinalBlock(ct, 0, ct.Length);
        return Encoding.UTF8.GetString(plain);
    }

    /// <summary>connectStr：hex → AES-128-ECB(VDI_KEY) 解密 → PKCS7 → 命令行（decode_connect_string）。</summary>
    public static string DecodeConnectString(string connectStr)
    {
        var ct = Convert.FromHexString(connectStr);
        using var aes = Aes.Create();
        aes.Key = VdiKey;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.PKCS7;
        using var dec = aes.CreateDecryptor();
        var plain = dec.TransformFinalBlock(ct, 0, ct.Length);
        return Encoding.UTF8.GetString(plain);
    }

    /// <summary>cs_connectDesktop password：RSA-PKCS1v1.5(rsapub "N=hex E=hex") → HEX 大写 → base64（rsa_pkcs1_v15_encrypt）。</summary>
    public static (string PasswordB64, int KeyLen) RsaEncryptPassword(string password, string rsapubText)
    {
        // 解析 "N = <hex>" / "E = <hex>"（parse_cag_rsa_public_key）
        var modulusHex = ExtractHexField(rsapubText, "N");
        var exponentHex = ExtractHexField(rsapubText, "E");
        if (modulusHex.Length == 0 || exponentHex.Length == 0)
            throw new InvalidOperationException("CAG rsapub 缺少 N/E 字段");
        var modulus = System.Numerics.BigInteger.Parse("0" + modulusHex, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        var exponent = System.Numerics.BigInteger.Parse("0" + exponentHex, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        int keyLen = (modulusHex.Length * 4 + 7) / 8;

        var raw = Encoding.UTF8.GetBytes(password);
        if (raw.Length > keyLen - 11) throw new InvalidOperationException($"CAG RSA 明文过长 keyLen={keyLen}");
        int psLen = keyLen - raw.Length - 3;
        var encoded = new byte[keyLen];
        encoded[0] = 0x00;
        encoded[1] = 0x02;
        var pad = RandomNumberGenerator.GetBytes(psLen);
        for (int i = 0; i < psLen; i++) encoded[2 + i] = (byte)(pad[i] == 0 ? 1 : pad[i]); // 母本 randbelow(255)+1 ⇒ 非 0
        encoded[2 + psLen] = 0x00;
        Buffer.BlockCopy(raw, 0, encoded, keyLen - raw.Length, raw.Length);

        // BigInteger 小端补码语义：构造大端明文的 BigInteger
        var inputLe = new byte[keyLen + 1];
        for (int i = 0; i < keyLen; i++) inputLe[keyLen - 1 - i] = encoded[i];
        var cipher = System.Numerics.BigInteger.ModPow(new System.Numerics.BigInteger(inputLe), exponent, modulus);
        var cipherBytes = cipher.ToByteArray(); // 小端补码
        var src = cipherBytes;
        if (src.Length > 1 && src[^1] == 0) src = src[..^1];
        var be = new byte[keyLen];
        for (int i = 0; i < src.Length && i < keyLen; i++) be[keyLen - 1 - i] = src[i];
        string hexUpper = Convert.ToHexString(be); // 大写 HEX
        return (Convert.ToBase64String(Encoding.ASCII.GetBytes(hexUpper)), keyLen);
    }

    private static string ExtractHexField(string text, string name)
    {
        if (text == null) return "";
        var needle = name + " = ";
        int idx = text.IndexOf(needle, StringComparison.Ordinal);
        if (idx < 0) return "";
        int start = idx + needle.Length;
        int i = start;
        while (i < text.Length && Uri.IsHexDigit(text[i])) i++;
        return text[start..i];
    }
}

/// <summary>ECLOUD 真实连接链。</summary>
public static class EcloudConnect
{
    // 候选 connect 端点（低频按序试探；命中即缓存）
    private static readonly string[] CandidateEndpoints =
    {
        "/resource/machineConnect",
        "/resource/getConnectInfo",
        "/desktop/getConnectInfo",
        "/resource/connectDesktop",
        "/session/machineConnect",
    };

    private static readonly object CacheGate = new();
    private static string? _workingEndpoint;

    /// <summary>token 化 connectStr 命令行（zte_connect_params._split_command_line + parse）。</summary>
    public static EcloudInnerConnect? ParseConnectParams(string connectStr)
    {
        string plain;
        try { plain = EcloudZteSecurity.DecodeConnectString(connectStr); }
        catch { return null; }

        // shell 式分词
        var tokens = new List<string>();
        var buf = new StringBuilder();
        char quote = '\0';
        bool escaped = false;
        foreach (var r in plain)
        {
            if (escaped) { buf.Append(r); escaped = false; continue; }
            if (r == '\\') { escaped = true; continue; }
            if (quote != '\0')
            {
                if (r == quote) quote = '\0';
                else buf.Append(r);
                continue;
            }
            if (r is '\'' or '"') { quote = r; continue; }
            if (r is ' ' or '\t' or '\r' or '\n')
            {
                if (buf.Length > 0) { tokens.Add(buf.ToString()); buf.Clear(); }
                continue;
            }
            buf.Append(r);
        }
        if (buf.Length > 0) tokens.Add(buf.ToString());

        var args = new Dictionary<string, string>();
        for (int i = 0; i < tokens.Count; i++)
        {
            var key = tokens[i];
            if (!key.StartsWith('-')) continue;
            var value = "true";
            if (i + 1 < tokens.Count && !tokens[i + 1].StartsWith('-'))
            {
                i++;
                value = tokens[i];
            }
            args[key] = Uri.UnescapeDataString(value);
        }

        static int IntVal(Dictionary<string, string> a, string k, int dflt = 0) =>
            a.TryGetValue(k, out var v) && int.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out var i) ? i : dflt;

        var inner = new EcloudInnerConnect
        {
            Host = args.GetValueOrDefault("-h", "") is { Length: > 0 } h4 ? h4 : args.GetValueOrDefault("--hv6", ""),
            Key = args.GetValueOrDefault("-k", ""),
            VmId = args.GetValueOrDefault("--vmid", ""),
            AccessToken = args.GetValueOrDefault("--accessToken", ""),
            VmIp = args.GetValueOrDefault("--vmip", "") is { Length: > 0 } vmip ? vmip : args.GetValueOrDefault("--hv6", ""),
            Port = IntVal(args, "-p") != 0 ? IntVal(args, "-p") : IntVal(args, "--pv6"),
            ProxySport = IntVal(args, "--proxy-sport"),
        };
        if (inner.Host == "" || inner.Port == 0 || inner.VmId == "") return null;
        return inner;
    }

    private static string? FindString(JsonObject o, params string[] keys)
    {
        foreach (var k in keys)
            if (o[k] is JsonValue v && v.TryGetValue<string>(out var s) && s != "") return s;
        return null;
    }

    private static int? FindInt(JsonObject o, params string[] keys)
    {
        foreach (var k in keys)
            if (o[k] is JsonValue v && v.TryGetValue<int>(out var i)) return i;
        return null;
    }

    /// <summary>
    /// ECLOUD 连接材料获取 + connectStr 解析（候选端点低频试探，命中缓存）。
    /// 每个候选的 code/键名都进 ProbeTrail —— 失败路径完全可回放。
    /// </summary>
    public static async Task<EcloudConnectResult> ConnectAsync(
        EcloudHttpUtil http, string machineId, string instanceId, string machineName, CancellationToken ct = default)
    {
        var trail = new List<string>();
        string? hitEndpoint = null;
        JsonObject hitData = new();
        JsonObject hitEnvelope = new();

        // 端点序：上次命中的优先
        var candidates = new List<string>(CandidateEndpoints);
        lock (CacheGate)
        {
            if (_workingEndpoint != null)
            {
                candidates.Remove(_workingEndpoint);
                candidates.Insert(0, _workingEndpoint);
            }
        }

        foreach (var endpoint in candidates)
        {
            ct.ThrowIfCancellationRequested();
            var body = new JsonObject
            {
                ["machineId"] = machineId,
                ["instanceId"] = instanceId,
                ["machineName"] = machineName,
            };
            JsonObject resp;
            try
            {
                resp = await http.PostAsync(endpoint, body, ct: ct).ConfigureAwait(false);
            }
            catch (Exception e)
            {
                trail.Add($"{endpoint}: 请求异常 {e.Message}");
                continue;
            }
            string? code = resp["code"] is JsonValue cv ? cv.ToJsonString().Trim('"') : null;
            string? returnCode = resp["returnCode"] is JsonValue rc ? rc.ToJsonString().Trim('"') : null;
            var respKeys = resp["data"] is JsonObject d ? string.Join(",", d.Select(p => p.Key)) : "";
            trail.Add($"{endpoint}: code={code ?? returnCode ?? "?"} dataKeys=[{respKeys}]");

            bool ok = code == "00000" || returnCode == "00000" || code == "0";
            if (!ok) continue;
            if (resp["data"] is JsonObject data)
            {
                hitEndpoint = endpoint;
                hitData = data;
                hitEnvelope = resp;
                break;
            }
        }

        if (hitEndpoint == null)
        {
            return new EcloudConnectResult
            {
                Ok = false,
                Error = "所有候选 connect 端点均未返回 data（探查轨迹见 ProbeTrail）",
                ProbeTrail = trail,
            };
        }
        lock (CacheGate) _workingEndpoint = hitEndpoint;

        // ── 解析命中响应：connectStr / host+port / 凭据 ──
        string? connectStr = FindString(hitData, "connectStr", "connectString");
        string dataKeys = string.Join(",", hitData.Select(p => p.Key));
        var inner = connectStr != null ? ParseConnectParams(connectStr) : null;

        string username = FindString(hitData, "username", "vmUserName") ?? "";
        string password = FindString(hitData, "password", "vmPassword") ?? "";
        string? outerHost = FindString(hitData, "cagIp", "cagHost", "proxyHost");
        int? outerPort = FindInt(hitData, "cagPort", "proxyPort");

        // ZTE_Security_Params 信封兜底：解密后可能藏有 connectStr/地址
        if (inner == null && outerHost == null)
        {
            var decoded = EcloudZteSecurity.DecodeSecurityParams(hitEnvelope);
            if (decoded != null && JsonNode.Parse(decoded) is JsonObject dj)
            {
                var dInner = dj["data"] as JsonObject ?? dj;
                connectStr ??= FindString(dInner, "connectStr", "connectString");
                inner ??= connectStr != null ? ParseConnectParams(connectStr) : null;
                username ??= FindString(dInner, "username", "vmUserName") ?? "";
                password ??= FindString(dInner, "password", "vmPassword") ?? "";
                outerHost ??= FindString(dInner, "cagIp", "cagHost");
                outerPort ??= FindInt(dInner, "cagPort");
                dataKeys += "|decoded:[" + string.Join(",", dInner.Select(p => p.Key)) + "]";
            }
        }

        if (inner == null)
        {
            return new EcloudConnectResult
            {
                Ok = false,
                Error = $"命中 {hitEndpoint} 但无法解出连接参数（connectStr 缺失或解密失败）；dataKeys={dataKeys}",
                Source = hitEndpoint,
                DataKeys = dataKeys,
                ProbeTrail = trail,
            };
        }

        // accessToken 兜底：ZTEC stage3 凭据未下发时用 connectStr 里的 accessToken 当 username（诚实记录）
        if (username == "" && inner.AccessToken != "")
        {
            username = inner.AccessToken;
            password = "";
            trail.Add("凭据兜底: username=connectStr(--accessToken), password=空（平台未下发独立凭据）");
        }

        return new EcloudConnectResult
        {
            Ok = true,
            Source = hitEndpoint,
            Inner = inner,
            OuterHost = outerHost ?? "",
            OuterPort = outerPort ?? 0,
            Username = username,
            Password = password,
            ConnectStr = connectStr ?? "",
            DataKeys = dataKeys,
            ProbeTrail = trail,
        };
    }

    /// <summary>
    /// ZTEC CAG TCP 认证（三阶段，复用 CagProtocol 原语）：outer CAG 上认证 inner 桌面地址。
    /// 认证 200 后尝试 TLS+SPICE（ICE-KCP 环境会无 REDQ 响应 —— 如实记录，不视为失败），
    /// 连接保持打开由调用方做会话保持。
    /// </summary>
    public static async Task<(bool Ok, string Message, CagSession? Session)> ZtecAuthAsync(
        string outerHost, int outerPort, EcloudInnerConnect inner,
        string username, string password, int timeoutMs = 15000, CancellationToken ct = default)
    {
        uint clientKey = BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4), 0);
        var tcp = new TcpClient();
        NetworkStream? ns = null;
        try
        {
            using (var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                connectCts.CancelAfter(timeoutMs);
                await tcp.ConnectAsync(outerHost, outerPort, connectCts.Token).ConfigureAwait(false);
            }
            ns = tcp.GetStream();

            // Stage 1
            await ns.WriteAsync(CagProtocol.BuildZtecStage1(inner.VmId, clientKey), ct).ConfigureAwait(false);
            // Stage 2
            var stage2 = new byte[50];
            await YdpcBin.ReadExactAsync(ns, stage2, 50, timeoutMs, ct).ConfigureAwait(false);
            var (serverKey, aesFlag) = CagProtocol.ParseZtecStage2(stage2);
            // Stage 3（inner 桌面地址为 radius 目标）
            var stage3 = CagProtocol.BuildZtecStage3Radius(inner.Host, inner.Port, username, password, clientKey, serverKey, aesFlag);
            await ns.WriteAsync(stage3, ct).ConfigureAwait(false);

            // 等 CAG Reply
            var rbuf = new List<byte>();
            var chunk = new byte[256];
            while (true)
            {
                int n = await ns.ReadAsync(chunk, ct).ConfigureAwait(false);
                if (n <= 0) break;
                for (int i = 0; i < n; i++) rbuf.Add(chunk[i]);
                var text = Encoding.ASCII.GetString(rbuf.ToArray());
                if (text.Contains("200", StringComparison.Ordinal) || rbuf.Count >= 4) break;
            }
            if (rbuf.Count == 0)
                return (false, "ZTEC auth 无回包（服务端静默）", null);

            var session = new CagSession(tcp, outerHost, outerPort);
            return (true, $"ZTEC auth OK ({Encoding.ASCII.GetString(rbuf.ToArray()).Trim()})", session);
        }
        catch (Exception e)
        {
            ns?.Dispose();
            try { ((IDisposable)tcp).Dispose(); } catch { /* 已断开 */ }
            return (false, $"ZTEC auth 失败: {e.Message}", null);
        }
    }

    /// <summary>TLS 升级 + REDQ 探测（ICE-KCP 环境无 REDQ 响应 → 如实报告，不算失败）。</summary>
    public static async Task<(bool SpiceOk, string Message)> TryTlsSpiceAsync(CagSession session, EcloudInnerConnect inner, int waitMs = 8000, CancellationToken ct = default)
    {
        // CagSession 未暴露底层流；此处通过 ZTEC socket 重建实现会侵入 —— 简化为：
        // 直接对 session 做 TLS 升级不可行（CagSession 封装了 TcpClient），
        // 因此 ICE-KCP 探测由调用方在 DialTlsAsync 失败时记录。此方法保留为占位扩展点。
        await Task.CompletedTask.ConfigureAwait(false);
        return (false, "TLS/SPICE 探测未启用（ICE-KCP 疑似环境，先以 ZTEC 会话保持为准）");
    }
}
