// =============================================================================
// CtyunDashboard.Ydpc / CsapBoot.cs
// =============================================================================
// 对齐参考实现（Python，只读）：ydpc-keeplive/webapp/keepalive_core.py
//   _csap_load_keys()/_csap_get_keys()（三把固定密钥：csapKey/uasKey/uasIv）
//   _pkcs7_pad()/_pkcs7_unpad()
//   _csap_encode_body()（AES-256-CBC(uasKey,uasIv) PKCS7 → HEX 大写；json compact+sort_keys）
//   _csap_decode_response()（ZTE_Security_Params hex → AES-CBC 解密 → json）
//   _csap_encrypt_password()（quote(pwd, safe="-_.~") → AES-192-ECB(csapKey) PKCS7 → b64 → '+'→%2B）
//   _csap_start_desktop()（完整开机五步：cs_sysConfig → cs_getToken → cs_getDesktopList →
//                          cs_startDesktop → cs_startDesktop_async_query 轮询 60s/3s）
//   boot_vm() 的 ZTE 分支调度（vmStatus 16/23 = 关机；vmStatus 0 且无 vmStatusShow = 从未开机）
//
// CAG HTTPS 请求形态：
//   POST https://{cagIp}:{cagPort}/cs/{action}?{query}
//   Headers: Content-Type=application/xml, X-Ap-sHost={vmcIp}:{vmcPort},
//            process_id=2, serialNum=uuid4, otlp_trace_id=32hex,
//            otlp_parent_id=%016x 递增, Connection=keep-alive
//   Body = 加密后 HEX 文本
// 版本常量 V7.25.22 / requestFrom=9 / RspSecurity=1 与母本逐字对齐。
//
// AOT：AES 用 System.Security.Cryptography（KeySize 192/256 均为 BCL 内建）；零反射。
// =============================================================================

using System.Globalization;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace CtyunDashboard.Ydpc;

public static class CsapBoot
{
    // 固定密钥（_csap_load_keys 逐字节对齐；官方客户端内置常量）
    private static readonly byte[] CsapKey = Convert.FromHexString("33666563386135342d376534392d3438");                                // AES-192
    private static readonly byte[] UasKey = Convert.FromHexString("3536416366346333343938664434633561304231666232363934376532646142"); // AES-256
    private static readonly byte[] UasIv = Convert.FromHexString("33343938664434633561304231666241");                                  // 16B IV

    private const string Version = "V7.25.22";
    private const string Mac = "0a-e0-60-8b-31-21";
    private const string ClientIp = "192.168.5.14";
    private const string HostName = "zxcs-MacBook-Pro.local";
    private const string SnCode = "5DF71D7B-6B8F-5186-9A1D-B503644C187F";

    /// <summary>vmStatus 16/23 = 关机（_is_vm_off；0 且无 vmStatusShow = 从未开机，需官方首连）。</summary>
    public static bool IsVmOff(long? vmStatus) => vmStatus is 16 or 23;

    // ---------- 加解密 ----------
    private static byte[] AesCbc(byte[] data, bool encrypt)
    {
        using var aes = Aes.Create();
        aes.Key = UasKey;
        aes.IV = UasIv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        using var t = encrypt ? aes.CreateEncryptor() : aes.CreateDecryptor();
        return encrypt ? t.TransformFinalBlock(data, 0, data.Length) : t.TransformFinalBlock(data, 0, data.Length);
    }

    private static byte[] AesEcb192(byte[] data)
    {
        using var aes = Aes.Create();
        aes.Key = CsapKey;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.PKCS7;
        using var enc = aes.CreateEncryptor();
        return enc.TransformFinalBlock(data, 0, data.Length);
    }

    private static byte[] Pkcs7Pad(byte[] data)
    {
        int pad = 16 - data.Length % 16;
        var outBuf = new byte[data.Length + pad];
        Buffer.BlockCopy(data, 0, outBuf, 0, data.Length);
        for (int i = data.Length; i < outBuf.Length; i++) outBuf[i] = (byte)pad;
        return outBuf;
    }

    /// <summary>请求体加密（_csap_encode_body：固定 dict 按 key 排序 compact 序列化的等价物 = 直接手写串）。</summary>
    private static string EncodeBody(string plainJsonSorted)
    {
        var ct = AesCbc(Pkcs7Pad(Encoding.UTF8.GetBytes(plainJsonSorted)), encrypt: true);
        return Convert.ToHexString(ct); // HEX 大写
    }

    private static string? DecodeResponseField(JsonObject envelope)
    {
        if (envelope["ZTE_Security_Params"] is JsonValue v && v.TryGetValue<string>(out var hex) && hex.Length > 0)
        {
            try
            {
                var plain = AesCbc(Convert.FromHexString(hex), encrypt: false);
                // PKCS7 去尾
                if (plain.Length > 0)
                {
                    int pad = plain[^1];
                    if (pad is >= 1 and <= 16 && pad <= plain.Length) plain = plain[..^pad];
                }
                return Encoding.UTF8.GetString(plain);
            }
            catch { return null; }
        }
        return null;
    }

    /// <summary>密码加密（_csap_encrypt_password）。</summary>
    private static string EncryptPassword(string password)
    {
        // urllib.parse.quote(password, safe="-_.~")
        var sb = new StringBuilder();
        foreach (var b in Encoding.UTF8.GetBytes(password))
        {
            char c = (char)b;
            if (char.IsAsciiLetterOrDigit(c) || c == '-' || c == '_' || c == '.' || c == '~') sb.Append(c);
            else sb.Append('%').Append(((int)b).ToString("X2", CultureInfo.InvariantCulture));
        }
        var enc = AesEcb192(Pkcs7Pad(Encoding.UTF8.GetBytes(sb.ToString())));
        return Convert.ToBase64String(enc).Replace("+", "%2B", StringComparison.Ordinal);
    }

    private static string Q(string s) => Uri.EscapeDataString(s);

    /// <summary>
    /// CSAP 完整开机流程（_csap_start_desktop）：sysConfig → getToken → getDesktopList →
    /// startDesktop →（无 connectStr 时）async_query 轮询 60s/3s。返回 (ok, message)。
    /// </summary>
    public static async Task<(bool Ok, string Message)> BootAsync(CagFirmAuth firm, int timeoutSec = 30, CancellationToken ct = default)
    {
        string cagHost = firm.EffectiveCagHost;
        int cagPort = firm.EffectiveCagPort;
        string vmcHost = firm.EffectiveVmcHost;
        int vmcPort = firm.EffectiveVmcPort;
        string vmUserName = firm.VmUserName;
        string vmPassword = firm.VmPassword;
        string vmId = firm.VmId;
        if (cagHost == "" || vmUserName == "" || vmId == "")
            throw new InvalidOperationException("CSAP 开机材料缺失（cagIp/vmUserName/vmId 为空）");

        string baseUrl = $"https://{cagHost}:{cagPort}";
        string traceId = YdpcBin.HexLower(RandomNumberGenerator.GetBytes(16));
        string serialNum = Guid.NewGuid().ToString();
        int parentCounter = 0;

        using var handler = new HttpClientHandler
        {
            UseProxy = false,                       // 母本 trust_env=False
            UseCookies = false,
            AutomaticDecompression = System.Net.DecompressionMethods.None,
            // 母本 verify=False：CAG 私有证书不校验
            ServerCertificateCustomValidationCallback = static (_, _, _, _) => true,
        };
        using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(Math.Max(10, timeoutSec)) };

        Dictionary<string, string> MakeHeaders()
        {
            parentCounter++;
            return new Dictionary<string, string>
            {
                ["Content-Type"] = "application/xml",
                ["X-Ap-sHost"] = $"{vmcHost}:{vmcPort}",
                ["process_id"] = "2",
                ["serialNum"] = serialNum,
                ["otlp_trace_id"] = traceId,
                ["otlp_parent_id"] = parentCounter.ToString("x16", CultureInfo.InvariantCulture),
                ["Connection"] = "keep-alive",
            };
        }

        async Task<JsonObject> CsapPostAsync(string action, string query, string bodyPlainJson, CancellationToken lct)
        {
            string url = baseUrl + "/cs/" + action + (query.Length > 0 ? "?" + query : "");
            using var req = new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = new StringContent(EncodeBody(bodyPlainJson), Encoding.UTF8, "application/xml"),
            };
            foreach (var kv in MakeHeaders()) req.Headers.TryAddWithoutValidation(kv.Key, kv.Value);
            using var resp = await http.SendAsync(req, lct).ConfigureAwait(false);
            string raw = await resp.Content.ReadAsStringAsync(lct).ConfigureAwait(false);
            var envelope = JsonNode.Parse(raw) as JsonObject
                ?? throw new InvalidOperationException($"CSAP {action} 响应非 JSON: {raw[..Math.Min(200, raw.Length)]}");
            var decoded = DecodeResponseField(envelope);
            if (decoded != null)
            {
                var inner = JsonNode.Parse(decoded) as JsonObject;
                if (inner != null) return inner;
            }
            return envelope;
        }

        try
        {
            // 1. sysConfig
            var q1 = $"version={Q(Version)}&language=zh&requestFrom=9&name={Q(vmUserName)}&RspSecurity=1";
            await CsapPostAsync("cs_sysConfig.action", q1, "", ct).ConfigureAwait(false);

            // 2. getToken（body 四键按 sort_keys 序：clienttype/hardware/nettype/ostype）
            string encPw = EncryptPassword(vmPassword);
            var q2 = $"username={Q(vmUserName)}&password={encPw}&version={Q(Version)}"
                + "&language=zh&clientId=&encrypt=4&token=&requestFrom=9"
                + $"&mac={Mac}&clientIp={ClientIp}"
                + $"&hostName={Q(HostName)}"
                + "&newVersionCtrl=1&netflags=1&unityType=1&isvm=0&RspSecurity=1";
            var tokenResp = await CsapPostAsync("cs_getToken.action", q2,
                "{\"clienttype\":5,\"hardware\":25,\"nettype\":2,\"ostype\":10}", ct).ConfigureAwait(false);
            string tokenResult = tokenResp["result"] is JsonValue rv ? rv.ToJsonString().Trim('"') : "";
            if (tokenResult != "0")
            {
                string mesg = tokenResp["mesg"] is JsonValue mv ? mv.ToJsonString().Trim('"') : tokenResult;
                return (false, $"getToken failed: {mesg}");
            }
            string accessToken = tokenResp["accessToken"] is JsonValue av ? av.ToJsonString().Trim('"') : "";
            if (accessToken == "") return (false, "getToken 未返回 accessToken");

            // 3. getDesktopList
            var q3 = $"accessToken={Q(accessToken)}&type=7&version={Q(Version)}"
                + $"&language=zh&clientIp={ClientIp}&requestFrom=9&isvm=0&RspSecurity=1";
            var listResp = await CsapPostAsync("cs_getDesktopList.action", q3, "", ct).ConfigureAwait(false);
            string listResult = listResp["result"] is JsonValue lv ? lv.ToJsonString().Trim('"') : "";
            if (listResult != "0")
            {
                string mesg = listResp["mesg"] is JsonValue mv ? mv.ToJsonString().Trim('"') : listResult;
                return (false, $"getDesktopList failed: {mesg}");
            }
            JsonObject? desktop = null;
            if (listResp["desktopList"] is JsonArray arr)
            {
                foreach (var n in arr)
                {
                    if (n is not JsonObject d) continue;
                    string vmIdHere = d["vmId"] is JsonValue vv ? vv.ToJsonString().Trim('"') : "";
                    if (vmIdHere == vmId) { desktop = d; break; }
                    desktop ??= d;
                }
            }
            if (desktop == null) return (false, "no desktop found");

            int userId = desktop["userId"] is JsonValue uv && uv.TryGetValue<int>(out var u1) ? u1 : 0;
            int groupId = desktop["groupId"] is JsonValue gv && gv.TryGetValue<int>(out var g1) ? g1 : -1;
            int poolId = desktop["poolId"] is JsonValue pv && pv.TryGetValue<int>(out var p1) ? p1 : 0;
            int connectionType = desktop["connectionType"] is JsonValue ctv && ctv.TryGetValue<int>(out var c1) ? c1 : 0;
            int desktopType = desktop["desktopType"] is JsonValue dtv && dtv.TryGetValue<int>(out var d1) ? d1 : 1;
            string desktopUuid = desktop["uuid"] is JsonValue uv2 ? uv2.ToJsonString().Trim('"') : "";

            // 4. startDesktop（参数全在 query string，body 为空）
            var q4 = $"accessToken={Q(accessToken)}"
                + $"&uuid={Q(desktopUuid)}"
                + $"&vmid={Q(vmId)}"
                + $"&type={desktopType.ToString(CultureInfo.InvariantCulture)}&connectionType={connectionType.ToString(CultureInfo.InvariantCulture)}"
                + $"&assignRelationtoString={Q($"{userId.ToString(CultureInfo.InvariantCulture)},{groupId.ToString(CultureInfo.InvariantCulture)},{poolId.ToString(CultureInfo.InvariantCulture)}")}"
                + $"&version={Q(Version)}&language=zh&requestFrom=9"
                + "&isvm=0&encryption=1&prover=1&supportAsync=1&allowSwitchRap=1"
                + $"&raptype={(connectionType == 0 ? 2 : 1).ToString(CultureInfo.InvariantCulture)}&netType=2"
                + $"&SNcode={Q(SnCode)}"
                + $"&hostName={Q(HostName)}"
                + $"&localipandmac={Q($"{ClientIp},{Mac}")}"
                + $"&diskNo={Q(SnCode)}"
                + "&newpara=1&newcharsetparse=1&upmnew=1&watermarkType=1"
                + "&allowExtUSBPolicy=1&verifyTerminalBind=11"
                + "&supportCustomConfig=00000000000000000000000000000011&RspSecurity=1";
            var startResp = await CsapPostAsync("cs_startDesktop.action", q4, "", ct).ConfigureAwait(false);
            string startResult = startResp["result"] is JsonValue sv ? sv.ToJsonString().Trim('"') : "";
            if (startResult != "0")
            {
                string mesg = startResp["mesg"] is JsonValue mv ? mv.ToJsonString().Trim('"') : startResult;
                return (false, $"startDesktop: {mesg}");
            }
            bool hasConnectStr = startResp["connectStr"] is JsonValue cv2 && cv2.ToJsonString().Trim('"') != "";
            if (hasConnectStr) return (true, "ok");

            // 5. async_query 轮询（60s，间隔 3s；nextQueryTimeInterval 与 3s 取差的母本节拍）
            var deadline = DateTime.UtcNow.AddSeconds(60);
            while (DateTime.UtcNow < deadline)
            {
                await Task.Delay(TimeSpan.FromSeconds(3), ct).ConfigureAwait(false);
                var q5 = $"accessToken={Q(accessToken)}&language=zh&isvm=0&vmid={Q(vmId)}"
                    + "&RspSecurity=1&prover=1&allowSwitchRap=1";
                JsonObject qr;
                try { qr = await CsapPostAsync("cs_startDesktop_async_query.action", q5, "", ct).ConfigureAwait(false); }
                catch { continue; }
                bool hasStr = qr["connectStr"] is JsonValue qcv && qcv.ToJsonString().Trim('"') != "";
                if (hasStr) return (true, "ok");
            }
            return (true, "startDesktop sent (poll timeout)");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception e)
        {
            return (false, e.Message);
        }
    }
}
