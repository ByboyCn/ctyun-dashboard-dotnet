// =============================================================================
// CtyunDashboard.Ydpc / CagClient.cs
// =============================================================================
// 对齐参考实现（Node.js，只读）：
//   · app/ydpc/cag_client.js      —— ZTEC CAG TCP 三阶段握手（控制面握手持留）
//   · app/ydpc/zte_cag_tls.js     —— IPv4 / TLS 长会话数据面（178B 头 → conv → 220B blob
//                                    → 36B ack → 同 socket 升 TLS → CAGMux → raw SPICE
//                                    → 子通道 → display type=3 心跳保活）
//   · app/ydpc/zte_cag_raw.js     —— buildCagAuthBlob / ipv4ToBytes / ipv6ToBytes /
//                                    buildCagAuthHeadShort / raw-ZTEC 预热与 HB（被 tls 版引用）
//   · app/ydpc/product_route.js   —— isIpv4Literal / resolveInnerRoute / resolveVmRoute
//                                    （纯函数，本文件只移植 CAG 需要的三小段）
//
// 逐函数对齐清单：
//   cag_client.js                    → 本文件
//   ─────────────────────────────────────────────────────────────────────────
//   CAG_MAGIC / AUTH_TYPE_RADIUS     → CagMagic / AuthTypeRadius
//   ipTo16Bytes()                    → IpTo16Bytes()
//   deriveAesKeyIv()                 → DeriveAesKeyIv()（键序/大小写/字节序逐字对齐）
//   cagAesEncrypt()                  → CagAesEncrypt()（AES-128/256 ECB|CBC，ZeroPadding 手工补零）
//   xorWithKey99()                   → XorWithKey99()
//   buildZtecStage1()                → BuildZtecStage1()（50B = 6B 魔数 + 44B 载荷）
//   parseZtecStage2()                → ParseZtecStage2()（serverKey@payload[4]、flags@payload[40]）
//   buildZtecStage3Radius()          → BuildZtecStage3Radius()（220B：port/ip64/encUser/encPwd）
//   performCagAuthHold()             → CagClient.AuthHoldAsync()（含「没材料先拒绝」防线）
//                                      HandshakeAsync() 返回活会话句柄（心跳 = 4B 空 DATA 帧）
//
//   zte_cag_tls.js                   → 本文件
//   ─────────────────────────────────────────────────────────────────────────
//   buildCagAuthHeadLong()           → BuildCagAuthHeadLong()（178B）
//   packFrame() / newZteLinkUuid()   → CagMux.PackFrame() / NewZteLinkUuid()
//   buildCagProxyAddLinkPacket()     → BuildCagProxyAddLinkPacket()（4 + 0x9a）
//   CagMuxLink / CagMux              → CagMuxLink / CagMux（4B 头 [cmd][linkID][u16len LE]）
//   buildRawMainREDQ()               → BuildRawMainRedq()（729B）
//   buildRawChannelREDQ()            → BuildRawChannelRedq()（按通道形状表）
//   buildTerminalInfoMessage() 等    → BuildTerminalInfoMessage()/DisplayInit/InputInit/Heartbeat
//   RawState.readMessage/autoReply   → RawSpiceState.ReadMessageAsync/AutoReplyAsync（8B ZTE 前缀 + 5B 后缀）
//   rawMainHandshake()               → RawMainHandshakeAsync()（REDQ → 128B 零 ticket → MAIN_INIT → attach → client_info）
//   setupSubChannels()               → SetupSubChannelsAsync()（先全开 7 条再认证，防 linkId 错位）
//   keepaliveRawSpiceLoop()          → CagTlsSession.RunKeepaliveLoopAsync()（25s tick + 21Hz display 心跳）
//   dialCagTcpTls(Once)()            → CagClient.DialTlsAsync()（严格校验先行；命中证书链缺陷白名单
//                                      才允许整条重拨放宽一次，降级必留证 host+错误码）
//   runTlsSpiceSession()             → DialTlsAsync() + CagTlsSession
//
// TLS 校验差异说明（诚实记录）：
//   JS 侧的降级判据是 OpenSSL 错误码（UNABLE_TO_VERIFY_LEAF_SIGNATURE 等）。.NET SslStream
//   抛的是 SslPolicyErrors/AuthenticationException，文本与 OpenSSL 不同 —— 本文件用语义子串
//   映射到同一套白名单代号，映射不到的一律原样上抛、绝不放宽。
//
// NativeAOT：全文件零反射、零序列化；字节构造全部手写偏移（与抓包布局一致）。
// =============================================================================

using System.Globalization;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace CtyunDashboard.Ydpc;

/// <summary>读超时（对齐 JS err.code='ETIMEDOUT' 语义：保活循环把读超时当常态）。</summary>
public sealed class YdpcTimeoutException : Exception
{
    public string Code { get; } = "ETIMEDOUT";
    public YdpcTimeoutException(string message) : base(message) { }
}

/// <summary>机器根本没下发 CAG 材料（cagIp 缺失）——「本次没做事」，不是链路故障（对齐 err.code='CAG_MATERIAL_MISSING'）。</summary>
public sealed class CagMaterialMissingException : Exception
{
    public string Code { get; } = "CAG_MATERIAL_MISSING";
    public CagMaterialMissingException(string message) : base(message) { }
}

// -----------------------------------------------------------------------------
// product_route.js 移植：地址族判定与底座路由（纯函数）
// -----------------------------------------------------------------------------
public enum CagInnerPath { Raw, Tls, Reject }
public enum CagRouteKind { Zte, Scg, Unknown }

public static class CagRoute
{
    /// <summary>对齐 product_route.js isIpv4Literal()：点分四段十进制，纯手写字符判定。</summary>
    public static bool IsIpv4Literal(string? s)
    {
        if (string.IsNullOrEmpty(s)) return false;
        string[] parts = s.Split('.');
        if (parts.Length != 4) return false;
        foreach (string p in parts)
        {
            if (p.Length < 1 || p.Length > 3) return false;
            foreach (char c in p)
            {
                if (c < '0' || c > '9') return false;
            }
            if (long.Parse(p, CultureInfo.InvariantCulture) > 255) return false;
        }
        return true;
    }

    /// <summary>对齐 resolveInnerRoute()：内层主机含 ':' ⇒ IPv6 raw；点分四段 ⇒ IPv4 TLS；其余拒绝。</summary>
    public static (CagInnerPath Path, string Family, string Reason) ResolveInnerRoute(string? innerHost)
    {
        string host = (innerHost ?? "").Trim();
        if (host.Length == 0) return (CagInnerPath.Reject, "unknown", "connectStr 未解出内层主机");
        string bare = host.Contains('%') ? host[..host.IndexOf('%')] : host;
        if (bare.Contains(':')) return (CagInnerPath.Raw, "ipv6", "内层主机为 IPv6 字面量 ⇒ raw ZTEC 通道");
        if (IsIpv4Literal(bare)) return (CagInnerPath.Tls, "ipv4", "内层主机为 IPv4 字面量 ⇒ TLS + CAGMux + raw SPICE 通道");
        return (CagInnerPath.Reject, "unknown", $"内层主机既非 IPv4 也非 IPv6 字面量（{host}），拒绝猜测通道");
    }

    /// <summary>对齐 resolveVmRoute()：spuCode 前缀优先（zte-* / sc-cloud-pc），回退 firm-auth 字段规则，判不出 ⇒ UNKNOWN 拒绝猜测。</summary>
    public static (CagRouteKind Kind, bool Supported, string Source, string Reason) ResolveVmRoute(string? spuCode, CagFirmAuth? firmAuth)
    {
        string spu = (spuCode ?? "").Trim();
        string spuText = spu.Length > 0 ? $"spuCode={spu}" : "spuCode 为空";

        if (spu.StartsWith("zte-", StringComparison.OrdinalIgnoreCase) || spu.StartsWith("zte_", StringComparison.OrdinalIgnoreCase))
            return (CagRouteKind.Zte, true, "spuCode", spuText);
        if (spu.StartsWith("sc-cloud-pc", StringComparison.OrdinalIgnoreCase) || spu.StartsWith("sc_cloud_pc", StringComparison.OrdinalIgnoreCase))
            return (CagRouteKind.Scg, true, "spuCode", $"{spuText}（SCG 通道：不引入 CEM/第三方客户端身份，直接用 firm-auth 下发的 scgIp/scAuthCode）");

        if (firmAuth != null)
        {
            bool hasScg = !string.IsNullOrEmpty(firmAuth.ScAuthCode) && string.IsNullOrEmpty(firmAuth.CagIp);
            bool hasZte = !string.IsNullOrEmpty(firmAuth.CagIp) || !string.IsNullOrEmpty(firmAuth.VmUserName) || !string.IsNullOrEmpty(firmAuth.VmcIp);
            string suffix = spu.Length > 0 ? $"（{spuText} 未登记，回退 firm-auth）" : "";
            if (hasScg) return (CagRouteKind.Scg, true, "firmAuth", $"scAuthCode 非空且 cagIp 为空{suffix}（SCG 通道：走 firm-auth 的 scgIp/scAuthCode）");
            if (hasZte) return (CagRouteKind.Zte, true, "firmAuth", $"firm-auth 字段齐备{suffix}");
        }

        string source = spu.Length > 0 ? "spuCode" : (firmAuth != null ? "firmAuth" : "none");
        return (CagRouteKind.Unknown, false, source, $"{spuText}、firm-auth 字段均不足 —— 拒绝猜测底座");
    }
}

// -----------------------------------------------------------------------------
// firm-auth 凭据载体（来自 SOHO /cc/getFirmAuth/v1 的 data）
// -----------------------------------------------------------------------------
public sealed class CagFirmAuth
{
    public string CagIp { get; init; } = "";
    public string CagHost { get; init; } = "";
    public int CagPort { get; init; }
    public string VmcIp { get; init; } = "";
    public string VmcHost { get; init; } = "";
    public int VmcPort { get; init; }
    public string VmUserName { get; init; } = "";
    public string VmPassword { get; init; } = "";
    public string VmId { get; init; } = "";
    public string ScAuthCode { get; init; } = "";
    public string ScgIp { get; init; } = "";
    public int ScgTcpPort { get; init; }
    public string ConnectStr { get; init; } = "";

    public static CagFirmAuth FromJson(JsonElement el)
    {
        static string S(JsonElement e, string n) =>
            e.ValueKind == JsonValueKind.Object && e.TryGetProperty(n, out JsonElement p)
                ? p.ValueKind switch { JsonValueKind.String => p.GetString() ?? "", JsonValueKind.Number => p.GetRawText(), _ => "" }
                : "";
        static int I(JsonElement e, string n)
        {
            if (e.ValueKind != JsonValueKind.Object || !e.TryGetProperty(n, out JsonElement p)) return 0;
            if (p.ValueKind == JsonValueKind.Number) return p.TryGetInt32(out int v) ? v : 0;
            if (p.ValueKind == JsonValueKind.String && int.TryParse(p.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out int v2)) return v2;
            return 0;
        }
        return new CagFirmAuth
        {
            CagIp = S(el, "cagIp"),
            CagHost = S(el, "cagHost"),
            CagPort = I(el, "cagPort"),
            VmcIp = S(el, "vmcIp"),
            VmcHost = S(el, "vmcHost"),
            VmcPort = I(el, "vmcPort"),
            VmUserName = S(el, "vmUserName"),
            VmPassword = S(el, "vmPassword"),
            VmId = S(el, "vmId"),
            ScAuthCode = S(el, "scAuthCode"),
            ScgIp = S(el, "scgIp"),
            ScgTcpPort = I(el, "scgTcpPort"),
            ConnectStr = S(el, "connectStr")
        };
    }

    /// <summary>对齐 performCagAuthHold：String(a.cagIp || a.cagHost || '').trim()。</summary>
    public string EffectiveCagHost => (FirstNonEmpty(CagIp, CagHost)).Trim();
    public int EffectiveCagPort => CagPort > 0 ? CagPort : 8899;
    public string EffectiveVmcHost => FirstNonEmpty(VmcIp, VmcHost, EffectiveCagHost);
    public int EffectiveVmcPort => VmcPort > 0 ? VmcPort : (CagPort > 0 ? CagPort : 8899);

    private static string FirstNonEmpty(params string[] vals)
    {
        foreach (string v in vals) if (!string.IsNullOrEmpty(v)) return v;
        return "";
    }
}

// -----------------------------------------------------------------------------
// 经典三阶段握手（cag_client.js）
// -----------------------------------------------------------------------------
public sealed record CagAuthHoldResult(bool Success, int CagCode, string Message);

public sealed record CagKeepaliveCounters(
    long Messages, long AutoReplies, long Ticks, long Errors, long Heartbeats, long DisplayType3HeartbeatFrames, int HeartbeatHz);

public sealed record CagRawKeepaliveCounters(long HbSent, long HbRecv, bool Ok, long LinksSent, long DataSent, long PrimeRecv, string? Error);

/// <summary>经典三阶段握手成功后的会话句柄：连接保持打开，可发 raw-ZTEC 4B 心跳。</summary>
public sealed class CagSession : IAsyncDisposable
{
    private readonly TcpClient _tcp;
    private readonly NetworkStream _stream;
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    public string Host { get; }
    public int Port { get; }
    public int CagCode { get; } = 200;

    internal CagSession(TcpClient tcp, string host, int port)
    {
        _tcp = tcp;
        _stream = tcp.GetStream();
        Host = host;
        Port = port;
    }

    /// <summary>
    /// 心跳：发送 4B 空 CAG DATA 帧 `0a 00 00 00`（对齐 zte_cag_raw.js ZTEC_RAW_HB / keepaliveRawZtecLoop）。
    /// 注：这是 raw-ZTEC 数据面的官方心跳帧；控制面握手持留期间发送它属于冗余但无害的保活流量。
    /// </summary>
    public async Task HeartbeatAsync(CancellationToken ct = default)
    {
        byte[] hb = { 0x0a, 0x00, 0x00, 0x00 };
        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try { await _stream.WriteAsync(hb, ct).ConfigureAwait(false); }
        finally { _writeLock.Release(); }
    }

    /// <summary>对齐 performCagAuthHold 的 hold：静默保持 N 秒（连接由调用方 Dispose）。</summary>
    public async Task HoldAsync(int seconds, CancellationToken ct = default)
    {
        if (seconds > 0) await Task.Delay(TimeSpan.FromSeconds(seconds), ct).ConfigureAwait(false);
    }

    public ValueTask DisposeAsync()
    {
        _writeLock.Dispose();
        _stream.Dispose();
        ((IDisposable)_tcp).Dispose();
        return ValueTask.CompletedTask;
    }
}

// -----------------------------------------------------------------------------
// 拨号参数（TLS / raw 数据面共用）
// -----------------------------------------------------------------------------
public sealed class CagTlsDialOptions
{
    public string OuterHost { get; set; } = "";
    public int OuterPort { get; set; }
    public string InnerHost { get; set; } = "";
    public int InnerPort { get; set; }
    /// <summary>connectStr 的 --proxy-sport（IPv4 blob 的 port 字段取它）。</summary>
    public int ProxySport { get; set; }
    public string VmId { get; set; } = "";
    /// <summary>connectStr 的 -k 会话密钥（raw SPICE REDQ 用）。</summary>
    public string Key { get; set; } = "";
    public string? TraceId { get; set; }
    public int TimeoutMs { get; set; } = 15000;
    /// <summary>证书链缺陷白名单命中时允许整条重拨放宽一次（对齐受控降级；默认开）。</summary>
    public bool AllowInsecureFallback { get; set; } = true;
}

// -----------------------------------------------------------------------------
// ZTEC 帧 / AES 构造（纯函数，cag_client.js + zte_cag_raw.js）
// -----------------------------------------------------------------------------
public static class CagProtocol
{
    public const int AuthTypeRadius = 1;

    /// <summary>'ZTEC,\0' —— 6 字节（cag_client.js CAG_MAGIC）。</summary>
    public static readonly byte[] CagMagic = { (byte)'Z', (byte)'T', (byte)'E', (byte)'C', (byte)',', 0x00 };

    /// <summary>对齐 ipTo16Bytes()：IPv4 点分四段填 [0:4]，其余一律 16 字节零。</summary>
    public static byte[] IpTo16Bytes(string host)
    {
        var buf = new byte[16];
        string[]? parts = CagRoute.IsIpv4Literal(host) ? host.Split('.') : null;
        if (parts != null)
        {
            for (int i = 0; i < 4; i++) buf[i] = (byte)long.Parse(parts[i], CultureInfo.InvariantCulture);
        }
        return buf;
    }

    /// <summary>
    /// 对齐 deriveAesKeyIv()（逐字节同源）：
    ///   mixedClient = clientKey &amp; 0xABACACAB；mixedServer = serverKey | 0x98979798；
    ///   key = hex8(clientKey)+hex8(serverKey)+hex(ms0)+hex(ms3)+hex(ms2)+hex(ms1)+hex(b3)+hex(b1)+hex(b0)+hex(b2)（前 32B）；
    ///   iv  = "02x"+HEX(b0)+HEX(b1)+hex(b3)+"02x"+hex(ms2)+hex(ms3)（16B，b0/b1 大写、其余小写）。
    /// </summary>
    public static (byte[] Key, byte[] Iv) DeriveAesKeyIv(uint clientKey, uint serverKey)
    {
        uint mixedClient = clientKey & 0xABACACABu;
        uint mixedServer = serverKey | 0x98979798u;

        byte b0 = (byte)(mixedClient & 0xFF);
        byte b1 = (byte)((mixedClient >> 8) & 0xFF);
        byte b2 = (byte)((mixedClient >> 16) & 0xFF);
        byte b3 = (byte)((mixedClient >> 24) & 0xFF);
        byte ms0 = (byte)(mixedServer & 0xFF);
        byte ms1 = (byte)((mixedServer >> 8) & 0xFF);
        byte ms2 = (byte)((mixedServer >> 16) & 0xFF);
        byte ms3 = (byte)((mixedServer >> 24) & 0xFF);

        static string Hex8(uint v) => v.ToString("x8", CultureInfo.InvariantCulture);
        static string H(byte b) => b.ToString("x2", CultureInfo.InvariantCulture);

        string keyStr =
            Hex8(clientKey) + Hex8(serverKey) +
            H(ms0) + H(ms3) + H(ms2) + H(ms1) +
            H(b3) + H(b1) + H(b0) + H(b2);
        string ivStr =
            "02x" + b0.ToString("X2", CultureInfo.InvariantCulture) +
            b1.ToString("X2", CultureInfo.InvariantCulture) +
            H(b3) + "02x" + H(ms2) + H(ms3);

        byte[] key = Encoding.ASCII.GetBytes(keyStr)[..32];
        byte[] iv = Encoding.ASCII.GetBytes(ivStr)[..16];
        return (key, iv);
    }

    /// <summary>对齐 cagAesEncrypt()：手工补零到 16 的倍数；aesFlag&amp;1 ⇒ 256bit，aesFlag&amp;0x100 ⇒ CBC 否则 ECB；无内置填充。</summary>
    public static byte[] CagAesEncrypt(byte[] plaintext, uint clientKey, uint serverKey, int aesFlag)
    {
        (byte[] keyMaterial, byte[] iv) = DeriveAesKeyIv(clientKey, serverKey);
        int bits = (aesFlag & 1) != 0 ? 256 : 128;
        byte[] key = keyMaterial[..(bits / 8)];

        byte[] padded = plaintext;
        if (padded.Length % 16 != 0)
        {
            int padLen = 16 - padded.Length % 16;
            var grown = new byte[padded.Length + padLen];
            Buffer.BlockCopy(padded, 0, grown, 0, padded.Length);
            padded = grown;
        }

        using Aes aes = Aes.Create();
        aes.Mode = (aesFlag & 0x100) != 0 ? CipherMode.CBC : CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        aes.Key = key;
        if (aes.Mode == CipherMode.CBC) aes.IV = iv;
        using ICryptoTransform enc = aes.CreateEncryptor();
        return enc.TransformFinalBlock(padded, 0, padded.Length);
    }

    /// <summary>对齐 xorWithKey99()。</summary>
    public static byte[] XorWithKey99(byte[] buf)
    {
        var outBuf = new byte[buf.Length];
        for (int i = 0; i < buf.Length; i++) outBuf[i] = (byte)(buf[i] ^ 99);
        return outBuf;
    }

    /// <summary>对齐 buildZtecStage1()：6B 魔数 + 44B 载荷 = 50B。</summary>
    public static byte[] BuildZtecStage1(string vmId, uint clientKey)
    {
        var kmBuf = new byte[16];
        byte[] vm = Encoding.ASCII.GetBytes(vmId.Length > 16 ? vmId[..16] : vmId);
        Buffer.BlockCopy(vm, 0, kmBuf, 0, Math.Min(16, vm.Length));

        var payload = new byte[44];
        YdpcBin.W32LE(payload, 0, (uint)(AuthTypeRadius + 100)); // 101
        YdpcBin.W32LE(payload, 4, clientKey);
        YdpcBin.W32LE(payload, 8, 220);
        Buffer.BlockCopy(kmBuf, 0, payload, 12, 16);
        // [28:40] 保持零
        YdpcBin.W32LE(payload, 40, 0x03);
        return YdpcBin.Concat(CagMagic, payload);
    }

    /// <summary>对齐 parseZtecStage2()：跳 6B 魔数，serverKey=u32le@4、flags=u32le@40；aesFlag = flags&amp;1?2:1，flags&amp;2 ⇒ |0x100。</summary>
    public static (uint ServerKey, int AesFlag) ParseZtecStage2(byte[] blob)
    {
        if (blob.Length < 50) throw new InvalidOperationException($"Stage 2 expected 50 bytes, got {blob.Length}");
        ReadOnlySpan<byte> payload = blob.AsSpan(6);
        uint serverKey = YdpcBin.U32LE(payload, 4);
        uint flags = YdpcBin.U32LE(payload, 40);
        int aesFlag = (flags & 1) != 0 ? 2 : 1;
        if ((flags & 2) != 0) aesFlag |= 0x100;
        return (serverKey, aesFlag);
    }

    /// <summary>对齐 buildZtecStage3Radius()：220B = u16le port@0 + ip16@4 + AES(user64)@60 + AES(xor99(pwd64))@124。</summary>
    public static byte[] BuildZtecStage3Radius(
        string destHost, int destPort, string username, string password, uint clientKey, uint serverKey, int aesFlag)
    {
        var usernameBuf = new byte[64];
        byte[] u = Encoding.ASCII.GetBytes(username.Length > 63 ? username[..63] : username);
        Buffer.BlockCopy(u, 0, usernameBuf, 0, Math.Min(63, u.Length));

        var passwordBuf = new byte[64];
        byte[] p = Encoding.ASCII.GetBytes(password.Length > 63 ? password[..63] : password);
        Buffer.BlockCopy(p, 0, passwordBuf, 0, Math.Min(63, p.Length));

        var pkt = new byte[220];
        YdpcBin.W16LE(pkt, 0, (ushort)(destPort & 0xFFFF));
        Buffer.BlockCopy(IpTo16Bytes(destHost), 0, pkt, 4, 16);

        byte[] encUser = CagAesEncrypt(usernameBuf, clientKey, serverKey, aesFlag);
        Buffer.BlockCopy(encUser, 0, pkt, 60, 64);

        byte[] encPwd = CagAesEncrypt(XorWithKey99(passwordBuf), clientKey, serverKey, aesFlag);
        Buffer.BlockCopy(encPwd, 0, pkt, 124, 64);
        return pkt;
    }

    // -----------------------------------------------------------------------
    // zte_cag_raw.js：短头 / blob / 字节族转换
    // -----------------------------------------------------------------------

    /// <summary>对齐 buildCagAuthHeadShort()：50B ZTEC 短头（raw IPv6 路径）。</summary>
    public static byte[] BuildCagAuthHeadShort()
    {
        var pkt = new byte[50];
        Encoding.ASCII.GetBytes("ZTEC").CopyTo(pkt, 0);
        YdpcBin.W16LE(pkt, 4, 0x002c);
        YdpcBin.W32LE(pkt, 6, 101);
        RandomNumberGenerator.Fill(pkt.AsSpan(10, 4));   // [10:14] random
        YdpcBin.W32LE(pkt, 14, 0xdc);                        // [14:18] dc 00 00 00
        // [18:34] 保持零
        pkt[34] = 0x03; pkt[35] = 0x00; pkt[36] = 0x8c; pkt[37] = 0x0c;
        // [38:50] 保持零
        return pkt;
    }

    /// <summary>对齐 buildCagAuthHeadLong()：178B ZTEC 长头（IPv4/TLS 路径，官方 199B 包的 [21:]）。</summary>
    public static byte[] BuildCagAuthHeadLong()
    {
        var p = new byte[178];
        Encoding.ASCII.GetBytes("ZTEC").CopyTo(p, 0);
        YdpcBin.W16LE(p, 4, 0x00ac);
        YdpcBin.W32LE(p, 6, 101);
        RandomNumberGenerator.Fill(p.AsSpan(10, 4));     // [10:14] random
        p[14] = 0xdc; p[15] = 0x00; p[16] = 0x00; p[17] = 0x00;
        RandomNumberGenerator.Fill(p.AsSpan(18, 20));    // [18:38] random
        p[38] = 0x07; p[39] = 0x00; p[40] = 0x0b; p[41] = 0x0b;
        // [42:54] 保持零
        byte[] hex32 = RandomNumberGenerator.GetBytes(16);
        Encoding.ASCII.GetBytes(YdpcBin.HexLower(hex32)).CopyTo(p, 54);   // [54:86] 32B ascii hex
        // [86:118] 保持零
        byte[] hex16 = RandomNumberGenerator.GetBytes(8);
        Encoding.ASCII.GetBytes(YdpcBin.HexLower(hex16)).CopyTo(p, 118);  // [118:134] 16B ascii hex
        // [134:178] 保持零
        return p;
    }

    /// <summary>对齐 ipv4ToBytes()：4 字节网络序；非 IPv4 字面量抛错。</summary>
    public static byte[] Ipv4ToBytes(string addr)
    {
        if (!CagRoute.IsIpv4Literal(addr)) throw new ArgumentException($"非法 IPv4 字面量: {addr}");
        string[] parts = addr.Split('.');
        var buf = new byte[4];
        for (int i = 0; i < 4; i++) buf[i] = (byte)long.Parse(parts[i], CultureInfo.InvariantCulture);
        return buf;
    }

    /// <summary>对齐 ipv6ToBytes()：16 字节网络序；支持 :: 压缩与 %zone。</summary>
    public static byte[] Ipv6ToBytes(string addr)
    {
        string bare = addr.Split('%')[0];
        string[] headParts, tailParts;
        int dbl = bare.IndexOf("::", StringComparison.Ordinal);
        if (dbl >= 0)
        {
            string h = bare[..dbl];
            string t = bare[(dbl + 2)..];
            headParts = h.Length > 0 ? h.Split(':') : Array.Empty<string>();
            tailParts = t.Length > 0 ? t.Split(':') : Array.Empty<string>();
        }
        else
        {
            headParts = bare.Split(':');
            tailParts = Array.Empty<string>();
        }
        int missing = 8 - headParts.Length - tailParts.Length;
        if (missing < 0) throw new ArgumentException($"非法 IPv6 地址: {addr}");
        var parts = new List<string>(headParts);
        for (int i = 0; i < missing; i++) parts.Add("0");
        parts.AddRange(tailParts);
        if (parts.Count != 8) throw new ArgumentException($"IPv6 段数异常: {addr}");
        var buf = new byte[16];
        for (int i = 0; i < 8; i++)
        {
            string seg = parts[i].Length == 0 ? "0" : parts[i];
            if (seg.Length is < 1 or > 4 || !IsHex(seg)) throw new ArgumentException($"非法 IPv6 段: {seg}");
            ushort v = ushort.Parse(seg, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            buf[i * 2] = (byte)(v >> 8);
            buf[i * 2 + 1] = (byte)(v & 0xFF);
        }
        return buf;
    }

    private static bool IsHex(string s)
    {
        foreach (char c in s)
        {
            if (!Uri.IsHexDigit(c)) return false;
        }
        return true;
    }

    /// <summary>对齐 buildCagAuthBlob()（地址族双分支）：[0:4] port LE（v6=innerPort / v4=proxySport）、[4:20] 地址、[20:56] vmId、[60:188] random、[188] family tag。</summary>
    public static byte[] BuildCagAuthBlob(string innerHost, int innerPort, int proxySport, string vmId)
    {
        if (string.IsNullOrEmpty(innerHost) || string.IsNullOrEmpty(vmId)) throw new ArgumentException("auth blob 缺少 innerHost/vmId");
        if (vmId.Length != 36) throw new ArgumentException($"auth blob 需要 36 字节 vmId，实际 {vmId.Length}");

        bool isV6 = innerHost.Contains(':');
        var blob = new byte[220];
        uint portVal;
        if (isV6)
        {
            if (innerPort <= 0) throw new ArgumentException("auth blob (IPv6) 需要 connectStr 的服务端口");
            portVal = (uint)innerPort;
            Buffer.BlockCopy(Ipv6ToBytes(innerHost), 0, blob, 4, 16);
            blob[188] = 0x51; // IPv6 family tag
        }
        else
        {
            if (proxySport <= 0) throw new ArgumentException("auth blob (IPv4) 需要 proxySport（--proxy-sport）");
            portVal = (uint)proxySport;
            Buffer.BlockCopy(Ipv4ToBytes(innerHost), 0, blob, 4, 4); // 只占 [4:8]
            blob[188] = 0x50; // IPv4 family tag
        }
        YdpcBin.W32LE(blob, 0, portVal);
        Encoding.ASCII.GetBytes(vmId).CopyTo(blob, 20);
        RandomNumberGenerator.Fill(blob.AsSpan(60, 128)); // [60:188] random
        return blob;
    }
}

// -----------------------------------------------------------------------------
// CAG proxy 复用层（zte_cag_tls.js CagMux / CagMuxLink）
// -----------------------------------------------------------------------------
public sealed class CagInnerEndpoint
{
    public string Host { get; init; } = "";
    public int Port { get; init; }
}

internal sealed class CagMuxLink
{
    public const int DataCmd = 0x0a;
    public const int AddLinkCmd = 0x1a;
    public const int CloseLinkCmd = 0x2a;
    public const int PayloadMax = 0xffff;

    private readonly CagMux _mux;
    private readonly object _gate = new();
    private readonly List<byte> _rbuf = new();
    private readonly Queue<LinkWaiter> _waiters = new();
    private bool _closed;
    private Exception? _closeErr;

    public int LinkId { get; }
    public byte[] LinkUuid { get; }
    public string TraceId { get; }
    public string SpanId { get; }
    /// <summary>REDQ 用的 span（与 add-link 的 spanId 不同，对齐 randomHex(8)）。</summary>
    public string RedqSpanId { get; } = YdpcBin.HexLower(RandomNumberGenerator.GetBytes(8));

    internal CagMuxLink(CagMux mux, int linkId, byte[] linkUuid, string traceId, string spanId)
    {
        _mux = mux;
        LinkId = linkId;
        LinkUuid = linkUuid;
        TraceId = traceId;
        SpanId = spanId;
    }

    private sealed class LinkWaiter
    {
        public readonly int Want;
        public readonly TaskCompletionSource<byte[]> Tcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public LinkWaiter(int want) { Want = want; }
    }

    /// <summary>对齐 CagMuxLink.readExact：读满恰好 n 字节，超时抛 YdpcTimeoutException(ETIMEDOUT)。</summary>
    public async Task<byte[]> ReadExactAsync(int n, int timeoutMs, CancellationToken ct = default)
    {
        if (n <= 0) return Array.Empty<byte>();
        var waiter = new LinkWaiter(n);
        lock (_gate)
        {
            if (_closed) throw _closeErr ?? new InvalidOperationException($"CAG mux link {LinkId} 已关闭");
            if (_rbuf.Count >= n) return TakeLocked(n);
            _waiters.Enqueue(waiter);
        }

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(timeoutMs);
        try
        {
            return await waiter.Tcs.Task.WaitAsync(timeoutCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            lock (_gate)
            {
                // 从队列摘掉本 waiter（若尚未被 pump 完成）
                var remaining = new Queue<LinkWaiter>(_waiters.Count);
                while (_waiters.Count > 0)
                {
                    LinkWaiter w = _waiters.Dequeue();
                    if (!ReferenceEquals(w, waiter)) remaining.Enqueue(w);
                }
                while (remaining.Count > 0) _waiters.Enqueue(remaining.Dequeue());
            }
            throw new YdpcTimeoutException($"CAG mux link {LinkId} 读取超时（等 {n}B）");
        }
    }

    /// <summary>对齐 CagMuxLink.write：按 0xFFFF 分帧；空数据不发帧。</summary>
    public async Task WriteAsync(byte[] data, CancellationToken ct = default)
    {
        byte[] buf = data ?? Array.Empty<byte>();
        int off = 0;
        while (off < buf.Length)
        {
            int n = Math.Min(buf.Length - off, PayloadMax);
            var chunk = new byte[n];
            Buffer.BlockCopy(buf, off, chunk, 0, n);
            await _mux.WriteFrameAsync(DataCmd, LinkId, chunk, ct).ConfigureAwait(false);
            off += n;
        }
    }

    /// <summary>对齐 takeReadBufferN：从缓冲头部取 n 字节（用于剥离 ZTE 5B 后缀）。</summary>
    public byte[]? TakeReadBufferN(int n)
    {
        if (n <= 0) return Array.Empty<byte>();
        lock (_gate)
        {
            if (_rbuf.Count == 0) return Array.Empty<byte>();
            return TakeLocked(Math.Min(n, _rbuf.Count));
        }
    }

    /// <summary>对齐 discardReadBuffer。</summary>
    public void DiscardReadBuffer()
    {
        lock (_gate) _rbuf.Clear();
    }

    /// <summary>对齐 close：置关闭态、唤醒等待者，随后发 CLOSE 帧（已断开则吞错）。</summary>
    public void Close()
    {
        lock (_gate)
        {
            if (_closed) return;
            _closed = true;
            RejectWaitersLocked(new InvalidOperationException($"CAG mux link {LinkId} 已关闭"));
        }
        try
        {
            _mux.WriteFrameAsync(CloseLinkCmd, LinkId, Array.Empty<byte>(), CancellationToken.None)
                .GetAwaiter().GetResult();
        }
        catch { /* 已断开 */ }
    }

    internal void PushPayload(byte[] payload)
    {
        lock (_gate)
        {
            if (_closed) return;
            _rbuf.AddRange(payload);
            PumpLocked();
        }
    }

    internal void MarkClosed(Exception? err)
    {
        lock (_gate)
        {
            if (_closed) return;
            _closed = true;
            _closeErr = err;
            RejectWaitersLocked(err ?? new InvalidOperationException($"CAG mux link {LinkId} 对端已关闭"));
        }
    }

    private void PumpLocked()
    {
        while (_waiters.Count > 0 && _waiters.Peek().Want <= _rbuf.Count)
        {
            LinkWaiter w = _waiters.Dequeue();
            w.Tcs.TrySetResult(TakeLocked(w.Want));
        }
    }

    private void RejectWaitersLocked(Exception err)
    {
        while (_waiters.Count > 0)
        {
            LinkWaiter w = _waiters.Dequeue();
            w.Tcs.TrySetException(err);
        }
    }

    private byte[] TakeLocked(int n)
    {
        var outBuf = new byte[n];
        _rbuf.CopyTo(0, outBuf, 0, n);
        _rbuf.RemoveRange(0, n);
        return outBuf;
    }
}

public sealed class CagMux : IAsyncDisposable
{
    public const int DataCmd = CagMuxLink.DataCmd;
    public const int AddLinkCmd = CagMuxLink.AddLinkCmd;
    public const int CloseLinkCmd = CagMuxLink.CloseLinkCmd;
    public const int PayloadMax = CagMuxLink.PayloadMax;
    /// <summary>LinkInfo 定长载荷（B 用 0x9a 字节块）。</summary>
    public const int AddLinkPayloadLen = 0x9a;
    /// <summary>LinkInfo[0x53] 的 QoS（官方隧道固定值）。</summary>
    public const byte AddLinkQos = 0x05;

    private readonly Stream _conn;
    private readonly Dictionary<int, CagMuxLink> _links = new();
    private int _nextLinkId = 1;
    private readonly object _gate = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly List<byte> _rx = new();
    private Task? _readLoop;
    private readonly Action<string, string>? _log;

    private CagMux(Stream conn, Action<string, string>? log)
    {
        _conn = conn;
        _log = log;
    }

    private void Log(string level, string msg) => _log?.Invoke(level, msg);

    /// <summary>对齐 CagMux.open：创建 mux 并启动读循环。</summary>
    public static CagMux Open(Stream conn, Action<string, string>? log = null)
    {
        var mux = new CagMux(conn, log);
        mux._readLoop = Task.Run(mux.ReadLoopAsync);
        return mux;
    }

    private async Task ReadLoopAsync()
    {
        var buf = new byte[64 * 1024];
        try
        {
            while (!_cts.IsCancellationRequested)
            {
                int n = await _conn.ReadAsync(buf, _cts.Token).ConfigureAwait(false);
                if (n <= 0) { FailAll(new InvalidOperationException("CAG mux 连接被关闭")); return; }
                // ⚠ 对齐 JS：解析异常必须就地收敛，不能冒成读循环未处理异常
                try { Feed(buf.AsSpan(0, n).ToArray()); }
                catch (Exception e) { FailAll(e); return; }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception e)
        {
            FailAll(e);
        }
    }

    private void Feed(byte[] chunk)
    {
        lock (_gate)
        {
            _rx.AddRange(chunk);
            while (_rx.Count >= 4)
            {
                int cmd = _rx[0];
                int linkId = _rx[1];
                int len = _rx[2] | (_rx[3] << 8);
                if (_rx.Count < 4 + len) break;
                var payload = new byte[len];
                _rx.CopyTo(4, payload, 0, len);
                _rx.RemoveRange(0, 4 + len);
                if (cmd == CloseLinkCmd)
                {
                    if (_links.TryGetValue(linkId, out CagMuxLink? link))
                    {
                        _links.Remove(linkId);
                        link.MarkClosed(null);
                    }
                }
                else if (cmd == DataCmd || (cmd & 0x0f) == DataCmd)
                {
                    if (_links.TryGetValue(linkId, out CagMuxLink? link)) link.PushPayload(payload);
                }
                // 其它 cmd：按官方语义丢弃
            }
        }
    }

    private void FailAll(Exception err)
    {
        List<CagMuxLink> links;
        lock (_gate)
        {
            links = new List<CagMuxLink>(_links.Values);
            _links.Clear();
            _rx.Clear();
        }
        foreach (CagMuxLink l in links) l.MarkClosed(err);
    }

    internal void NotifyLinkWriteFailure(CagMuxLink link, Exception err) => FailAll(err);

    /// <summary>对齐 newZteLinkUuid：16B 随机，置 v4 版本位与 RFC-4122 variant 位。</summary>
    public static byte[] NewZteLinkUuid()
    {
        byte[] b = RandomNumberGenerator.GetBytes(16);
        b[6] = (byte)((b[6] & 0x0f) | 0x40);
        b[8] = (byte)((b[8] & 0x3f) | 0x80);
        return b;
    }

    public static string RandomHex(int n) => YdpcBin.HexLower(RandomNumberGenerator.GetBytes(n));

    /// <summary>对齐 writeCString：C 字符串语义（短则补 NUL，长则截断且不补）。</summary>
    public static void WriteCString(byte[] buf, int offset, int size, string? text)
    {
        if (size <= 0) return;
        byte[] enc = Encoding.UTF8.GetBytes(text ?? "");
        if (enc.Length > size) enc = enc[..size];
        Buffer.BlockCopy(enc, 0, buf, offset, enc.Length);
        if (enc.Length < size) buf[offset + enc.Length] = 0;
    }

    /// <summary>对齐 packFrame：4B 头 [cmd][linkID][u16 len LE] + 载荷。</summary>
    public static byte[] PackFrame(int cmd, int linkId, byte[]? payload)
    {
        byte[] body = payload ?? Array.Empty<byte>();
        if (body.Length > PayloadMax) throw new InvalidOperationException($"CAG proxy 帧载荷过大：{body.Length} > {PayloadMax}");
        var head = new byte[4];
        head[0] = (byte)(cmd & 0xff);
        head[1] = (byte)(linkId & 0xff);
        YdpcBin.W16LE(head, 2, (ushort)body.Length);
        return YdpcBin.Concat(head, body);
    }

    /// <summary>对齐 buildCagProxyAddLinkPacket：4 + 0x9a；port@0、channel@2、IPv4 反序@4、QoS@0x53、主干@0x54、trace/span。</summary>
    public static byte[] BuildCagProxyAddLinkPacket(CagInnerEndpoint inner, int linkId, string traceId, string spanId)
    {
        string host = inner?.Host ?? "";
        int port = inner?.Port ?? 0;
        byte[] addr = CagProtocol.Ipv4ToBytes(host); // 非 IPv4 抛错 —— 调用方必须先过地址族路由
        var payload = new byte[AddLinkPayloadLen];
        YdpcBin.W16LE(payload, 0, (ushort)(port & 0xFFFF));
        payload[2] = linkId == 1 ? (byte)1 : (byte)2;         // 主链路 1 / 子链路 2
        payload[4] = addr[3];
        payload[5] = addr[2];
        payload[6] = addr[1];
        payload[7] = addr[0];
        payload[0x53] = AddLinkQos;
        if (linkId == 1) payload[0x54] = 1;
        WriteCString(payload, 0x68, 0x21, traceId);
        WriteCString(payload, 0x89, 0x11, spanId);
        return PackFrame(AddLinkCmd, linkId, payload);
    }

    /// <summary>对齐 openLink：分配 linkId（按 open 顺序递增）并发 add-link 包。</summary>
    internal async Task<CagMuxLink> OpenLinkAsync(CagInnerEndpoint inner, string? traceId = null, string? spanId = null, CancellationToken ct = default)
    {
        lock (_gate)
        {
            if (_cts.IsCancellationRequested) throw new ObjectDisposedException(nameof(CagMux));
        }
        int linkId = Interlocked.Increment(ref _nextLinkId) - 1;
        var link = new CagMuxLink(
            this, linkId, NewZteLinkUuid(),
            string.IsNullOrEmpty(traceId) ? RandomHex(16) : traceId!,
            string.IsNullOrEmpty(spanId) ? RandomHex(8) : spanId!);
        lock (_gate) _links[linkId] = link;
        try
        {
            byte[] packet = BuildCagProxyAddLinkPacket(inner, linkId, link.TraceId, link.SpanId);
            await WriteFrameRawAsync(packet, ct).ConfigureAwait(false);
        }
        catch (Exception)
        {
            lock (_gate) _links.Remove(linkId);
            throw;
        }
        return link;
    }

    public Task WriteFrameAsync(int cmd, int linkId, byte[]? payload, CancellationToken ct = default) =>
        WriteFrameRawAsync(PackFrame(cmd, linkId, payload), ct);

    private async Task WriteFrameRawAsync(byte[] frame, CancellationToken ct)
    {
        await _conn.WriteAsync(frame, ct).ConfigureAwait(false);
    }

    public int LinkCount { get { lock (_gate) return _links.Count; } }

    public async ValueTask DisposeAsync()
    {
        List<CagMuxLink> links;
        lock (_gate)
        {
            links = new List<CagMuxLink>(_links.Values);
            _links.Clear();
            _rx.Clear();
        }
        foreach (CagMuxLink l in links) l.MarkClosed(new InvalidOperationException("CAG mux 已关闭"));
        _cts.Cancel();
        if (_readLoop != null)
        {
            try { await _readLoop.ConfigureAwait(false); } catch { /* 收尾 */ }
        }
        _cts.Dispose();
        try { _conn.Dispose(); } catch { /* 已断开 */ }
    }
}

// -----------------------------------------------------------------------------
// raw SPICE 帧构造与状态机（zte_cag_tls.js）
// -----------------------------------------------------------------------------
public static class CagSpice
{
    public const string TerminalGuid = "31BF5444-86E0-4D5D-B1AB-A42FFBAC72C9";
    public static readonly byte[] TerminalGuidBytes = Convert.FromHexString("4454BF31E0865D4DB1ABA42FFBAC72C9");
    public const int MainRedqLen = 729;
    public const int RedqReplyMax = 4096;
    public const int RawMsgMax = 1 << 20;
    /// <summary>128B 全零 ticket（无 auth-type 前缀，官方产品隧道线上行为）。</summary>
    public static readonly byte[] RawTicket = new byte[128];

    /// <summary>子通道表 (linkId, channelType, channelId) —— 真机协商结果；主干占 link 1，7 条子通道 link 2..8。</summary>
    public static readonly int[][] SubchannelRedqs =
    {
        new[] { 3, 4, 1 },
        new[] { 2, 6, 0 },
        new[] { 4, 5, 0 },
        new[] { 6, 3, 0 },
        new[] { 7, 2, 0 },
        new[] { 8, 4, 0 },
        new[] { 5, 2, 1 }
    };

    /// <summary>认证成功后写一次的通道初始化消息种类（linkId → kind）。</summary>
    public static readonly IReadOnlyDictionary<int, string> SubchannelInitKind = new Dictionary<int, string>
    {
        { 6, "input" }, { 5, "display" }, { 7, "display" }
    };

    private static void PutU32(byte[] buf, int off, uint v) => YdpcBin.W32LE(buf, off, v);

    private static void WriteCString(byte[] buf, int offset, int size, string? text) => CagMux.WriteCString(buf, offset, size, text);

    /// <summary>对齐 buildRawMainREDQ：729B 主干 REDQ。</summary>
    public static byte[] BuildRawMainRedq(string key, string vmId, byte[]? linkUuid, string traceId, string spanId)
    {
        byte[] uuid = linkUuid is { Length: 16 } ? linkUuid : RandomNumberGenerator.GetBytes(16);
        var redq = new byte[MainRedqLen];
        Encoding.ASCII.GetBytes("REDQ").CopyTo(redq, 0);
        PutU32(redq, 4, 2);
        PutU32(redq, 8, 2);
        PutU32(redq, 12, 713);
        redq[20] = 1;
        PutU32(redq, 22, 1);
        PutU32(redq, 26, 1);
        PutU32(redq, 30, 705);
        PutU32(redq, 42, 0x1400);
        PutU32(redq, 46, 0x10000);
        WriteCString(redq, 50, 45, $"{key ?? ""}{vmId ?? ""}");
        Buffer.BlockCopy(uuid, 0, redq, 95, 16);
        Buffer.BlockCopy(TerminalGuidBytes, 0, redq, 127, 16);
        WriteCString(redq, 159, 33, traceId);
        WriteCString(redq, 192, 17, spanId);
        PutU32(redq, 717, 0x800);
        PutU32(redq, 721, 0x232900);
        return redq;
    }

    /// <summary>对齐 CHANNEL_REDQ_SHAPE / buildRawChannelREDQ：长度随 channelType 变化。</summary>
    public static byte[] BuildRawChannelRedq(
        string key, string vmId, byte[]? linkUuid, string traceId, string spanId,
        int connectionId, int channelType, int channelId)
    {
        (int length, int size, uint[] caps) = channelType switch
        {
            2 => (733, 717, new uint[] { 0xa00, 0xffc30dec, 0x48 }),
            5 => (729, 713, new uint[] { 0x800, 0x0e }),
            6 => (729, 713, new uint[] { 0x800, 0x07 }),
            _ => (725, 709, new uint[] { 0x800 })
        };
        int capCount = channelType == 2 ? 2 : (channelType == 5 || channelType == 6 ? 1 : 0);

        byte[] uuid = linkUuid is { Length: 16 } ? linkUuid : RandomNumberGenerator.GetBytes(16);
        var redq = new byte[length];
        Encoding.ASCII.GetBytes("REDQ").CopyTo(redq, 0);
        PutU32(redq, 4, 2);
        PutU32(redq, 8, 2);
        PutU32(redq, 12, (uint)size);
        PutU32(redq, 16, (uint)connectionId);
        redq[20] = (byte)(channelType & 0xff);
        redq[21] = (byte)(channelId & 0xff);
        PutU32(redq, 22, 1);
        PutU32(redq, 26, (uint)capCount);
        PutU32(redq, 30, 705);
        PutU32(redq, 42, 0x1400);
        PutU32(redq, 46, 0x10000);
        WriteCString(redq, 50, 45, $"{key ?? ""}{vmId ?? ""}");
        Buffer.BlockCopy(uuid, 0, redq, 95, 16);
        WriteCString(redq, 159, 33, traceId);
        WriteCString(redq, 192, 17, spanId);
        int capOff = length - caps.Length * 4;
        for (int i = 0; i < caps.Length; i++) PutU32(redq, capOff + i * 4, caps[i]);
        return redq;
    }

    /// <summary>对齐 buildTerminalInfoMessage：68B（u16le 0x7c + u32le 57 + 36B GUID ascii@11）。</summary>
    public static byte[] BuildTerminalInfoMessage()
    {
        var msg = new byte[68];
        YdpcBin.W16LE(msg, 0, 0x7c);
        YdpcBin.W32LE(msg, 2, 57);
        Encoding.ASCII.GetBytes(TerminalGuid).CopyTo(msg, 11);
        return msg;
    }

    /// <summary>对齐 buildZteRawDisplayInit。</summary>
    public static byte[] BuildZteRawDisplayInit() => Convert.FromHexString("65001300000000000000000100004001000000000100fc5f000000000003");

    /// <summary>对齐 buildZteRawInputInit。</summary>
    public static byte[] BuildZteRawInputInit() => Convert.FromHexString("67000200000000000000000200");

    /// <summary>对齐 buildZteRawDisplayHeartbeat：display type=3 心跳（18B，第三个 u32 为单调计数器）。</summary>
    public static byte[] BuildZteRawDisplayHeartbeat(uint counter)
    {
        var msg = new byte[18];
        YdpcBin.W16LE(msg, 0, 0x0003);
        YdpcBin.W32LE(msg, 2, 12);
        YdpcBin.W32LE(msg, 6, 0);
        YdpcBin.W32LE(msg, 10, 0xffffff00);
        YdpcBin.W32LE(msg, 14, counter);
        return msg;
    }

    /// <summary>对齐 rawMessageWithPrefix：8B ZTE 数据消息前缀（u32 serial + 4B 零）。</summary>
    public static byte[] RawMessageWithPrefix(uint serial, byte[] msg)
    {
        var outBuf = new byte[8 + msg.Length];
        YdpcBin.W32LE(outBuf, 0, serial);
        Buffer.BlockCopy(msg, 0, outBuf, 8, msg.Length);
        return outBuf;
    }

    /// <summary>对齐 zteMainInitConnectionId：用标记 02 00 00 00 01 定位 MAIN_INIT connection_id。</summary>
    public static int ZteMainInitConnectionId(byte[] payload)
    {
        var marker = new byte[] { 0x02, 0x00, 0x00, 0x00, 0x01 };
        int idx = IndexOf(payload, marker);
        if (idx >= 4) return (int)YdpcBin.U32LE(payload, idx - 4);
        if (payload.Length >= 7) return (int)YdpcBin.U32LE(payload, 3);
        return 0;
    }

    private static int IndexOf(byte[] hay, byte[] needle)
    {
        for (int i = 0; i <= hay.Length - needle.Length; i++)
        {
            bool ok = true;
            for (int j = 0; j < needle.Length; j++)
            {
                if (hay[i + j] != needle[j]) { ok = false; break; }
            }
            if (ok) return i;
        }
        return -1;
    }

    /// <summary>对齐 hasRsaPublicKeyMarker：只做存在性校验，不使用、不硬编码。</summary>
    public static bool HasRsaPublicKeyMarker(byte[] reply)
    {
        var m1 = new byte[] { 0x30, 0x81, 0x9f, 0x30, 0x0d };
        var m2 = new byte[] { 0x30, 0x81 };
        return IndexOf(reply, m1) >= 0 || IndexOf(reply, m2) >= 0;
    }

    /// <summary>对齐 readRawLinkReply：16B 头（REDQ 魔数 + u32le size@12）+ 体；size 上限 4096。</summary>
    internal static async Task<byte[]> ReadRawLinkReply(CagMuxLink link, int timeoutMs, CancellationToken ct = default)
    {
        byte[] head = await link.ReadExactAsync(16, timeoutMs, ct).ConfigureAwait(false);
        if (Encoding.ASCII.GetString(head, 0, 4) != "REDQ")
            throw new InvalidOperationException($"raw SPICE 链路回包魔数非法：{YdpcBin.HexLower(head.AsSpan(0, 4).ToArray())}");
        uint size = YdpcBin.U32LE(head, 12);
        if (size > RedqReplyMax) throw new InvalidOperationException($"raw SPICE REDQ 回包长度非法：{size}");
        byte[] body = size > 0 ? await link.ReadExactAsync((int)size, timeoutMs, ct).ConfigureAwait(false) : Array.Empty<byte>();
        return YdpcBin.Concat(head, body);
    }
}

/// <summary>raw SPICE 读写状态机（对齐 zte_cag_tls.js RawState）。</summary>
internal sealed class RawSpiceState
{
    public uint LastSerial { get; private set; }
    public byte[] LastSuffix { get; private set; } = Array.Empty<byte>();
    private uint _nextSerialValue;

    public readonly struct RawMessage
    {
        public RawMessage(ushort msgType, byte[] payload) { MsgType = msgType; Payload = payload; }
        public ushort MsgType { get; }
        public byte[] Payload { get; }
    }

    /// <summary>对齐 RawState.readMessage：size==0 的消息带 8B ZTE 前缀，载荷之后剥 5B 后缀到 LastSuffix。</summary>
    public async Task<RawMessage> ReadMessageAsync(CagMuxLink link, int timeoutMs, CancellationToken ct = default)
    {
        byte[] head = await link.ReadExactAsync(6, timeoutMs, ct).ConfigureAwait(false);
        ushort msgType = YdpcBin.U16LE(head, 0);
        uint size = YdpcBin.U32LE(head, 2);
        bool hasZtePrefix = false;
        if (size == 0)
        {
            uint serial = YdpcBin.U32LE(head, 0);
            await link.ReadExactAsync(2, timeoutMs, ct).ConfigureAwait(false); // 前缀剩余 2B
            head = await link.ReadExactAsync(6, timeoutMs, ct).ConfigureAwait(false);
            msgType = YdpcBin.U16LE(head, 0);
            size = YdpcBin.U32LE(head, 2);
            LastSerial = serial;
            LastSuffix = Array.Empty<byte>();
            hasZtePrefix = true;
        }
        if (size > CagSpice.RawMsgMax) throw new InvalidOperationException($"raw SPICE 消息体过大：{size}");
        byte[] payload = size > 0 ? await link.ReadExactAsync((int)size, timeoutMs, ct).ConfigureAwait(false) : Array.Empty<byte>();
        if (hasZtePrefix) LastSuffix = link.TakeReadBufferN(5) ?? Array.Empty<byte>();
        return new RawMessage(msgType, payload);
    }

    /// <summary>对齐 RawState.autoReply：ping(0x04)/ack(0x03)/0x74 三类自动回包。返回是否回过。</summary>
    public async Task<bool> AutoReplyAsync(CagMuxLink link, ushort msgType, byte[] payload, CancellationToken ct = default)
    {
        if (msgType == 0x04)
        {
            var pong = new byte[6 + payload.Length];
            YdpcBin.W16LE(pong, 0, 0x03);
            YdpcBin.W32LE(pong, 2, (uint)payload.Length);
            Buffer.BlockCopy(payload, 0, pong, 6, payload.Length);
            await WriteMessageAsync(link, LastSerial, pong, ct).ConfigureAwait(false);
            return true;
        }
        if (msgType == 0x03)
        {
            uint generation = payload.Length >= 4 ? YdpcBin.U32LE(payload, 0) : 0;
            var ack = new byte[10];
            YdpcBin.W16LE(ack, 0, 0x01);
            YdpcBin.W32LE(ack, 2, 4);
            YdpcBin.W32LE(ack, 6, generation);
            await WriteMessageAsync(link, LastSerial, ack, ct).ConfigureAwait(false);
            return true;
        }
        if (msgType == 0x74)
        {
            var reply = new byte[7];
            YdpcBin.W16LE(reply, 0, 0x79);
            YdpcBin.W32LE(reply, 2, 1);
            await WriteMessageAsync(link, NextSerial(), reply, ct).ConfigureAwait(false);
            return true;
        }
        return false;
    }

    /// <summary>对齐 RawState.writeMessage：8B 前缀 + msg + LastSuffix。</summary>
    public Task WriteMessageAsync(CagMuxLink link, uint serial, byte[] msg, CancellationToken ct = default) =>
        link.WriteAsync(YdpcBin.Concat(CagSpice.RawMessageWithPrefix(serial, msg), LastSuffix), ct);

    public uint NextSerial()
    {
        if (_nextSerialValue == 0) _nextSerialValue = 4;
        return _nextSerialValue++;
    }
}

// -----------------------------------------------------------------------------
// TLS 数据面会话（zte_cag_tls.js runTlsSpiceSession / keepaliveRawSpiceLoop）
// -----------------------------------------------------------------------------
public sealed class CagTlsSession : IAsyncDisposable
{
    private readonly CagMux _mux;
    private readonly TcpClient _tcp;
    private readonly CagMuxLink _mainLink;
    private readonly RawSpiceState _state = new();
    private readonly Action<string, string>? _log;
    private readonly List<CagMuxLink> _displayLinks = new();
    private readonly SemaphoreSlim _ioLock = new(1, 1);
    private readonly DateTime _startedAt = DateTime.UtcNow;

    public uint Conv { get; }
    public int SpiceSessionId { get; }
    public int SubLinks { get; }
    public int AuthedSubLinks { get; }
    public int DisplaySubLinks => _displayLinks.Count;
    public bool TlsDowngraded { get; }
    public string? TlsError { get; }

    private uint _hbCounter;
    private long _hbSeq;

    internal CagTlsSession(CagMux mux, TcpClient tcp, CagMuxLink mainLink, uint conv, int spiceSessionId,
        int subLinks, int authedSubLinks, IEnumerable<CagMuxLink> displayLinks,
        bool tlsDowngraded, string? tlsError, Action<string, string>? log)
    {
        _mux = mux;
        _tcp = tcp;
        _mainLink = mainLink;
        Conv = conv;
        SpiceSessionId = spiceSessionId;
        SubLinks = subLinks;
        AuthedSubLinks = authedSubLinks;
        _displayLinks.AddRange(displayLinks);
        TlsDowngraded = tlsDowngraded;
        TlsError = tlsError;
        _log = log;
    }

    private void Log(string level, string msg) => _log?.Invoke(level, msg);

    /// <summary>
    /// 单次 display type=3 心跳（对齐 keepaliveRawSpiceLoop 的心跳步）：
    /// 8B 前缀(NextSerial) + 18B type=3 帧 + 5B 后缀，发往所有 display 子链路（无则主干）；
    /// 每 5 拍计数器 +250（模拟屏幕刷新时间戳）。
    /// </summary>
    public async Task HeartbeatAsync(CancellationToken ct = default)
    {
        await _ioLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            byte[] suffix = _state.LastSuffix.Length > 0 ? _state.LastSuffix : new byte[5];
            byte[] hbMsg = YdpcBin.Concat(
                CagSpice.RawMessageWithPrefix(_state.NextSerial(), CagSpice.BuildZteRawDisplayHeartbeat(_hbCounter)), suffix);
            List<CagMuxLink> targets = _displayLinks.Count > 0 ? _displayLinks : new List<CagMuxLink> { _mainLink };
            foreach (CagMuxLink l in targets) await l.WriteAsync(hbMsg, ct).ConfigureAwait(false);
            _hbSeq++;
            if (_hbSeq % 5 == 0) _hbCounter += 250; // & 0xffffffff：uint 自然回绕
        }
        finally { _ioLock.Release(); }
    }

    /// <summary>
    /// 主干保活循环（对齐 keepaliveRawSpiceLoop）：读消息 + 自动回包；每 interval 秒补发
    /// display/input init；heartbeatHz &gt; 0 时按该节奏向 display 链路注入 type=3 心跳。
    /// 只如实返回计数器 —— 收到消息/回过包 ≠ 保活被证明。
    /// </summary>
    public async Task<CagKeepaliveCounters> RunKeepaliveLoopAsync(
        int intervalSec = 25, int stopAfterSec = 0, int heartbeatHz = 21,
        Func<bool>? shouldStop = null, CancellationToken ct = default)
    {
        long messages = 0, autoReplies = 0, ticks = 0, errors = 0, heartbeats = 0, hbFrames = 0;
        double hbIntervalMs = heartbeatHz > 0 ? 1000.0 / heartbeatHz : 0;
        int readTimeoutMs = hbIntervalMs > 0
            ? (int)Math.Min(hbIntervalMs, 1000)
            : Math.Min(1000, Math.Max(100, intervalSec * 1000));
        DateTime nextTickAt = DateTime.UtcNow;
        DateTime nextHbAt = DateTime.UtcNow;
        DateTime lastProgressAt = DateTime.UtcNow;

        while (true)
        {
            if (shouldStop?.Invoke() == true) break;
            if (stopAfterSec > 0 && (DateTime.UtcNow - _startedAt).TotalSeconds >= stopAfterSec) break;

            try
            {
                RawSpiceState.RawMessage got = await _state.ReadMessageAsync(_mainLink, readTimeoutMs, ct).ConfigureAwait(false);
                messages++;
                if (await _state.AutoReplyAsync(_mainLink, got.MsgType, got.Payload, ct).ConfigureAwait(false)) autoReplies++;
            }
            catch (YdpcTimeoutException)
            {
                // 读超时是常态（服务端只在有事件时才发）
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception e)
            {
                errors++;
                if (messages == 0 && ticks == 0)
                    Log("warning", $"raw SPICE 主干读取中断：{e.Message}");
                break;
            }

            DateTime now = DateTime.UtcNow;
            if (now >= nextTickAt)
            {
                try
                {
                    await _mainLink.WriteAsync(YdpcBin.Concat(CagSpice.RawMessageWithPrefix(_state.NextSerial(), CagSpice.BuildZteRawDisplayInit())), ct).ConfigureAwait(false);
                    await _mainLink.WriteAsync(YdpcBin.Concat(CagSpice.RawMessageWithPrefix(_state.NextSerial(), CagSpice.BuildZteRawInputInit())), ct).ConfigureAwait(false);
                    ticks++;
                }
                catch (Exception) { errors++; break; }
                nextTickAt = now + TimeSpan.FromSeconds(intervalSec);
            }

            if (hbIntervalMs > 0 && now >= nextHbAt)
            {
                try
                {
                    await HeartbeatAsync(ct).ConfigureAwait(false);
                    heartbeats++;
                    hbFrames += _displayLinks.Count > 0 ? _displayLinks.Count : 1;
                }
                catch (Exception) { errors++; break; }
                nextHbAt = now + TimeSpan.FromMilliseconds(hbIntervalMs);
            }

            if ((now - lastProgressAt).TotalMilliseconds >= 10000)
            {
                lastProgressAt = now;
                double left = stopAfterSec > 0 ? Math.Max(0, stopAfterSec - (now - _startedAt).TotalSeconds) : -1;
                Log("info", $"progress msg={messages} reply={autoReplies} tick={ticks} hb={heartbeats} left={(left < 0 ? "∞" : $"{(int)left}s")}");
            }
        }

        return new CagKeepaliveCounters(messages, autoReplies, ticks, errors, heartbeats, hbFrames, heartbeatHz);
    }

    public async ValueTask DisposeAsync()
    {
        await _mux.DisposeAsync().ConfigureAwait(false);
        try { ((IDisposable)_tcp).Dispose(); } catch { /* 已断开 */ }
        _ioLock.Dispose();
    }
}

// -----------------------------------------------------------------------------
// IPv6 raw 会话（zte_cag_raw.js dialCagTcpRaw / keepaliveRawZtecLoop）
// -----------------------------------------------------------------------------
public sealed class CagRawSession : IAsyncDisposable
{
    private readonly TcpClient _tcp;
    private readonly NetworkStream _stream;
    private readonly Action<string, string>? _log;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private long _hbRecv;
    private readonly object _recvGate = new();
    private CancellationTokenSource? _recvCts;
    private Task? _recvTask;

    public uint Conv { get; }

    internal CagRawSession(TcpClient tcp, uint conv, Action<string, string>? log)
    {
        _tcp = tcp;
        _stream = tcp.GetStream();
        Conv = conv;
        _log = log;
        StartRecvCounter();
    }

    private void Log(string level, string msg) => _log?.Invoke(level, msg);

    private void StartRecvCounter()
    {
        _recvCts = new CancellationTokenSource();
        _recvTask = Task.Run(async () =>
        {
            var buf = new byte[16 * 1024];
            try
            {
                while (!_recvCts.IsCancellationRequested)
                {
                    int n = await _stream.ReadAsync(buf, _recvCts.Token).ConfigureAwait(false);
                    if (n <= 0) return;
                    lock (_recvGate) _hbRecv += Math.Max(1, n / 4); // 对齐：按 4B HB 帧估算 hb_recv
                }
            }
            catch { /* 会话收尾 */ }
        });
    }

    public long HbRecv { get { lock (_recvGate) return _hbRecv; } }

    /// <summary>对齐 primeRawZtecLinks：预热 ADD_LINK lid=7/8 + DATA lid=7。</summary>
    public async Task PrimeAsync(CancellationToken ct = default)
    {
        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await _stream.WriteAsync(BuildRawZtecAddLinkPacket(7), ct).ConfigureAwait(false);
            await _stream.WriteAsync(BuildRawZtecAddLinkPacket(8), ct).ConfigureAwait(false);
            await _stream.WriteAsync(BuildRawZtecDataPacket(7), ct).ConfigureAwait(false);
        }
        finally { _writeLock.Release(); }
    }

    private static byte[] BuildRawZtecAddLinkPacket(int linkId)
    {
        var payload = new byte[0x9a];
        YdpcBin.W16LE(payload, 0, 3246); // RAW_ZTEC_LINK_PORT
        payload[2] = 0x09;               // RAW_ZTEC_LINK_TYPE
        payload[4] = 1; payload[5] = 0; payload[6] = 0; payload[7] = 127; // 127.0.0.1 反序
        payload[0x54] = 0x0c;
        var head = new byte[4];
        head[0] = 0x1a; // CAG_ADD_LINK_CMD
        head[1] = (byte)(linkId & 0xFF);
        YdpcBin.W16LE(head, 2, 0x9a);
        return YdpcBin.Concat(head, payload);
    }

    private static byte[] BuildRawZtecDataPacket(int linkId)
    {
        var body = new byte[1688];
        body[8] = 0x12; body[528] = 0x01; body[537] = 0x01;
        var head = new byte[4];
        head[0] = 0x0a; // CAG_DATA_CMD
        head[1] = (byte)(linkId & 0xFF);
        YdpcBin.W16LE(head, 2, 1688);
        return YdpcBin.Concat(head, body);
    }

    /// <summary>心跳：4B 空 CAG DATA 帧（对齐 ZTEC_RAW_HB）。</summary>
    public async Task HeartbeatAsync(CancellationToken ct = default)
    {
        byte[] hb = { 0x0a, 0x00, 0x00, 0x00 };
        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try { await _stream.WriteAsync(hb, ct).ConfigureAwait(false); }
        finally { _writeLock.Release(); }
    }

    /// <summary>对齐 keepaliveRawZtecLoop：周期 HB + 每 dataResend 秒重发 DATA；hb_recv 只按字节估算。</summary>
    public async Task<CagRawKeepaliveCounters> RunKeepaliveLoopAsync(
        double intervalSec = 1.0, int stopAfterSec = 20, bool primeLinks = true,
        double dataResendSec = 60, CancellationToken ct = default)
    {
        long hbSent = 0, linksSent = 0, dataSent = 0, primeRecv = 0;
        string? error = null;
        DateTime deadline = DateTime.UtcNow + TimeSpan.FromSeconds(stopAfterSec);
        DateTime nextDataAt = DateTime.MinValue;
        DateTime lastProgressAt = DateTime.UtcNow;

        if (primeLinks)
        {
            try
            {
                await PrimeAsync(ct).ConfigureAwait(false);
                linksSent = 2; dataSent = 1;
                if (dataResendSec > 0) nextDataAt = DateTime.UtcNow + TimeSpan.FromSeconds(dataResendSec);
                Log("info", "raw-ZTEC 预热 links=2 data=1");
            }
            catch (Exception e)
            {
                Log("warning", $"raw-ZTEC 预热告警: {e.Message}");
            }
        }

        while (true)
        {
            if (ct.IsCancellationRequested) break;
            DateTime now = DateTime.UtcNow;
            if (now >= deadline) break;

            if (dataResendSec > 0 && now >= nextDataAt)
            {
                try
                {
                    byte[] pkt = BuildRawZtecDataPacket(7);
                    await _writeLock.WaitAsync(ct).ConfigureAwait(false);
                    try { await _stream.WriteAsync(pkt, ct).ConfigureAwait(false); }
                    finally { _writeLock.Release(); }
                    dataSent++;
                    nextDataAt = now + TimeSpan.FromSeconds(dataResendSec);
                }
                catch (Exception e) { error = e.Message; break; }
            }

            try { await HeartbeatAsync(ct).ConfigureAwait(false); hbSent++; }
            catch (Exception e) { error = e.Message; break; }

            if ((now - lastProgressAt).TotalMilliseconds >= 10000)
            {
                lastProgressAt = now;
                Log("info", $"progress hb_sent={hbSent} hb_recv={HbRecv} data={dataSent} left={Math.Max(0, (int)(deadline - now).TotalSeconds)}s");
            }

            double nextDelay = Math.Min(intervalSec * 1000, (deadline - DateTime.UtcNow).TotalMilliseconds);
            if (nextDelay > 0)
            {
                try { await Task.Delay(TimeSpan.FromMilliseconds(nextDelay), ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
            }
        }
        return new CagRawKeepaliveCounters(hbSent, HbRecv, HbRecv > 0, linksSent, dataSent, primeRecv, error);
    }

    public async ValueTask DisposeAsync()
    {
        _recvCts?.Cancel();
        if (_recvTask != null) { try { await _recvTask.ConfigureAwait(false); } catch { /* 收尾 */ } }
        _recvCts?.Dispose();
        _writeLock.Dispose();
        _stream.Dispose();
        ((IDisposable)_tcp).Dispose();
    }
}

// -----------------------------------------------------------------------------
// CAG 客户端门面
// -----------------------------------------------------------------------------
public sealed class CagClient
{
    /// <summary>证书链缺陷白名单（对齐 zte_cag_tls.js CERT_CHAIN_ERROR_CODES；.NET 侧经语义子串映射）。</summary>
    private static readonly string[] CertChainErrorCodes =
    {
        "UNABLE_TO_VERIFY_LEAF_SIGNATURE", // 只发叶证书、无中间 CA
        "SELF_SIGNED_CERT_IN_CHAIN",
        "DEPTH_ZERO_SELF_SIGNED_CERT",
        "CERT_HAS_EXPIRED",
        "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
        "UNABLE_TO_GET_ISSUER_CERT",
        "ERR_TLS_CERT_ALTNAME_INVALID"     // CAG 按 IP 访问时的主机名不匹配
    };

    private readonly Action<string, string>? _log;
    public int TimeoutMs { get; set; } = 15000;

    public CagClient(Action<string, string>? log = null) { _log = log; }

    private void Log(string level, string msg) => _log?.Invoke(level, $"[CAG] {msg}");

    // -----------------------------------------------------------------------
    // 经典三阶段握手（cag_client.js performCagAuthHold）
    // -----------------------------------------------------------------------

    /// <summary>
    /// ZTEC CAG TCP 三阶段握手：连 cagIp:cagPort → Stage1(50B) → Stage2(50B, serverKey/flags)
    /// → Stage3(220B AES 加密 RADIUS 材料) → 等回包（含 "200" 或 ≥4B）。
    /// 成功返回**保持打开**的会话句柄（心跳方法见 CagSession.HeartbeatAsync）。
    /// 材料缺失（cagIp 空）时拒绝拨号（CAG_MATERIAL_MISSING）——「本次没做事」，不是链路故障。
    /// </summary>
    public async Task<CagSession> HandshakeAsync(CagFirmAuth vmInfo, int timeoutMs = 15000, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(vmInfo);
        string cagHost = vmInfo.EffectiveCagHost;
        if (cagHost.Length == 0)
        {
            // 【防线对齐】必须在拨号之前明确拒绝，不得把空主机拼成 "undefined" 去 DNS
            throw new CagMaterialMissingException("该机器未下发 CAG 连接材料（cagIp 缺失），本次不发起 CAG 握手");
        }
        int cagPort = vmInfo.EffectiveCagPort;
        string vmcHost = vmInfo.EffectiveVmcHost;
        int vmcPort = vmInfo.EffectiveVmcPort;
        string vmUserName = vmInfo.VmUserName ?? "";
        string vmPassword = vmInfo.VmPassword ?? "";
        string vmId = vmInfo.VmId ?? "";

        uint clientKey = BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4), 0);

        var tcp = new TcpClient();
        try
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(timeoutMs);
            CancellationToken lct = timeoutCts.Token;

            await tcp.ConnectAsync(cagHost, cagPort, lct).ConfigureAwait(false);
            NetworkStream ns = tcp.GetStream();

            // Stage 1 → 发 50B
            byte[] stage1 = CagProtocol.BuildZtecStage1(vmId, clientKey);
            await ns.WriteAsync(stage1, lct).ConfigureAwait(false);

            // Stage 2 → 读 50B，解 serverKey / aesFlag
            byte[] stage2 = new byte[50];
            await YdpcBin.ReadExactAsync(ns, stage2, 50, timeoutMs, lct).ConfigureAwait(false);
            (uint serverKey, int aesFlag) = CagProtocol.ParseZtecStage2(stage2);

            // Stage 3 → 发 220B
            byte[] stage3 = CagProtocol.BuildZtecStage3Radius(vmcHost, vmcPort, vmUserName, vmPassword, clientKey, serverKey, aesFlag);
            await ns.WriteAsync(stage3, lct).ConfigureAwait(false);

            // 等 CAG Reply：ascii 含 "200" 或累计 ≥4B（对齐 JS 判据）
            var rbuf = new List<byte>();
            var chunk = new byte[256];
            while (true)
            {
                int n = await ns.ReadAsync(chunk, lct).ConfigureAwait(false);
                if (n <= 0) break;
                for (int i = 0; i < n; i++) rbuf.Add(chunk[i]);
                string text = Encoding.ASCII.GetString(rbuf.ToArray());
                if (text.Contains("200", StringComparison.Ordinal) || rbuf.Count >= 4) break;
            }

            return new CagSession(tcp, cagHost, cagPort);
        }
        catch
        {
            try { ((IDisposable)tcp).Dispose(); } catch { /* 已断开 */ }
            throw;
        }
    }

    /// <summary>对齐 performCagAuthHold(firmAuth, holdSeconds)：握手成功后保持 holdSeconds 秒再优雅关闭。</summary>
    public async Task<CagAuthHoldResult> AuthHoldAsync(CagFirmAuth firmAuth, int holdSeconds = 3, int timeoutMs = 15000, CancellationToken ct = default)
    {
        await using CagSession session = await HandshakeAsync(firmAuth, timeoutMs, ct).ConfigureAwait(false);
        try
        {
            await session.HoldAsync(holdSeconds, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { /* 取消即视为 hold 提前结束 */ }
        return new CagAuthHoldResult(true, 200, "ZTEC CAG 握手成功，网关已确认活跃");
    }

    // -----------------------------------------------------------------------
    // IPv4 / TLS 数据面（zte_cag_tls.js dialCagTcpTls + runTlsSpiceSession）
    // -----------------------------------------------------------------------

    private static bool AllowAnyCertificate(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors) => true;

    /// <summary>把 .NET TLS 错误映射为 OpenSSL 风格白名单代号；映射不到返回 null（= 不可降级）。</summary>
    private static string? MapTlsErrorCode(Exception e)
    {
        string s = (e.ToString() ?? "").ToLowerInvariant();
        if (s.Contains("self-signed") || s.Contains("self_signed") || s.Contains("self signed"))
            return s.Contains("chain") ? "SELF_SIGNED_CERT_IN_CHAIN" : "DEPTH_ZERO_SELF_SIGNED_CERT";
        if (s.Contains("unable to get local issuer") || s.Contains("partial chain") || s.Contains("untrusted"))
            return "UNABLE_TO_GET_ISSUER_CERT_LOCALLY";
        if (s.Contains("expired") || s.Contains("not yet valid") || s.Contains("not valid before") || s.Contains("not valid after"))
            return "CERT_HAS_EXPIRED";
        if (s.Contains("name mismatch") || s.Contains("altname") || s.Contains("cn mismatch"))
            return "ERR_TLS_CERT_ALTNAME_INVALID";
        if (s.Contains("remotecertificatechainerrors") || s.Contains("chain errors") || s.Contains("certificate chain"))
            return "UNABLE_TO_VERIFY_LEAF_SIGNATURE";
        return null;
    }

    private async Task<(SslStream Ssl, TcpClient Tcp, uint Conv)> DialTlsOnceAsync(CagTlsDialOptions o, bool allowInsecure, CancellationToken ct)
    {
        // 两块线上材料先构造好：抛错必须发生在拨号之前（对齐 JS 注释）
        byte[] head = CagProtocol.BuildCagAuthHeadLong();
        byte[] blob = CagProtocol.BuildCagAuthBlob(o.InnerHost, o.InnerPort, o.ProxySport, o.VmId);

        var tcp = new TcpClient();
        NetworkStream? ns = null;
        try
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(o.TimeoutMs);
            CancellationToken lct = timeoutCts.Token;

            await tcp.ConnectAsync(o.OuterHost, o.OuterPort, lct).ConfigureAwait(false);
            ns = tcp.GetStream();
            Log("info", $"TCP 已连接 {o.OuterHost}:{o.OuterPort}，发送 178B ZTEC 认证头（IPv4/TLS 路径）");
            await ns.WriteAsync(head, lct).ConfigureAwait(false);

            byte[] ack1 = new byte[50];
            await YdpcBin.ReadExactAsync(ns, ack1, 50, o.TimeoutMs, lct).ConfigureAwait(false);
            string magic = Encoding.ASCII.GetString(ack1, 0, 4);
            if (magic != "ZTEC")
                throw new InvalidOperationException($"178B 头回包魔数校验失败：\"{magic}\"");
            uint conv = YdpcBin.U32LE(ack1, 14);
            Log("info", $"conv = {conv} (0x{conv:x})，发送 220B auth blob（IPv4：host={o.InnerHost} proxySport={o.ProxySport}）");
            await ns.WriteAsync(blob, lct).ConfigureAwait(false);

            byte[] ack2 = new byte[36];
            await YdpcBin.ReadExactAsync(ns, ack2, 36, o.TimeoutMs, lct).ConfigureAwait(false);
            if (ack2[4] != 0x01)
                throw new InvalidOperationException($"auth ack 校验失败：ack[4]=0x{ack2[4]:x2}");

            Log("info", $"auth 通过（conv={conv}），升级 TLS（{(allowInsecure ? "受控降级：已放宽校验" : "严格校验先行")}）");
            var ssl = new SslStream(ns, leaveInnerStreamOpen: false, allowInsecure ? AllowAnyCertificate : null);
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                // 内网 IP 端点，无 SNI 可用（对齐 servername: undefined）
                TargetHost = o.OuterHost,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                RemoteCertificateValidationCallback = allowInsecure ? AllowAnyCertificate : null
            }, lct).ConfigureAwait(false);
            return (ssl, tcp, conv);
        }
        catch
        {
            ns?.Dispose();
            try { ((IDisposable)tcp).Dispose(); } catch { /* 已断开 */ }
            throw;
        }
    }

    /// <summary>
    /// IPv4/TLS 拨号（对齐 dialCagTcpTls）：严格校验先行；仅当失败为证书链缺陷白名单内的
    /// 错误时，留证（host + 错误码 warning）后**整条重拨**一次并放宽校验。
    /// </summary>
    private async Task<(SslStream Ssl, TcpClient Tcp, uint Conv, bool Downgraded, string? TlsError)> DialCagTcpTlsAsync(CagTlsDialOptions o, CancellationToken ct)
    {
        try
        {
            var r = await DialTlsOnceAsync(o, false, ct).ConfigureAwait(false);
            return (r.Ssl, r.Tcp, r.Conv, false, null);
        }
        catch (AuthenticationException err)
        {
            string? code = MapTlsErrorCode(err);
            if (code == null || Array.IndexOf(CertChainErrorCodes, code) < 0) throw;
            if (!o.AllowInsecureFallback) throw;
            // 留证：降级必须写明 host + 错误码
            Log("warning",
                $"TLS 证书链验证失败（{o.OuterHost} / {code}）→ 受控降级：重新拨号并放宽校验一次" +
                $"（该 CAG 端点只下发叶证书、无中间 CA）");
            var r2 = await DialTlsOnceAsync(o, true, ct).ConfigureAwait(false);
            return (r2.Ssl, r2.Tcp, r2.Conv, true, code);
        }
    }

    /// <summary>
    /// 跑完一个 IPv4/TLS 数据面切片的建立段（对齐 runTlsSpiceSession 的拨号 → 主干握手 →
    /// 子通道认证），返回可做 21Hz display 心跳保活的会话句柄。
    /// 会话已建立 ≠ 保活已被证明。
    /// </summary>
    public async Task<CagTlsSession> DialTlsAsync(CagTlsDialOptions o, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(o);
        (SslStream ssl, TcpClient tcp, uint conv, bool downgraded, string? tlsError) = await DialCagTcpTlsAsync(o, ct).ConfigureAwait(false);
        if (downgraded) Log("warning", $"TLS 已按受控降级建立（原因码 {tlsError}）");

        CagMux mux = CagMux.Open(ssl, _log);
        bool established = false;
        try
        {
            string traceId = string.IsNullOrEmpty(o.TraceId) ? CagMux.RandomHex(16) : o.TraceId!;
            var inner = new CagInnerEndpoint { Host = o.InnerHost, Port = o.InnerPort };
            CagMuxLink mainLink = await mux.OpenLinkAsync(inner, traceId).ConfigureAwait(false);

            (bool ok, int spiceSessionId, string error) = await RawMainHandshakeAsync(
                mainLink, o.Key, o.VmId, traceId, mainLink.RedqSpanId, ct).ConfigureAwait(false);
            if (!ok) throw new InvalidOperationException($"raw SPICE 主干握手失败：{error}");

            (int subLinks, int authed, List<CagMuxLink> displayLinks) = await SetupSubChannelsAsync(
                mux, inner, mainLink, spiceSessionId, o.Key, o.VmId, 8000, ct).ConfigureAwait(false);

            established = true;
            Log("success",
                $"✅ 数据面会话已建立 (conv={conv} spice={spiceSessionId} 子通道 {authed}/{subLinks}，" +
                $"display {displayLinks.Count} 条{(downgraded ? "，TLS 已按受控降级建立" : "")})");

            return new CagTlsSession(mux, tcp, mainLink, conv, spiceSessionId, subLinks, authed, displayLinks, downgraded, tlsError, _log);
        }
        finally
        {
            if (!established)
            {
                // 与 JS finally 语义一致：会话未建立 → 清理 mux/socket
                try { await mux.DisposeAsync().ConfigureAwait(false); } catch { /* 已断开 */ }
                try { ((IDisposable)tcp).Dispose(); } catch { /* 已断开 */ }
            }
        }
    }

    /// <summary>对齐 rawMainHandshake：REDQ → RSA 标记校验 → 128B 零 ticket → MAIN_INIT → attach → client_info。</summary>
    private async Task<(bool Ok, int SpiceSessionId, string Error)> RawMainHandshakeAsync(
        CagMuxLink link, string key, string vmId, string traceId, string spanId, CancellationToken ct)
    {
        try
        {
            var state = new RawSpiceState();
            await link.WriteAsync(CagSpice.BuildRawMainRedq(key, vmId, link.LinkUuid, traceId, spanId), ct).ConfigureAwait(false);
            byte[] reply = await CagSpice.ReadRawLinkReply(link, 8000, ct).ConfigureAwait(false);
            if (!CagSpice.HasRsaPublicKeyMarker(reply))
                return (false, 0, "REDQ 回包里没有 RSA 公钥定位标记");

            // 官方产品隧道此处发 128B 全零 ticket（不带 auth-type 前缀）——保留线上行为
            await link.WriteAsync(CagSpice.RawTicket, ct).ConfigureAwait(false);
            byte[] authResult = await link.ReadExactAsync(4, 8000, ct).ConfigureAwait(false);
            uint code = YdpcBin.U32LE(authResult, 0);
            if (code != 0) return (false, 0, $"raw SPICE 认证失败：result={code}");

            int spiceSessionId = 0;
            for (int i = 0; i < 15; i++)
            {
                RawSpiceState.RawMessage m = await state.ReadMessageAsync(link, 2000, ct).ConfigureAwait(false);
                if (m.MsgType == 0x67 && m.Payload.Length >= 10)
                {
                    spiceSessionId = CagSpice.ZteMainInitConnectionId(m.Payload);
                    link.DiscardReadBuffer();
                    break;
                }
                await state.AutoReplyAsync(link, m.MsgType, m.Payload, ct).ConfigureAwait(false);
            }
            if (spiceSessionId == 0) return (false, 0, "未收到 raw SPICE MAIN_INIT");

            byte[] attach = Convert.FromHexString("680000000000");
            bool attachSent = false;
            for (int i = 0; i < 4; i++)
            {
                RawSpiceState.RawMessage got;
                try { got = await state.ReadMessageAsync(link, 2000, ct).ConfigureAwait(false); }
                catch { break; }
                if (got.MsgType == 0x04)
                {
                    if (state.LastSerial == 3 || i == 3)
                    {
                        await state.WriteMessageAsync(link, state.LastSerial, attach, ct).ConfigureAwait(false);
                        attachSent = true;
                        break;
                    }
                    continue;
                }
                await state.AutoReplyAsync(link, got.MsgType, got.Payload, ct).ConfigureAwait(false);
            }
            if (!attachSent)
                await link.WriteAsync(YdpcBin.Concat(CagSpice.RawMessageWithPrefix(3, attach), new byte[5]), ct).ConfigureAwait(false);

            byte[] clientInfo = Convert.FromHexString("72000800000000000000000100000001000000");
            await link.WriteAsync(CagSpice.RawMessageWithPrefix(1, clientInfo), ct).ConfigureAwait(false);
            await link.WriteAsync(CagSpice.RawMessageWithPrefix(2, CagSpice.BuildTerminalInfoMessage()), ct).ConfigureAwait(false);

            bool initOk = false;
            for (int i = 0; i < 5; i++)
            {
                RawSpiceState.RawMessage got;
                try { got = await state.ReadMessageAsync(link, 1000, ct).ConfigureAwait(false); }
                catch { break; }
                if (got.MsgType != 0x04)
                    await state.AutoReplyAsync(link, got.MsgType, got.Payload, ct).ConfigureAwait(false);
                if (got.MsgType == 0x68 || got.MsgType == 0x73)
                {
                    initOk = true;
                    if (got.MsgType == 0x73) break;
                }
            }
            if (!initOk) return (false, spiceSessionId, "raw SPICE 初始化未到达 CHANNELS_LIST/info");

            Log("info", $"raw SPICE 主干握手完成（spiceSessionId={spiceSessionId}）");
            return (true, spiceSessionId, "");
        }
        catch (Exception e)
        {
            return (false, 0, e.Message);
        }
    }

    /// <summary>
    /// 对齐 setupSubChannels：⚠ 必须先把 7 条全开出来再认证 —— linkId 按 open 顺序递增分配，
    /// 边开边认证会与 SubchannelRedqs 表错位。
    /// </summary>
    private async Task<(int SubLinks, int Authed, List<CagMuxLink> DisplayLinks)> SetupSubChannelsAsync(
        CagMux mux, CagInnerEndpoint inner, CagMuxLink mainLink, int spiceSessionId,
        string key, string vmId, int timeoutMs, CancellationToken ct)
    {
        var links = new Dictionary<int, CagMuxLink>();
        foreach (int[] spec in CagSpice.SubchannelRedqs)
        {
            CagMuxLink link = await mux.OpenLinkAsync(inner, mainLink.TraceId, mainLink.RedqSpanId, ct).ConfigureAwait(false);
            links[link.LinkId] = link;
        }

        var authed = new HashSet<int>();
        foreach (int[] spec in CagSpice.SubchannelRedqs)
        {
            int linkId = spec[0], channelType = spec[1], channelId = spec[2];
            if (!links.TryGetValue(linkId, out CagMuxLink? link)) continue;
            bool ok = await RawSubChannelHandshakeAsync(
                link, key, vmId, mainLink.LinkUuid, mainLink.TraceId, mainLink.RedqSpanId,
                spiceSessionId, channelType, channelId, timeoutMs, ct).ConfigureAwait(false);
            if (!ok) continue;
            authed.Add(linkId);
            if (CagSpice.SubchannelInitKind.TryGetValue(linkId, out string? kind))
            {
                if (kind == "display")
                    await link.WriteAsync(CagSpice.RawMessageWithPrefix(1, CagSpice.BuildZteRawDisplayInit()), ct).ConfigureAwait(false);
                else if (kind == "input")
                    await link.WriteAsync(CagSpice.RawMessageWithPrefix(1, CagSpice.BuildZteRawInputInit()), ct).ConfigureAwait(false);
            }
        }

        string displayText = (authed.Contains(5) ? "5" : "") + (authed.Contains(7) ? (authed.Contains(5) ? "/" : "") + "7" : "");
        Log("info", $"raw SPICE 子通道：开出 {links.Count} 条，认证通过 {authed.Count} 条（display={(displayText.Length == 0 ? "无" : displayText)}）");

        var displayLinks = new List<CagMuxLink>();
        foreach (int[] spec in CagSpice.SubchannelRedqs)
        {
            int linkId = spec[0];
            if (CagSpice.SubchannelInitKind.TryGetValue(linkId, out string? kind) && kind == "display" && authed.Contains(linkId) && links.TryGetValue(linkId, out CagMuxLink? l))
                displayLinks.Add(l);
        }
        return (links.Count, authed.Count, displayLinks);
    }

    /// <summary>对齐 rawSubChannelHandshake：REDQ → 标记 → 零 ticket → 4B 结果；跳过 MAIN_INIT/attach/client_info。</summary>
    private static async Task<bool> RawSubChannelHandshakeAsync(
        CagMuxLink link, string key, string vmId, byte[] linkUuid, string traceId, string spanId,
        int spiceSessionId, int channelType, int channelId, int timeoutMs, CancellationToken ct)
    {
        try
        {
            await link.WriteAsync(CagSpice.BuildRawChannelRedq(
                key, vmId, linkUuid, traceId, spanId, spiceSessionId, channelType, channelId), ct).ConfigureAwait(false);
            byte[] reply = await CagSpice.ReadRawLinkReply(link, timeoutMs, ct).ConfigureAwait(false);
            if (!CagSpice.HasRsaPublicKeyMarker(reply)) return false;
            await link.WriteAsync(CagSpice.RawTicket, ct).ConfigureAwait(false);
            byte[] res = await link.ReadExactAsync(4, timeoutMs, ct).ConfigureAwait(false);
            return YdpcBin.U32LE(res, 0) == 0;
        }
        catch
        {
            return false;
        }
    }

    // -----------------------------------------------------------------------
    // IPv6 raw 拨号（zte_cag_raw.js dialCagTcpRaw）
    // -----------------------------------------------------------------------

    /// <summary>
    /// IPv6 raw ZTEC 拨号：50B 短头 → 50B ack(conv) → 220B blob(IPv6 分支) → 36B ack[4]==0x01。
    /// 前置地址族校验：只有内层主机为 IPv6 字面量才允许走本路径（其余明确拒绝，不猜）。
    /// </summary>
    public async Task<CagRawSession> DialRawAsync(CagTlsDialOptions o, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(o);
        (CagInnerPath path, _, string reason) = CagRoute.ResolveInnerRoute(o.InnerHost);
        if (path != CagInnerPath.Raw)
            throw new InvalidOperationException($"CAG raw 拨号前置校验失败：{reason}");

        var tcp = new TcpClient();
        try
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(o.TimeoutMs);
            CancellationToken lct = timeoutCts.Token;

            await tcp.ConnectAsync(o.OuterHost, o.OuterPort, lct).ConfigureAwait(false);
            NetworkStream ns = tcp.GetStream();
            Log("info", $"TCP 已连接 {o.OuterHost}:{o.OuterPort}，发送 50B ZTEC 短头");
            await ns.WriteAsync(CagProtocol.BuildCagAuthHeadShort(), lct).ConfigureAwait(false);

            byte[] ack1 = new byte[50];
            await YdpcBin.ReadExactAsync(ns, ack1, 50, o.TimeoutMs, lct).ConfigureAwait(false);
            string magic = Encoding.ASCII.GetString(ack1, 0, 4);
            if (magic != "ZTEC")
                throw new InvalidOperationException($"50B ack 魔数校验失败: \"{magic}\"");
            uint conv = YdpcBin.U32LE(ack1, 14);
            Log("info", $"conv = {conv} (0x{conv:x})");

            byte[] blob = CagProtocol.BuildCagAuthBlob(o.InnerHost, o.InnerPort, o.ProxySport, o.VmId);
            Log("info", $"发送 220B auth blob (innerPort={o.InnerPort} innerHost={o.InnerHost})");
            await ns.WriteAsync(blob, lct).ConfigureAwait(false);

            byte[] ack2 = new byte[36];
            await YdpcBin.ReadExactAsync(ns, ack2, 36, o.TimeoutMs, lct).ConfigureAwait(false);
            Log("info", $"auth ack[4] = 0x{ack2[4]:x2}");
            if (ack2[4] != 0x01)
                throw new InvalidOperationException($"auth ack 校验失败：ack[4]=0x{ack2[4]:x2}");

            return new CagRawSession(tcp, conv, _log);
        }
        catch
        {
            try { ((IDisposable)tcp).Dispose(); } catch { /* 已断开 */ }
            throw;
        }
    }
}
