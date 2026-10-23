// =============================================================================
// CtyunDashboard.Ydpc / ScgRoute.cs
// =============================================================================
// 对齐参考实现（Python，只读）：cmcc-cloud-alive/cmcc_cloud_alive/scg_route.py
//（1:1 移植；spice_protocol.py 的编解码以内部类 ScgSpice 承载）
//
//   scg_route.py                              → 本文件
//   ────────────────────────────────────────────────────────────────────────
//   TRUNK_HELLO=3/DATA=4/SWITCH=5/GBN=6、FRAME_HEAD_SIZE=24、DATA_TYPE=1、CONTROL_TYPE=2
//   AUTH_AES_KEY=0xFE*16 / AUTH_CTR_INIT      → 常量 ScgConsts
//   _aes_ctr_encrypt_go_compatible()          → ScgCrypto.AesCtrEncryptGoCompatible
//     （Go crypto.AESCTREncrypt：counter[0:8]=LE(init+i)、counter[8:16]=LE(init)，ECB 造 keystream 后 XOR）
//   build_auth_packet()                       → ScgProtocol.BuildAuthPacket
//     （plaintext = 00 02 + BE u64(now) + 03 + BE u16(len) + "scAuthCode|vmId"；输出 01 + len&0xFF + 密文）
//   frame_head_pack()（<BBHIQQ：ver=1,type,len,reserved,f1,f2）→ ScgProtocol.FrameHeadPack
//   trunk_switch_pack()（<QQIB3xQ 32B，reason 钳 6）→ ScgProtocol.TrunkSwitchPack
//   recv_trunk_frame()/recv_all_frames()      → RecvTrunkFrameAsync
//   _strip_spice_token_prefix()               → ScgSpice.StripTokenPrefix
//     （00 01 + u32 declared 才剥；01 01 是川云帧头不能剥）
//   build_channel_auth()（ExtInfo 模板末字节=channelType、[10:14]=BE vmId；
//                         REDQ type∈{1,2,5,6} 26B 表 / 其余 22B 表；token=16B 随机前缀）
//                                             → ScgProtocol.BuildChannelAuth
//   _find_reply_pubkey()/_send_ticket()       → ScgSpice.FindReplyPubkey/SendTicketAsync
//     （SPICE ticket = RSA-OAEP-SHA1(空密码)，公钥取 LinkReply DER 标记 30 81 9f 30 0d 起 162B）
//   spice_handshake()（main 40s → MAIN_INIT → client_info+attach → channels_list →
//     display 120s + display_init + MARK 40s → inputs/cursor 各 60s）
//                                             → SpiceHandshakeAsync
//   _handle_display_payload()/_apply_display_spice_type()
//     （mini 优先 DATA 兜底；SET_ACK→ACK_SYNC、PING→PONG、SURFACE/DRAW_COPY/MARK 进度）
//                                             → HandleDisplayPayloadAsync
//   _send_mouse_mode()（<HII = 0x69,4,2 主通道）→ SendMouseModeAsync
//   _reply_keepalive_frame()（PING→PONG、SET_ACK→ACK_SYNC）→ ReplyKeepaliveFrameAsync
//   _hold_should_run_slow_plane()（25s 慢平面；None=首拍必发）→ ShouldRunSlowPlane
//   _scg_sleep_drain()/_scg_probe_socket()    → HoldAsync（select 改 Poll）
//   connect_scg()（TCP → auth → 单次 Read 128B → byte[0]==0x00、0x0B=降级 →
//                 sessionId=(b6<<16)|(b7<<8)|b8 → 同 socket 升 TLS 不校验）
//                                             → ConnectScgAsync
//   exchange_cem_access_token()（oauth/token form：bizCode=10002/client_id=sc-user-5e38ece5/
//                 grant_type=ext/source=biz/token=scAuthCode；code=="00000"）
//                                             → ExchangeCemAccessTokenAsync
//   cem_request()（Bearer + gzs-client-id/gzs-timestamp/sc-terminal-sn/sc-network-type=2/
//                 sc-unit-type=MacBookPro + UA cdpsdk-macos-2.18.21）→ CemRequestAsync
//   wait_vm_ready()（getVmReadyStatus 20×3s；ready 时优先新 scAuthCode）→ WaitVmReadyAsync
//   get_connect_info()（getConnectInfo；readyStatus!=1 且有 traceId → 等 ready；
//                 scAuthCode 就绪后覆盖）        → GetConnectInfoAsync
//   classify_scg_soft_failure()（维护/关机 hints → vm_powered_off；502/503/504 →
//                 platform_maintenance；CEM blip → token_transient/scg_cem_blip）
//                                             → ClassifySoftFailure
//   _run_once()/run_scg_keepalive()（forever 软恢复 + reconnect_fn 重拉 connect-info +
//                 指数退避 5s×2^n 上限 60s）  → 调用方 ScgRoundAsync（YdpcRuntime.cs）
//   HoldShouldRunSlowPlane()（lead 点名 API）  = ShouldRunSlowPlane 别名
//
// AOT：字节构造全手写偏移；RSA-OAEP-SHA1 用 BCL RSAEncryptionPadding.OaepSHA1
//（公钥 DER 由 BCL ImportSubjectPublicKeyInfo/ImportRSAPublicKey 解析，替代母本手写 DER 解析器）。
// =============================================================================

using System.Globalization;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace CtyunDashboard.Ydpc;

public static class ScgConsts
{
    public const int TrunkHello = 3;
    public const int TrunkData = 4;
    public const int TrunkSwitch = 5;
    public const int TrunkGbn = 6;
    public const int FrameHeadSize = 24;
    public const int DataType = 1;
    public const int ControlType = 2;

    public static readonly byte[] AuthAesKey = { 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe };
    public const ulong AuthCtrInit = 0xFEFEFEFEFEFEFEFEUL;

    public const string CemBase = "https://api.soho.komect.com:1443";
    public const string CemClientId = "sc-user-5e38ece5";
    public const string CemBizCode = "10002";
    public const string CemRsaPublicKeyB64 =
        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRwADvpa+s20CapaSeDeWA" +
        "fRKbK5zD91jIUxNDe/2twuvKdQA+Ln3VWFtL8opVod0ebqQanpVb/uITI56G" +
        "coVdSzis2IgqIkVvN+iOPH+on/FK+6EXYeIZn3MYmVxsmS0IVifVl2EGLeOC" +
        "RMwjPmy9fHB+gByQtGnxAsknwBKUqQIDAQAB";

    public const int ChannelCtrl = 0;
    public const int ChannelMain = 1;
    public const int ChannelDisplay = 2;
    public const int ChannelInputs = 3;
    public const int ChannelCursor = 4;

    public const double HoldSelectSeconds = 1.0;
    public const double HoldKeepaliveInterval = 25.0;
    public const double ForeverBackoffBaseS = 5.0;
    public const double ForeverBackoffCapS = 60.0;
}

/// <summary>川云帧（scg_route.Frame）。</summary>
public sealed record ScgFrame(int PktType, byte[] Payload, ulong Field1, ulong Field2);

/// <summary>SCG 连接（认证 + TLS 升级后的同一 socket）。</summary>
public sealed class ScgConnection : IAsyncDisposable
{
    public TcpClient Tcp { get; }
    public SslStream Stream { get; }
    public int AuthSessionId { get; }

    internal ScgConnection(TcpClient tcp, SslStream stream, int authSessionId)
    {
        Tcp = tcp; Stream = stream; AuthSessionId = authSessionId;
    }

    public ValueTask DisposeAsync()
    {
        Stream.Dispose();
        ((IDisposable)Tcp).Dispose();
        return ValueTask.CompletedTask;
    }
}

/// <summary>软失败分类（对齐 classify_scg_soft_failure 的 tags）。</summary>
public sealed record ScgFailureTags(string Error, bool Recoverable, bool PlatformMaintenance, string FailReason);

public static class ScgCrypto
{
    private static readonly object Gate = new();
    private static RSA? _cemPub;

    private static RSA CemPublicKey()
    {
        if (_cemPub != null) return _cemPub;
        lock (Gate)
        {
            if (_cemPub == null)
            {
                var rsa = RSA.Create();
                rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(ScgConsts.CemRsaPublicKeyB64), out _);
                _cemPub = rsa;
            }
            return _cemPub;
        }
    }

    /// <summary>CEM 参数 RSA 加密（_cem_rsa_encrypt："{rsa}" + PKCS1 v1.5 b64）。</summary>
    public static string CemRsaEncrypt(string text) =>
        "{rsa}" + Convert.ToBase64String(CemPublicKey().Encrypt(Encoding.UTF8.GetBytes(text), RSAEncryptionPadding.Pkcs1));

    /// <summary>
    /// Go 兼容 AES-128-CTR（_aes_ctr_encrypt_go_compatible）：手工造计数器块
    /// counter[0:8]=LE(init+i)、counter[8:16]=LE(init)，AES-ECB 加密计数器得 keystream 后 XOR。
    /// </summary>
    public static byte[] AesCtrEncryptGoCompatible(byte[] plaintext)
    {
        using var aes = Aes.Create();
        aes.Key = ScgConsts.AuthAesKey;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        using var enc = aes.CreateEncryptor();
        int blocks = (plaintext.Length + 15) / 16;
        var stream = new byte[blocks * 16];
        var counter = new byte[16];
        for (int i = 0; i < blocks; i++)
        {
            ulong lo = ScgConsts.AuthCtrInit + (ulong)i;
            ulong hi = ScgConsts.AuthCtrInit;
            for (int b = 0; b < 8; b++) counter[b] = (byte)(lo >> (8 * b));
            for (int b = 0; b < 8; b++) counter[8 + b] = (byte)(hi >> (8 * b));
            enc.TransformBlock(counter, 0, 16, stream, i * 16);
        }
        var outBuf = new byte[plaintext.Length];
        for (int i = 0; i < plaintext.Length; i++) outBuf[i] = (byte)(plaintext[i] ^ stream[i]);
        return outBuf;
    }

    /// <summary>SPICE ticket：RSAES-OAEP-SHA1(空密码)（encode_spice_ticket；BCL 替代母本手写 OAEP）。</summary>
    public static byte[] SpiceTicketOaep(byte[] publicKeyDer, byte[] password)
    {
        using var rsa = RSA.Create();
        try { rsa.ImportSubjectPublicKeyInfo(publicKeyDer, out _); }
        catch
        {
            try { rsa.ImportRSAPublicKey(publicKeyDer, out _); }
            catch { throw new InvalidOperationException("SCG LinkReply 公钥 DER 无法解析"); }
        }
        return rsa.Encrypt(password, RSAEncryptionPadding.OaepSHA1);
    }
}

public static class ScgProtocol
{
    /// <summary>帧头 24B：<BBHIQQ → version=1, type, u16 len, u32 0, u64 f1, u64 f2（frame_head_pack）。</summary>
    public static byte[] FrameHeadPack(int pktType, int payloadLen, ulong field1, ulong field2)
    {
        if (payloadLen > 0xFFFF) throw new ArgumentException("Chuanyun payload too large for 16-bit frame length");
        var head = new byte[ScgConsts.FrameHeadSize];
        head[0] = 1;
        head[1] = (byte)(pktType & 0xFF);
        head[2] = (byte)(payloadLen & 0xFF);
        head[3] = (byte)((payloadLen >> 8) & 0xFF);
        // [4:8] reserved = 0
        for (int b = 0; b < 8; b++) head[8 + b] = (byte)(field1 >> (8 * b));
        for (int b = 0; b < 8; b++) head[16 + b] = (byte)(field2 >> (8 * b));
        return head;
    }

    /// <summary>SCG TCP 认证包（build_auth_packet）。</summary>
    public static byte[] BuildAuthPacket(string scAuthCode, string vmId)
    {
        byte[] tlvValue = Encoding.UTF8.GetBytes(scAuthCode + "|" + vmId);
        if (tlvValue.Length > 0xFFFF) throw new ArgumentException("SCG auth TLV too long");
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var plaintext = new byte[2 + 8 + 1 + 2 + tlvValue.Length];
        int off = 0;
        plaintext[off++] = 0x00;
        plaintext[off++] = 0x02;
        for (int b = 7; b >= 0; b--) plaintext[off++] = (byte)((ulong)now >> (8 * b)); // >Q
        plaintext[off++] = 0x03;
        plaintext[off++] = (byte)((tlvValue.Length >> 8) & 0xFF);                      // >H
        plaintext[off++] = (byte)(tlvValue.Length & 0xFF);
        Buffer.BlockCopy(tlvValue, 0, plaintext, off, tlvValue.Length);
        byte[] encrypted = ScgCrypto.AesCtrEncryptGoCompatible(plaintext);
        var pkt = new byte[2 + encrypted.Length];
        pkt[0] = 0x01;
        pkt[1] = (byte)(encrypted.Length & 0xFF);
        Buffer.BlockCopy(encrypted, 0, pkt, 2, encrypted.Length);
        return pkt;
    }

    /// <summary>TrunkSwitch 帧（trunk_switch_pack：<QQIB3xQ 32B，reason 钳 6）。</summary>
    public static byte[] TrunkSwitchPack(ulong targetCid, ulong senderCid, uint param, uint switchReason, ulong extraId, ulong field1, ulong field2)
    {
        if (switchReason > 6) switchReason = 6;
        var payload = new byte[32];
        for (int b = 0; b < 8; b++) payload[b] = (byte)(targetCid >> (8 * b));
        for (int b = 0; b < 8; b++) payload[8 + b] = (byte)(senderCid >> (8 * b));
        payload[16] = (byte)(param & 0xFF);
        payload[17] = (byte)((param >> 8) & 0xFF);
        payload[18] = (byte)((param >> 16) & 0xFF);
        payload[19] = (byte)((param >> 24) & 0xFF);
        payload[20] = (byte)(switchReason & 0xFF);
        // [21:24] 3B padding
        for (int b = 0; b < 8; b++) payload[24 + b] = (byte)(extraId >> (8 * b));
        return YdpcBin.Concat(FrameHeadPack(ScgConsts.TrunkSwitch, payload.Length, field1, field2), payload);
    }

    /// <summary>
    /// 川云通道认证双帧（build_channel_auth）：ExtInfo（模板末字节=channelType、[10:14]=BE vmId）
    /// + SPICE REDQ token（16B 随机前缀 + REDQ 体；type∈{1,2,5,6} 走 26B 表，其余 22B 表）。
    /// </summary>
    public static byte[] BuildChannelAuth(ulong sid, int channelId, int channelType, int connectionId = 0, int vmId = 0)
    {
        var extInfo = Convert.FromHexString("010013f300080000000000010820f1000101f2000104");
        extInfo[^1] = (byte)(channelType & 0xFF);
        if (vmId > 0)
        {
            // ExtInfo[10:14]：BE vmId（服务端按它做 redirect 查找）
            uint v = (uint)vmId;
            extInfo[10] = (byte)(v >> 24);
            extInfo[11] = (byte)(v >> 16);
            extInfo[12] = (byte)(v >> 8);
            extInfo[13] = (byte)(v & 0xFF);
        }

        var redq = new List<byte>();
        redq.AddRange(Encoding.ASCII.GetBytes("REDQ"));
        void U32(uint v) { redq.Add((byte)v); redq.Add((byte)(v >> 8)); redq.Add((byte)(v >> 16)); redq.Add((byte)(v >> 24)); }
        U32(2);
        U32(2);
        if (channelType is 1 or 2 or 5 or 6)
        {
            U32(26);
            U32((uint)connectionId);
            redq.Add((byte)(channelType & 0xFF));
            redq.Add(0);
            U32(1);
            U32(1);
            U32(18);
            U32(0x00000009);
            U32(0x0000000F);
        }
        else
        {
            U32(22);
            U32((uint)connectionId);
            redq.Add((byte)(channelType & 0xFF));
            redq.Add(0);
            U32(1);
            U32(0);
            U32(14);
            U32(0x00000009);
        }

        byte[] random16 = RandomNumberGenerator.GetBytes(16);
        var tokenRedq = YdpcBin.Concat(random16.ToArray(), redq.ToArray());
        return YdpcBin.Concat(
            FrameHeadPack(ScgConsts.DataType, extInfo.Length, sid, (ulong)channelId),
            extInfo,
            FrameHeadPack(ScgConsts.DataType, tokenRedq.Length, sid, (ulong)channelId),
            tokenRedq);
    }
}

// -----------------------------------------------------------------------------
// SPICE 编解码（spice_protocol.py 精选子集 → ScgSpice）
// -----------------------------------------------------------------------------
public static class ScgSpice
{
    public const int MiniHeaderSize = 6;
    public const int DataHeaderSize = 18;
    public const int SpiceTicketPubkeyBytes = 162;

    // SpiceMessage
    public const int MsgSetAck = 0x0003;
    public const int MsgPing = 0x0004;
    public const int MsgPong = 0x0005;
    public const int MsgAckSync = 0x0006;
    public const int MsgAck = 0x0007;
    public const int MsgMark = 0x0066;
    public const int MsgMainInit = 0x0067;
    public const int MsgChannelsList = 0x0068;
    public const int MsgDisplayInit = 0x0065;
    public const int MsgDrawCopy = 0x0130;
    public const int MsgSurfaceCreate = 0x013A;

    /// <summary>剥可选 6B token 前缀（00 01 + u32 declared，且 declared 放得下才剥；_strip_spice_token_prefix）。</summary>
    public static byte[] StripTokenPrefix(byte[] payload)
    {
        if (payload.Length < 6) return payload;
        if (payload[0] != 0x00 || payload[1] != 0x01) return payload;
        uint declared = (uint)(payload[2] | (payload[3] << 8) | (payload[4] << 16) | (payload[5] << 24));
        if (6 + declared <= payload.Length) return payload[6..];
        return payload;
    }

    /// <summary>mini 头解码（<HI）；size 放不下返回 null（对齐 decode_mini_message 的完整性检查）。</summary>
    public static (int Type, int Size, byte[] Payload)? DecodeMiniMessage(byte[] data)
    {
        if (data.Length < MiniHeaderSize) return null;
        int type = data[0] | (data[1] << 8);
        int size = data[2] | (data[3] << 8) | (data[4] << 16) | (data[5] << 24);
        int total = MiniHeaderSize + size;
        if (data.Length < total) return null;
        var payload = new byte[size];
        Buffer.BlockCopy(data, MiniHeaderSize, payload, 0, size);
        return (type, size, payload);
    }

    /// <summary>DATA 头解码（<QHII 18B）；放不下返回 null。</summary>
    public static (ushort Type, int Size, byte[] Payload)? DecodeDataMessage(byte[] data)
    {
        if (data.Length < DataHeaderSize) return null;
        ushort type = (ushort)(data[8] | (data[9] << 8));
        int size = data[10] | (data[11] << 8) | (data[12] << 16) | (data[13] << 24);
        int total = DataHeaderSize + size;
        if (data.Length < total) return null;
        var payload = new byte[size];
        Buffer.BlockCopy(data, DataHeaderSize, payload, 0, size);
        return (type, size, payload);
    }

    /// <summary>mini 消息编码（encode_mini_message）。</summary>
    public static byte[] EncodeMiniMessage(int messageType, byte[] payload)
    {
        var head = new byte[MiniHeaderSize];
        head[0] = (byte)(messageType & 0xFF);
        head[1] = (byte)((messageType >> 8) & 0xFF);
        head[2] = (byte)(payload.Length & 0xFF);
        head[3] = (byte)((payload.Length >> 8) & 0xFF);
        head[4] = (byte)((payload.Length >> 16) & 0xFF);
        head[5] = (byte)((payload.Length >> 24) & 0xFF);
        return YdpcBin.Concat(head, payload);
    }

    /// <summary>display_init（encode_display_init：u8 1 + i64 20MiB + u8 1 + u32 0x7FFC00）。</summary>
    public static byte[] EncodeDisplayInit()
    {
        var payload = new byte[14];
        payload[0] = 1;                                  // pixmapCacheId
        long cache = 20 * 1024 * 1024;                   // pixmapCacheSize (i64)
        for (int b = 0; b < 8; b++) payload[1 + b] = (byte)(cache >> (8 * b));
        payload[9] = 1;                                  // glzDictionaryId
        uint win = 0x7FFC00;                             // glzDictionaryWindowSize (u32)
        payload[10] = (byte)(win & 0xFF);
        payload[11] = (byte)((win >> 8) & 0xFF);
        payload[12] = (byte)((win >> 16) & 0xFF);
        payload[13] = (byte)((win >> 24) & 0xFF);
        return EncodeMiniMessage(MsgDisplayInit, payload);
    }

    /// <summary>ACK_SYNC（encode_ack_sync：mini ACK_SYNC + u32 generation）。</summary>
    public static byte[] EncodeAckSync(uint generation)
    {
        var payload = new byte[] { (byte)(generation & 0xFF), (byte)((generation >> 8) & 0xFF), (byte)((generation >> 16) & 0xFF), (byte)((generation >> 24) & 0xFF) };
        return EncodeMiniMessage(MsgAckSync, payload);
    }

    /// <summary>PONG（encode_pong：mini PONG + ping 载荷）。</summary>
    public static byte[] EncodePong(byte[] pingPayload) => EncodeMiniMessage(MsgPong, pingPayload);

    /// <summary>LinkReply 公钥提取（_find_reply_pubkey：DER 标记 30 81 9f 30 0d 起 162B）。</summary>
    public static byte[]? FindReplyPubkey(byte[] payload)
    {
        var marker = new byte[] { 0x30, 0x81, 0x9f, 0x30, 0x0d };
        int off = IndexOf(payload, marker);
        if (off >= 0 && payload.Length >= off + SpiceTicketPubkeyBytes)
            return payload[off..(off + SpiceTicketPubkeyBytes)];
        return null;
    }

    private static int IndexOf(byte[] hay, byte[] needle)
    {
        for (int i = 0; i <= hay.Length - needle.Length; i++)
        {
            bool ok = true;
            for (int j = 0; j < needle.Length; j++)
                if (hay[i + j] != needle[j]) { ok = false; break; }
            if (ok) return i;
        }
        return -1;
    }

    /// <summary>协议进度字典（create_protocol_progress）。</summary>
    public static Dictionary<string, bool> CreateProgress() => new()
    {
        ["displayInitSent"] = false,
        ["setAckReceived"] = false,
        ["ackSyncSent"] = false,
        ["pingReceived"] = false,
        ["pongSent"] = false,
        ["surfaceCreateReceived"] = false,
        ["drawCopyReceived"] = false,
        ["markReceived"] = false,
    };
}

// -----------------------------------------------------------------------------
// SCG 路由主体
// -----------------------------------------------------------------------------
public static class ScgRoute
{
    private static readonly string[] MaintenanceHints =
    {
        "maintenance", "maintain", "维护", "升级", "powered off", "poweroff", "power off",
        "vm_powered_off", "not running", "desktop is off", "status is off", "关机", "已关机", "停机",
    };
    private static readonly string[] CemBlipHints =
    {
        "getconnectinfo", "cem", "http error", "http 5", "http 4", "502", "503", "504",
        "timeout", "timed out", "temporarily", "connection reset", "connection refused",
        "network is unreachable", "name or service not known",
    };

    /// <summary>慢平面判定（_hold_should_run_slow_plane：last=null 首拍必发；不用 0 当哨兵）。</summary>
    public static bool ShouldRunSlowPlane(DateTime? last, double interval = ScgConsts.HoldKeepaliveInterval)
    {
        if (last == null) return true;
        return (DateTime.UtcNow - last.Value).TotalSeconds >= interval;
    }

    /// <summary>lead 点名 API（= ShouldRunSlowPlane 别名）。</summary>
    public static bool HoldShouldRunSlowPlane(DateTime? last, double interval = ScgConsts.HoldKeepaliveInterval) =>
        ShouldRunSlowPlane(last, interval);

    private static HttpClient NewCemClient()
    {
        var handler = new SocketsHttpHandler
        {
            UseProxy = false, // 对齐 _NO_PROXY_OPENER：SCG 直连恒不走系统代理
            UseCookies = false,
            ConnectTimeout = TimeSpan.FromSeconds(15),
        };
        return new HttpClient(handler);
    }

    /// <summary>CEM oauth token（exchange_cem_access_token；code=="00000" → data.access_token）。</summary>
    public static async Task<string> ExchangeCemAccessTokenAsync(string scAuthCode, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(scAuthCode)) throw new InvalidOperationException("empty scAuthCode in firm auth response");
        using var http = NewCemClient();
        using var req = new HttpRequestMessage(HttpMethod.Post, ScgConsts.CemBase + "/gzs/auth/oauth/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["bizCode"] = ScgConsts.CemBizCode,
                ["client_id"] = ScgConsts.CemClientId,
                ["grant_type"] = "ext",
                ["source"] = "biz",
                ["token"] = scAuthCode,
            }),
        };
        using var resp = await http.SendAsync(req, ct).ConfigureAwait(false);
        string raw = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        string? code = root.TryGetProperty("code", out var c) && c.ValueKind == JsonValueKind.String ? c.GetString() : null;
        if (code != "00000")
        {
            string m = root.TryGetProperty("msg", out var mEl) ? mEl.GetString() ?? "" : "";
            throw new InvalidOperationException($"oauth/token failed: code={code} msg={m}");
        }
        string token = "";
        if (root.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Object &&
            data.TryGetProperty("access_token", out var at) && at.ValueKind == JsonValueKind.String)
            token = at.GetString() ?? "";
        if (token == "") throw new InvalidOperationException("oauth/token returned empty access_token");
        return token;
    }

    /// <summary>CEM API 调用（cem_request：Bearer + gzs-* 头族）。</summary>
    public static async Task<JsonObject> CemRequestAsync(string path, JsonObject body, string accessToken, string deviceId = "", CancellationToken ct = default)
    {
        string payload = body.ToJsonString();
        using var http = NewCemClient();
        using var req = new HttpRequestMessage(HttpMethod.Post, ScgConsts.CemBase + path)
        {
            Content = new StringContent(payload, Encoding.UTF8, "application/json"),
        };
        req.Headers.TryAddWithoutValidation("Authorization", "Bearer " + accessToken);
        req.Headers.TryAddWithoutValidation("gzs-client-id", ScgConsts.CemClientId);
        req.Headers.TryAddWithoutValidation("gzs-timestamp", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(CultureInfo.InvariantCulture));
        req.Headers.TryAddWithoutValidation("sc-terminal-sn", deviceId ?? "");
        req.Headers.TryAddWithoutValidation("sc-network-type", "2");
        req.Headers.TryAddWithoutValidation("sc-unit-type", "MacBookPro");
        req.Headers.TryAddWithoutValidation("User-Agent", "cdpsdk-macos-2.18.21(2.18.21.159)");
        using var resp = await http.SendAsync(req, ct).ConfigureAwait(false);
        string raw = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        return JsonNode.Parse(raw) as JsonObject ?? new JsonObject();
    }

    /// <summary>VM 就绪轮询（wait_vm_ready：20×3s；ready 时优先返回新 scAuthCode）。</summary>
    public static async Task<(int ReadyStatus, string ScAuthCode)> WaitVmReadyAsync(
        string accessToken, string vmId, string traceId, string deviceId = "", int attempts = 20, int intervalSec = 3, CancellationToken ct = default)
    {
        if (traceId == "") throw new InvalidOperationException("empty traceId; cannot wait VM ready");
        string vmEncrypted = ScgCrypto.CemRsaEncrypt(vmId);
        string lastError = "not ready";
        for (int attempt = 0; attempt < Math.Max(1, attempts); attempt++)
        {
            var result = await CemRequestAsync("/sc/open-portal/openapi/terminal/v1/getVmReadyStatus", new JsonObject
            {
                ["vmId"] = vmEncrypted,
                ["traceId"] = traceId,
            }, accessToken, deviceId, ct).ConfigureAwait(false);
            string? code = result["code"] is JsonValue cv && cv.TryGetValue<string>(out var c1) ? c1 : null;
            string? returnCode = result["returnCode"] is JsonValue rv && rv.TryGetValue<string>(out var c2) ? c2 : null;
            if (code == "00000" || returnCode == "00000")
            {
                if (result["data"] is JsonObject data)
                {
                    int readyNum = data["readyStatus"] is JsonValue rn && rn.TryGetValue<int>(out var rn2) ? rn2 : -1;
                    string readyText = data["readyStatus"] is JsonValue rt ? rt.ToJsonString().Trim('"') : "";
                    if (readyNum == 1 || readyText == "1")
                        return (1, data["scAuthCode"] is JsonValue sa && sa.TryGetValue<string>(out var sa2) ? sa2 : "");
                    lastError = $"readyStatus={readyText}";
                }
            }
            else
            {
                string? msg = result["msg"] is JsonValue mv ? mv.TryGetValue<string>(out var m1) ? m1 : null : null;
                string? returnMsg = result["returnMsg"] is JsonValue rm ? rm.TryGetValue<string>(out var m2) ? m2 : null : null;
                lastError = $"code={code ?? returnCode} msg={msg ?? returnMsg}";
            }
            if (attempt + 1 < attempts)
                await Task.Delay(TimeSpan.FromSeconds(Math.Max(0, intervalSec)), ct).ConfigureAwait(false);
        }
        throw new InvalidOperationException($"VM ready timeout after getConnectInfo trigger: {lastError}");
    }

    /// <summary>
    /// SCG 连接信息（get_connect_info）：oauth token → getConnectInfo；readyStatus!=1 且有
    /// traceId → 轮询 getVmReadyStatus 并优先其 scAuthCode。冷启动慢路径整体超时由调用方控制
    /// （lead 口径：单次 140s、有限次重试）。
    /// </summary>
    public static async Task<(string ScgIp, string ScgPort, string ScAuthCode, string TraceId, int ReadyStatus)> GetConnectInfoAsync(
        string scAuthCode, string vmId, string deviceId = "", CancellationToken ct = default)
    {
        string accessToken = await ExchangeCemAccessTokenAsync(scAuthCode, ct).ConfigureAwait(false);
        var result = await CemRequestAsync("/sc/open-portal/openapi/terminal/v1/getConnectInfo", new JsonObject
        {
            ["vmId"] = ScgCrypto.CemRsaEncrypt(vmId),
        }, accessToken, deviceId, ct).ConfigureAwait(false);
        string? code = result["code"] is JsonValue cv && cv.TryGetValue<string>(out var c1) ? c1 : null;
        string? returnCode = result["returnCode"] is JsonValue rv && rv.TryGetValue<string>(out var c2) ? c2 : null;
        if (code != "00000" && returnCode != "00000")
        {
            string? msg = result["msg"] is JsonValue mv ? mv.TryGetValue<string>(out var m1) ? m1 : null : null;
            string? returnMsg = result["returnMsg"] is JsonValue rm ? rm.TryGetValue<string>(out var m2) ? m2 : null : null;
            throw new InvalidOperationException($"getConnectInfo failed: code={code ?? returnCode} msg={msg ?? returnMsg}");
        }
        var data = result["data"] as JsonObject ?? new JsonObject();
        static string Str(JsonObject o, params string[] keys)
        {
            foreach (var k in keys)
                if (o[k] is JsonValue v && v.TryGetValue<string>(out var s) && s != "") return s;
            return "";
        }
        static int Num(JsonObject o, string key)
        {
            if (o[key] is JsonValue v)
            {
                if (v.TryGetValue<int>(out var i)) return i;
                if (v.TryGetValue<string>(out var s) && int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var i2)) return i2;
            }
            return 0;
        }
        string scgIp = Str(data, "scgIp", "scgIP");
        string scgPort = Str(data, "scgTcpPort", "scgPort");
        if (scgPort == "")
        {
            int portNum = Num(data, "scgTcpPort");
            if (portNum > 0) scgPort = portNum.ToString(CultureInfo.InvariantCulture);
        }
        if (scgPort == "") scgPort = "10800";
        if (scgIp == "") throw new InvalidOperationException("getConnectInfo returned empty scgIp");
        string freshAuth = Str(data, "scAuthCode");
        string authCode = freshAuth != "" ? freshAuth : scAuthCode;
        string traceId = Str(data, "traceId");
        int readyStatus = Num(data, "readyStatus");

        if (readyStatus != 1 && traceId != "")
        {
            var (rs, nextAuth) = await WaitVmReadyAsync(accessToken, vmId, traceId, deviceId, ct: ct).ConfigureAwait(false);
            if (nextAuth != "") authCode = nextAuth;
            if (rs == 1) readyStatus = 1;
        }
        return (scgIp, scgPort, authCode, traceId, readyStatus);
    }

    // -----------------------------------------------------------------------
    // TCP 认证 + TLS 升级（connect_scg）
    // -----------------------------------------------------------------------
    private static async Task<byte[]> ReadExactAsync(Stream stream, int n, int timeoutMs, CancellationToken ct)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(timeoutMs);
        var data = new byte[n];
        int off = 0;
        while (off < n)
        {
            int read = await stream.ReadAsync(data.AsMemory(off, n - off), timeoutCts.Token).ConfigureAwait(false);
            if (read <= 0) throw new EndOfStreamException("connection closed");
            off += read;
        }
        return data;
    }

    private static bool AllowAnyCert(object s, X509Certificate? c, X509Chain? ch, SslPolicyErrors e) => true;

    /// <summary>连 SCG 网关：TCP → 认证包 → 单次 Read 128B → 校验 byte[0] → sessionId → 同 socket 升 TLS（不校验证书）。</summary>
    public static async Task<ScgConnection> ConnectScgAsync(string scgIp, string scgPort, string scAuthCode, string vmId, int timeoutMs = 10000, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(scgIp) || string.IsNullOrEmpty(scgPort))
            throw new InvalidOperationException("SCG endpoint missing: scg_ip/scg_port are required");
        var tcp = new TcpClient();
        try
        {
            using (var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                connectCts.CancelAfter(timeoutMs);
                await tcp.ConnectAsync(scgIp, int.Parse(scgPort, CultureInfo.InvariantCulture), connectCts.Token).ConfigureAwait(false);
            }
            NetworkStream ns = tcp.GetStream();
            byte[] authPkt = ScgProtocol.BuildAuthPacket(scAuthCode, vmId);
            await ns.WriteAsync(authPkt, ct).ConfigureAwait(false);
            // 对齐 Go ConnectSCG：单次 Read 进 128B 缓冲，取 [6:9] 为 sessionId
            byte[] response = new byte[128];
            using (var readCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                readCts.CancelAfter(10000);
                int n = await ns.ReadAsync(response.AsMemory(0, 128), readCts.Token).ConfigureAwait(false);
                response = response[..n];
            }
            if (response.Length == 0 || response[0] != 0x00)
            {
                if (response.Length > 0 && response[0] == 0x0B)
                    throw new InvalidOperationException("auth downgrade (token expired or replay)");
                throw new InvalidOperationException($"auth failed: byte[0]=0x{(response.Length > 0 ? response[0] : 0xFF):x2}");
            }
            if (response.Length < 9)
                throw new InvalidOperationException($"auth response too short: {response.Length} bytes");
            int sessionId = (response[6] << 16) | (response[7] << 8) | response[8];

            // Go InsecureSkipVerify：私有 SCG 端点不校验证书、无 SNI
            var ssl = new SslStream(ns, leaveInnerStreamOpen: false, AllowAnyCert);
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = scgIp,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                RemoteCertificateValidationCallback = AllowAnyCert,
            }, ct).ConfigureAwait(false);
            return new ScgConnection(tcp, ssl, sessionId);
        }
        catch
        {
            try { ((IDisposable)tcp).Dispose(); } catch { /* 已断开 */ }
            throw;
        }
    }

    // -----------------------------------------------------------------------
    // 帧收发
    // -----------------------------------------------------------------------
    public static async Task<ScgFrame> RecvTrunkFrameAsync(Stream stream, int timeoutMs = 3000, CancellationToken ct = default)
    {
        byte[] head = await ReadExactAsync(stream, ScgConsts.FrameHeadSize, timeoutMs, ct).ConfigureAwait(false);
        if (head[0] != 1)
            throw new InvalidOperationException($"unexpected Chuanyun version {head[0]}");
        int pktType = head[1];
        int payloadLen = head[2] | (head[3] << 8);
        ulong f1 = 0, f2 = 0;
        for (int b = 0; b < 8; b++) f1 |= (ulong)head[8 + b] << (8 * b);
        for (int b = 0; b < 8; b++) f2 |= (ulong)head[16 + b] << (8 * b);
        byte[] payload = payloadLen > 0 ? await ReadExactAsync(stream, payloadLen, timeoutMs, ct).ConfigureAwait(false) : Array.Empty<byte>();
        return new ScgFrame(pktType, payload, f1, f2);
    }

    private static async Task WriteFrameAsync(Stream stream, byte[] frame, CancellationToken ct) =>
        await stream.WriteAsync(frame, ct).ConfigureAwait(false);

    /// <summary>PING→PONG / SET_ACK→ACK_SYNC 自动回包（_reply_keepalive_frame）。</summary>
    private static async Task ReplyKeepaliveFrameAsync(Stream stream, ulong sid, ScgFrame frame, CancellationToken ct)
    {
        if (frame.PktType != ScgConsts.DataType || frame.Payload.Length < 6) return;
        int msgType = frame.Payload[0] | (frame.Payload[1] << 8);
        if (msgType == 0x04) // PING → PONG
        {
            byte[] pingData = frame.Payload[6..];
            var pong = new byte[6 + pingData.Length];
            pong[0] = 0x03; pong[1] = 0x00;
            int len = pingData.Length;
            pong[2] = (byte)(len & 0xFF); pong[3] = (byte)((len >> 8) & 0xFF);
            pong[4] = (byte)((len >> 16) & 0xFF); pong[5] = (byte)((len >> 24) & 0xFF);
            Buffer.BlockCopy(pingData, 0, pong, 6, pingData.Length);
            await WriteFrameAsync(stream, YdpcBin.Concat(ScgProtocol.FrameHeadPack(ScgConsts.DataType, pong.Length, sid, frame.Field2), pong), ct).ConfigureAwait(false);
        }
        else if (msgType == 0x03) // SET_ACK → ACK_SYNC
        {
            uint generation = 0;
            if (frame.Payload.Length >= 10)
                generation = (uint)(frame.Payload[6] | (frame.Payload[7] << 8) | (frame.Payload[8] << 16) | (frame.Payload[9] << 24));
            var ack = new byte[10];
            ack[0] = 0x01; ack[1] = 0x00;
            ack[2] = 4; ack[3] = 0; ack[4] = 0; ack[5] = 0;
            ack[6] = (byte)(generation & 0xFF); ack[7] = (byte)((generation >> 8) & 0xFF);
            ack[8] = (byte)((generation >> 16) & 0xFF); ack[9] = (byte)((generation >> 24) & 0xFF);
            await WriteFrameAsync(stream, YdpcBin.Concat(ScgProtocol.FrameHeadPack(ScgConsts.DataType, ack.Length, sid, frame.Field2), ack), ct).ConfigureAwait(false);
        }
    }

    /// <summary>display 载荷处理（_handle_display_payload：mini 优先 DATA 兜底；回复排队统一发）。</summary>
    private static async Task HandleDisplayPayloadAsync(Stream stream, ulong sid, byte[] payload, Dictionary<string, bool> progress, CancellationToken ct)
    {
        byte[] data = ScgSpice.StripTokenPrefix(payload);
        var responses = new List<byte[]>();
        try
        {
            while (data.Length > 0)
            {
                int consumed = 0;
                if (data.Length >= ScgSpice.MiniHeaderSize)
                {
                    var mini = ScgSpice.DecodeMiniMessage(data);
                    if (mini.HasValue)
                    {
                        int mtype = mini.Value.Type;
                        bool known = mtype is ScgSpice.MsgSetAck or ScgSpice.MsgPing or ScgSpice.MsgPong or ScgSpice.MsgAckSync
                            or ScgSpice.MsgAck or ScgSpice.MsgMark or ScgSpice.MsgDisplayInit
                            or ScgSpice.MsgDrawCopy or ScgSpice.MsgSurfaceCreate;
                        if (known || mini.Value.Size <= data.Length - ScgSpice.MiniHeaderSize)
                        {
                            ApplyDisplaySpiceType(mtype, mini.Value.Payload, responses, progress);
                            consumed = ScgSpice.MiniHeaderSize + mini.Value.Size;
                        }
                    }
                }
                if (consumed == 0 && data.Length >= ScgSpice.DataHeaderSize)
                {
                    var msg = ScgSpice.DecodeDataMessage(data);
                    if (msg.HasValue)
                    {
                        ApplyDisplaySpiceType(msg.Value.Type, msg.Value.Payload, responses, progress);
                        consumed = ScgSpice.DataHeaderSize + msg.Value.Size;
                    }
                }
                if (consumed == 0) break;
                data = data[consumed..];
            }
        }
        catch
        {
            return; // 服务端可能合并不透明字节：解码失败也要保住连接
        }
        foreach (var resp in responses)
            await WriteFrameAsync(stream, YdpcBin.Concat(ScgProtocol.FrameHeadPack(ScgConsts.DataType, resp.Length, sid, ScgConsts.ChannelDisplay), resp), ct).ConfigureAwait(false);
    }

    /// <summary>display 已知 SPICE 类型处理（_apply_display_spice_type）。</summary>
    private static void ApplyDisplaySpiceType(int mtype, byte[] body, List<byte[]> responses, Dictionary<string, bool> progress)
    {
        if (mtype == ScgSpice.MsgSetAck)
        {
            uint gen = 1;
            if (body.Length >= 4)
                gen = (uint)(body[0] | (body[1] << 8) | (body[2] << 16) | (body[3] << 24));
            responses.Add(ScgSpice.EncodeAckSync(gen));
            progress["setAckReceived"] = true;
            progress["ackSyncSent"] = true;
        }
        else if (mtype == ScgSpice.MsgPing)
        {
            responses.Add(ScgSpice.EncodePong(body));
            progress["pingReceived"] = true;
            progress["pongSent"] = true;
        }
        else if (mtype == ScgSpice.MsgSurfaceCreate) progress["surfaceCreateReceived"] = true;
        else if (mtype == ScgSpice.MsgDrawCopy) progress["drawCopyReceived"] = true;
        else if (mtype == ScgSpice.MsgMark) progress["markReceived"] = true;
    }

    /// <summary>mouse_mode 请求（_send_mouse_mode：<HII = 0x69,4,2 主通道）。</summary>
    public static async Task SendMouseModeAsync(Stream stream, ulong sid, CancellationToken ct)
    {
        var payload = new byte[10];
        payload[0] = 0x69; payload[1] = 0x00;                             // u16 0x69
        payload[2] = 4; payload[3] = 0; payload[4] = 0; payload[5] = 0;   // u32 4
        payload[6] = 2; payload[7] = 0; payload[8] = 0; payload[9] = 0;   // u32 2
        await WriteFrameAsync(stream, YdpcBin.Concat(ScgProtocol.FrameHeadPack(ScgConsts.DataType, payload.Length, sid, ScgConsts.ChannelMain), payload), ct).ConfigureAwait(false);
    }

    /// <summary>SPICE ticket 发送（_send_ticket：auth_type u32=1 + OAEP-SHA1 空密码票据）。</summary>
    private static async Task<bool> SendTicketAsync(Stream stream, ulong sid, int channelId, byte[] payload, CancellationToken ct)
    {
        byte[]? pub = ScgSpice.FindReplyPubkey(payload);
        if (pub == null) return false;
        byte[] authType = { 1, 0, 0, 0 };
        byte[] ticket = ScgCrypto.SpiceTicketOaep(pub, Array.Empty<byte>());
        byte[] blob = YdpcBin.Concat(
            ScgProtocol.FrameHeadPack(ScgConsts.DataType, authType.Length, sid, (ulong)channelId), authType,
            ScgProtocol.FrameHeadPack(ScgConsts.DataType, ticket.Length, sid, (ulong)channelId), ticket);
        await WriteFrameAsync(stream, blob, ct).ConfigureAwait(false);
        return true;
    }

    // -----------------------------------------------------------------------
    // SPICE 握手（spice_handshake）
    // -----------------------------------------------------------------------
    public sealed record ScgSpiceHandshakeResult(
        ulong SessionId, int SpiceSessionId, List<string> ConnectedChannels,
        Dictionary<string, bool> Progress, bool SpiceOk, long Frames, long Responses);

    public static async Task<ScgSpiceHandshakeResult> SpiceHandshakeAsync(
        ScgConnection conn, string vmId = "", CancellationToken ct = default)
    {
        Stream stream = conn.Stream;
        ScgFrame first = await RecvTrunkFrameAsync(stream, 3000, ct).ConfigureAwait(false);
        ulong sid = first.Field1;
        int spiceSessionId = 0; // 仅从 MAIN_INIT 赋值（对齐 Go SpiceHandshake）
        int vmIdInt = int.TryParse((vmId ?? "").Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var vi) ? vi : 0;

        var connected = new List<string>();
        var progress = ScgSpice.CreateProgress();
        long frames = 1, responses = 0;

        async Task<ScgFrame> RecvFrameArAsync(int timeoutMs = 2000)
        {
            var frame = await RecvTrunkFrameAsync(stream, timeoutMs, ct).ConfigureAwait(false);
            frames++;
            await ReplyKeepaliveFrameAsync(stream, sid, frame, ct).ConfigureAwait(false);
            return frame;
        }

        async Task DisplayFrameHandlerAsync(ScgFrame f)
        {
            if (f.Field2 == (ulong)ScgConsts.ChannelDisplay && f.Payload.Length > 0)
            {
                try { await HandleDisplayPayloadAsync(stream, sid, f.Payload, progress, ct).ConfigureAwait(false); }
                catch { /* 解码失败保连接 */ }
            }
        }

        async Task<bool> AuthenticateChannelAsync(int channelId, int channelType, double waitSeconds, int connectionId)
        {
            var authBlob = ScgProtocol.BuildChannelAuth(sid, channelId, channelType, connectionId, vmIdInt);
            await WriteFrameAsync(stream, authBlob, ct).ConfigureAwait(false);
            var deadline = DateTime.UtcNow.AddSeconds(waitSeconds);
            while (DateTime.UtcNow < deadline)
            {
                ScgFrame frame;
                try { frame = await RecvFrameArAsync(2000).ConfigureAwait(false); }
                catch { break; }
                if (frame.PktType == ScgConsts.ControlType) continue;
                if (frame.Field2 != (ulong)channelId)
                {
                    await DisplayFrameHandlerAsync(frame).ConfigureAwait(false);
                    continue;
                }
                if (IndexOf(frame.Payload, "REDQ") < 0)
                {
                    if (channelId == ScgConsts.ChannelDisplay)
                        await DisplayFrameHandlerAsync(frame).ConfigureAwait(false);
                    continue;
                }
                if (!await SendTicketAsync(stream, sid, channelId, frame.Payload, ct).ConfigureAwait(false))
                    return false;
                for (int i = 0; i < 10; i++)
                {
                    if (DateTime.UtcNow >= deadline) break;
                    ScgFrame authFrame;
                    try { authFrame = await RecvFrameArAsync(2000).ConfigureAwait(false); }
                    catch { return false; }
                    if (authFrame.PktType == ScgConsts.ControlType) continue;
                    if (authFrame.Field2 != (ulong)channelId)
                    {
                        await DisplayFrameHandlerAsync(authFrame).ConfigureAwait(false);
                        continue;
                    }
                    if (authFrame.Payload.Length != 4) continue;
                    uint code = (uint)(authFrame.Payload[0] | (authFrame.Payload[1] << 8) | (authFrame.Payload[2] << 16) | (authFrame.Payload[3] << 24));
                    return code == 0;
                }
                return false;
            }
            return false;
        }

        async Task<int> WaitMainInitAsync(double waitSeconds = 30.0)
        {
            var deadline = DateTime.UtcNow.AddSeconds(waitSeconds);
            while (DateTime.UtcNow < deadline)
            {
                ScgFrame frame;
                try { frame = await RecvFrameArAsync(2000).ConfigureAwait(false); }
                catch { continue; }
                if (frame.PktType == ScgConsts.ControlType || frame.Field2 != ScgConsts.ChannelMain || frame.Payload.Length < 10)
                    continue;
                int msgType = frame.Payload[0] | (frame.Payload[1] << 8);
                int msgSize = frame.Payload[2] | (frame.Payload[3] << 8) | (frame.Payload[4] << 16) | (frame.Payload[5] << 24);
                if (msgType == ScgSpice.MsgMainInit && msgSize >= 4)
                    return frame.Payload[6] | (frame.Payload[7] << 8) | (frame.Payload[8] << 16) | (frame.Payload[9] << 24);
            }
            return 0;
        }

        // Go 同款 client_info + attach（hex 逐字对齐）
        byte[] clientInfo = Convert.FromHexString("7200140000001000000064000000080000002008010000000000");
        byte[] attachChannels = Convert.FromHexString("680000000000");

        async Task SendClientInfoAndAttachAsync()
        {
            await WriteFrameAsync(stream, YdpcBin.Concat(
                ScgProtocol.FrameHeadPack(ScgConsts.DataType, clientInfo.Length, sid, ScgConsts.ChannelMain), clientInfo,
                ScgProtocol.FrameHeadPack(ScgConsts.DataType, attachChannels.Length, sid, ScgConsts.ChannelMain), attachChannels), ct).ConfigureAwait(false);
            responses += 2;
        }

        async Task WaitChannelsListAsync(double waitSeconds = 20.0)
        {
            var deadline = DateTime.UtcNow.AddSeconds(waitSeconds);
            while (DateTime.UtcNow < deadline)
            {
                ScgFrame frame;
                try { frame = await RecvFrameArAsync(2000).ConfigureAwait(false); }
                catch { break; }
                if (frame.PktType == ScgConsts.ControlType) continue;
                if (frame.Field2 == ScgConsts.ChannelMain && frame.Payload.Length >= 6)
                {
                    int msgType = frame.Payload[0] | (frame.Payload[1] << 8);
                    if (msgType == ScgSpice.MsgChannelsList) break;
                }
            }
        }

        async Task WaitDisplayMarkAsync(double waitSeconds = 40.0)
        {
            var deadline = DateTime.UtcNow.AddSeconds(waitSeconds);
            for (int i = 0; i < 20; i++)
            {
                if (DateTime.UtcNow >= deadline) break;
                ScgFrame frame;
                try { frame = await RecvFrameArAsync(2000).ConfigureAwait(false); }
                catch { break; }
                if (frame.PktType == ScgConsts.ControlType) continue;
                if (frame.Field2 == ScgConsts.ChannelDisplay && frame.Payload.Length > 0)
                    await HandleDisplayPayloadAsync(stream, sid, frame.Payload, progress, ct).ConfigureAwait(false);
                if (progress.GetValueOrDefault("markReceived")) break;
                if (frame.Field2 != ScgConsts.ChannelDisplay || frame.Payload.Length < 6) continue;
                // 真机 SCG：MARK 是 payload[0:2] 的 mini type 102（无 token 前缀）
                int msgType = frame.Payload[0] | (frame.Payload[1] << 8);
                if (msgType == ScgSpice.MsgMark)
                {
                    progress["markReceived"] = true;
                    break;
                }
            }
        }

        if (await AuthenticateChannelAsync(ScgConsts.ChannelMain, 1 /* SpiceChannel.MAIN */, 40.0, 0).ConfigureAwait(false))
        {
            connected.Add("main");
            int mainInitSessionId = await WaitMainInitAsync().ConfigureAwait(false);
            if (mainInitSessionId != 0)
            {
                spiceSessionId = mainInitSessionId;
                await SendClientInfoAndAttachAsync().ConfigureAwait(false);
                await WaitChannelsListAsync().ConfigureAwait(false);
                if (await AuthenticateChannelAsync(ScgConsts.ChannelDisplay, 2 /* DISPLAY */, 120.0, spiceSessionId).ConfigureAwait(false))
                {
                    connected.Add("display");
                    byte[] init = ScgSpice.EncodeDisplayInit();
                    await WriteFrameAsync(stream, YdpcBin.Concat(
                        ScgProtocol.FrameHeadPack(ScgConsts.DataType, init.Length, sid, ScgConsts.ChannelDisplay), init), ct).ConfigureAwait(false);
                    progress["displayInitSent"] = true;
                    await WaitDisplayMarkAsync().ConfigureAwait(false);
                    if (await AuthenticateChannelAsync(ScgConsts.ChannelInputs, 3 /* INPUTS */, 60.0, spiceSessionId).ConfigureAwait(false))
                        connected.Add("inputs");
                    if (await AuthenticateChannelAsync(ScgConsts.ChannelCursor, 4 /* CURSOR */, 60.0, spiceSessionId).ConfigureAwait(false))
                        connected.Add("cursor");
                }
            }
        }

        return new ScgSpiceHandshakeResult(sid, spiceSessionId, connected, progress, spiceSessionId != 0, frames, responses);
    }

    private static int IndexOf(byte[] hay, string ascii)
    {
        var needle = Encoding.ASCII.GetBytes(ascii);
        for (int i = 0; i <= hay.Length - needle.Length; i++)
        {
            bool ok = true;
            for (int j = 0; j < needle.Length; j++)
                if (hay[i + j] != needle[j]) { ok = false; break; }
            if (ok) return i;
        }
        return -1;
    }

    // -----------------------------------------------------------------------
    // 保持切片（_run_once 的 hold 双平面：快 1s drain / 慢 25s SOHO+mouse）
    // -----------------------------------------------------------------------
    public sealed record ScgHoldResult(long Frames, long Responses, long TrunkSwitchReplies, long Heartbeats, long SohoHeartbeats, double WallSeconds);

    /// <summary>
    /// 保持切片：快平面 ~1s drain（帧回复 / trunk_switch 回显）；慢平面 ~25s
    /// （sohoHeartbeat 回调 + mouse_mode）。spiceOk=false 时不发 mouse_mode。
    /// </summary>
    public static async Task<ScgHoldResult> HoldAsync(
        ScgConnection conn, ulong sid, bool spiceOk, int durationSeconds,
        Func<CancellationToken, Task>? sohoHeartbeatAsync = null,
        Action<Exception>? onSlowPlaneError = null,
        CancellationToken ct = default)
    {
        Stream stream = conn.Stream;
        long heartbeats = 0, sohoHeartbeats = 0;
        DateTime? lastSlowPlane = null; // None → 首拍必发
        var started = DateTime.UtcNow;
        long frames = 0, responses = 0, switchReplies = 0;

        while (true)
        {
            double elapsed = (DateTime.UtcNow - started).TotalSeconds;
            if (durationSeconds > 0 && elapsed >= durationSeconds) break;

            // --- 慢平面：SOHO 心跳 + mouse_mode（~25s）---
            if (ShouldRunSlowPlane(lastSlowPlane))
            {
                lastSlowPlane = DateTime.UtcNow;
                heartbeats++;
                if (sohoHeartbeatAsync != null)
                {
                    try
                    {
                        await sohoHeartbeatAsync(ct).ConfigureAwait(false);
                        sohoHeartbeats++;
                    }
                    catch (Exception e)
                    {
                        onSlowPlaneError?.Invoke(e); // 心跳失败不影响快平面
                    }
                }
                if (spiceOk && sid != 0)
                    await SendMouseModeAsync(stream, sid, ct).ConfigureAwait(false);
            }

            // --- 快平面：~1s drain（_scg_sleep_drain：最多 5 帧、单帧 0.5s；_scg_probe_socket）---
            var sliceDeadline = DateTime.UtcNow.AddSeconds(
                durationSeconds > 0
                    ? Math.Min(ScgConsts.HoldSelectSeconds, Math.Max(0.05, durationSeconds - (DateTime.UtcNow - started).TotalSeconds))
                    : ScgConsts.HoldSelectSeconds);
            while (DateTime.UtcNow < sliceDeadline)
            {
                // probe：socket 已死立即抛（_scg_probe_socket）
                if (conn.Tcp.Client.Poll(0, SelectMode.SelectRead) && !conn.Tcp.Connected)
                    throw new EndOfStreamException("SCG connection lost");
                var list = new List<ScgFrame>();
                for (int i = 0; i < 5; i++)
                {
                    int remainMs = (int)Math.Max(1, (sliceDeadline - DateTime.UtcNow).TotalMilliseconds);
                    if (remainMs <= 1) break;
                    try
                    {
                        list.Add(await RecvTrunkFrameAsync(stream, Math.Min(500, remainMs), ct).ConfigureAwait(false));
                    }
                    catch (YdpcTimeoutException) { break; }
                    catch (EndOfStreamException) { throw; }
                }
                if (list.Count == 0) continue;
                frames += list.Count;
                foreach (var frame in list)
                {
                    if (frame.PktType == ScgConsts.TrunkSwitch)
                    {
                        if (frame.Payload.Length >= 32)
                        {
                            ulong targetCid = BitConverter.ToUInt64(frame.Payload, 0);
                            ulong senderCid = BitConverter.ToUInt64(frame.Payload, 8);
                            uint param = BitConverter.ToUInt32(frame.Payload, 16);
                            uint reason = frame.Payload[20];
                            ulong extraId = BitConverter.ToUInt64(frame.Payload, 24);
                            await WriteFrameAsync(stream, ScgProtocol.TrunkSwitchPack(senderCid, sid, param, reason, extraId, frame.Field1, frame.Field2), ct).ConfigureAwait(false);
                            switchReplies++;
                        }
                        continue;
                    }
                    await ReplyKeepaliveFrameAsync(stream, sid, frame, ct).ConfigureAwait(false);
                }
            }
            // probe（对齐 _scg_probe_socket）
            if (conn.Tcp.Client.Poll(0, SelectMode.SelectRead) && !conn.Tcp.Connected)
                throw new EndOfStreamException("SCG connection lost");
        }
        return new ScgHoldResult(frames, responses, switchReplies, heartbeats, sohoHeartbeats, (DateTime.UtcNow - started).TotalSeconds);
    }

    // -----------------------------------------------------------------------
    // 软失败分类（classify_scg_soft_failure）
    // -----------------------------------------------------------------------
    public static ScgFailureTags ClassifySoftFailure(Exception exc)
    {
        string msg = $"{exc.GetType().Name}: {exc.Message}";
        string low = msg.ToLowerInvariant();
        bool maintenance = false;
        string failReason = "scg_exception";
        foreach (var h in MaintenanceHints)
        {
            if (low.Contains(h, StringComparison.OrdinalIgnoreCase))
            {
                maintenance = true;
                failReason = "vm_powered_off";
                break;
            }
        }
        foreach (var h in CemBlipHints)
        {
            if (low.Contains(h, StringComparison.OrdinalIgnoreCase))
            {
                if (failReason == "scg_exception")
                    failReason = low.Contains("token") ? "token_transient" : "scg_cem_blip";
                if (low.Contains("502") || low.Contains("503") || low.Contains("504") ||
                    low.Contains("维护") || low.Contains("maintenance"))
                    maintenance = true;
                break;
            }
        }
        return new ScgFailureTags(msg, true, maintenance, failReason);
    }
}
