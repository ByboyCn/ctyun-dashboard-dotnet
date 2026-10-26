using System.Buffers.Binary;
using System.Net.WebSockets;
using System.Text;

namespace CtyunDashboard.CtYun;

/// <summary>connect/status 返回的 desktopInfo —— CLINK 连接全部材料。</summary>
public class ClinkConfig
{
    public string ProxyBase { get; set; } = "";
    public string DesktopId { get; set; } = "";
    public string InternalIp { get; set; } = "";
    public string InternalPort { get; set; } = "9011";
    public string ClientCert { get; set; } = "";
    public string ClientKey { get; set; } = "";
    public string CaCert { get; set; } = "";
    public string Token { get; set; } = "";
    public int Oqs { get; set; }

    public static ClinkConfig FromResponse(System.Text.Json.JsonElement resp)
    {
        var info = resp.ValueKind == System.Text.Json.JsonValueKind.Object &&
                   resp.TryGetProperty("desktopInfo", out var nested) && nested.ValueKind == System.Text.Json.JsonValueKind.Object
            ? nested : resp;
        string Read(string name)
        {
            foreach (var src in new[] { info, resp })
                if (src.ValueKind == System.Text.Json.JsonValueKind.Object &&
                    src.TryGetProperty(name, out var v) &&
                    v.ValueKind is System.Text.Json.JsonValueKind.String or System.Text.Json.JsonValueKind.Number &&
                    !string.IsNullOrWhiteSpace(v.ToString())) return v.ToString();
            return "";
        }
        var gateway = Read("clinkLvsOutHost");
        if (gateway.Length == 0) gateway = Read("clinkLvsInHost");
        if (gateway.Length == 0) throw new InvalidDataException("服务器未返回连接网关");
        var address = gateway.Contains("://") ? gateway : "wss://" + gateway;
        if (!Uri.TryCreate(address, UriKind.Absolute, out var uri)) throw new InvalidDataException("网关地址无效: " + gateway);
        var builder = new UriBuilder(uri) { Path = "/clinkProxy" };
        if (uri.IsDefaultPort && !gateway.Contains("://") &&
            !System.Text.RegularExpressions.Regex.IsMatch(gateway, @":\d+(?:/|$)")) builder.Port = 9011;
        var cfg = new ClinkConfig
        {
            ProxyBase = builder.Uri.AbsoluteUri.TrimEnd('/'),
            DesktopId = Read("desktopId"), InternalIp = Read("internalIp"), InternalPort = Read("internalPort"),
            ClientCert = Read("clientCert"), ClientKey = Read("clientKey"), CaCert = Read("caCert"),
            Token = Read("token"),
            Oqs = int.TryParse(Read("desktopCertCategory"), out var oqs) ? oqs : 0,
        };
        if (cfg.DesktopId.Length == 0 || cfg.InternalIp.Length == 0 || cfg.ClientCert.Length == 0 ||
            cfg.ClientKey.Length == 0 || cfg.CaCert.Length == 0) throw new InvalidDataException("连接响应缺少有效材料");
        return cfg;
    }
}

/// <summary>
/// CLINK MAIN 通道（保活专用，单通道）。
/// 流程：WS(/clinkProxy/{desktopId}/MAIN) → JSON 探针 → 0x01 → REDQ LinkMess → LinkReply →
///       RSA-OAEP ticket → AuthReply → READY → (MAIN_INIT 后) 118 身份 [→ 112 认领 + 104 订阅]。
/// 旁观者脉冲：claim=false（不发 112/104，绝不顶掉官方客户端）；挂机/打卡：claim=true。
/// 在席信令：119/120/137 = 官方客户端在场。
/// </summary>
public sealed class ClinkMain : IDisposable
{
    public const byte MAIN = 1;

    private readonly ClientWebSocket _ws = new();
    private readonly ClinkConfig _cfg;
    private readonly Action<string, string, string> _log; // level, scope, msg
    private readonly string _account;
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private readonly CancellationTokenSource _cts = new();
    private readonly TaskCompletionSource _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly FrameReader _reader = new();
    private readonly MemoryStream _handshake = new();

    private string _userName = "";
    private long _userId;
    private bool _claim;
    private bool _earlyLogin;
    private uint _ackWindow, _untilAck;
    private readonly bool _dump =
        string.Equals(Environment.GetEnvironmentVariable("CTYUN_CLINK_DUMP")?.Trim(), "1", StringComparison.OrdinalIgnoreCase);

    public bool Ready { get; private set; }
    public bool HandshakeDone { get; private set; }
    public bool ClaimSent { get; private set; }
    public long RedqCount { get; private set; }
    public long BytesRecv { get; private set; }
    public DateTime? LastPresenceAt { get; private set; }
    public string LastCloseReason { get; private set; } = "";
    public Task ReadyTask => _ready.Task;

    public ClinkMain(ClinkConfig cfg, string account, Action<string, string, string> log)
    {
        _cfg = cfg; _account = account; _log = log;
        _ws.Options.AddSubProtocol("binary");
        _ws.Options.SetRequestHeader("Origin", "https://pc.ctyun.cn");
        _ws.Options.SetRequestHeader("User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36");
        _ws.Options.KeepAliveInterval = Timeout.InfiniteTimeSpan; // 心跳自己发（Type 7）
        // CLINK 网关（国内）从海外机房不可达（脉冲全超时）→ 支持经中国代理隧道出站：
        // CTYUN_PROXY_URL=http://host:port（与 ECLOUD_PROXY_URL 同一代理即可，CONNECT 隧道透传 wss）
        var wsProxy = Environment.GetEnvironmentVariable("CTYUN_PROXY_URL")?.Trim();
        if (!string.IsNullOrEmpty(wsProxy))
        {
            _ws.Options.Proxy = new System.Net.WebProxy(wsProxy);
            _log("info", account, "CLINK 心跳走代理出站: " + wsProxy);
        }
    }

    private static string Esc(string s) => (s ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "").Replace("\r", "");

    public async Task ConnectAsync(string userName, long userId, bool claim, CancellationToken ct)
    {
        _userName = userName; _userId = userId; _claim = claim;
        var url = $"{_cfg.ProxyBase}/{_cfg.DesktopId}/MAIN";
        await _ws.ConnectAsync(new Uri(url), ct);

        var probe = "{\"type\":1,\"ssl\":1,\"host\":\"" + Esc(_cfg.InternalIp) + "\",\"port\":\"" + Esc(_cfg.InternalPort) +
                    "\",\"ca\":\"" + Esc(_cfg.CaCert) + "\",\"cert\":\"" + Esc(_cfg.ClientCert) + "\",\"key\":\"" + Esc(_cfg.ClientKey) +
                    "\",\"servername\":\"" + Esc(_cfg.InternalIp + ":" + _cfg.InternalPort) + "\",\"oqs\":" + _cfg.Oqs + "}";
        await SendTextAsync(probe, ct);

        var first = await ReadExactAsync(1, ct);
        if (first[0] != 1) throw new Exception($"探针失败 首字节=0x{first[0]:X2}");

        await SendBinaryAsync(BuildLink(MAIN, 0, 0), ct);

        var hdr = await ReadExactAsync(16, ct);
        if (Encoding.ASCII.GetString(hdr, 0, 4) != "REDQ") throw new Exception("LinkReply magic 错误");
        RedqCount++;
        var bodySize = BinaryPrimitives.ReadInt32LittleEndian(hdr.AsSpan(12));
        if (bodySize is < 4 or > 1024 * 1024) throw new InvalidDataException("LinkReply 长度无效: " + bodySize);
        var body = await ReadExactAsync(bodySize, ct);
        if (BinaryPrimitives.ReadInt32LittleEndian(body.AsSpan(0, 4)) != 0) throw new Exception("LinkReply error!=0");
        if (body.Length < 178) throw new InvalidDataException("LinkReply 缺少公钥字段");
        var pubKey = body.AsSpan(4, 162).ToArray();
        _earlyLogin = HasChannelCapability(body, 11);
        HandshakeDone = true;

        var ticket = CyCrypto.RsaEncryptTicketSpki(pubKey, [0]);
        var auth = new byte[4 + ticket.Length];
        BinaryPrimitives.WriteInt32LittleEndian(auth, 1);
        ticket.CopyTo(auth, 4);
        _log("info", _account, $"CLINK ticket 已提交 ({ticket.Length}B, SPKI 前缀 0x{pubKey[0]:X2}{pubKey[1]:X2}, earlyLogin={_earlyLogin})，等待 AuthReply…");
        await SendBinaryAsync(auth, ct);

        var authCode = await ReadExactAsync(4, ct);
        if (BinaryPrimitives.ReadInt32LittleEndian(authCode) != 0) throw new Exception("AuthReply code!=0");

        // 【根因修复】认证已通过（AuthReply==0）：完成 ReadyTask。
        // 此前 _ready 只在 ReceiveLoopAsync 的 finally（连接退出）里 TrySetResult，
        // 成功路径永不完成 → Engine 的 ReadyTask.WaitAsync(30s) 必然超时
        //（表象恰似"服务端不回 AuthReply"，但 103/MAIN_INIT 能到达即证明认证早已通过）。
        Ready = true;
        _ready.TrySetResult();
        _log("info", _account, $"CLINK 认证通过 (ticket={ticket.Length}B, earlyLogin={_earlyLogin})");
        _ = Task.Run(() => ReceiveLoopAsync(_cts.Token));
        _ = Task.Run(async () =>   // CLINK_MSGC_HEARTBEAT Type 7
        {
            try
            {
                while (!_cts.IsCancellationRequested && Ready)
                {
                    await Task.Delay(30_000, _cts.Token);
                    await SendMiniAsync(7, [], _cts.Token);
                }
            }
            catch { }
        });
    }

    private static byte[] BuildLink(byte type, byte id, uint session)
    {
        uint[] caps = type == MAIN ? [0x804u] : [];
        var data = new byte[16 + 18 + 4 + caps.Length * 4];
        "REDQ"u8.CopyTo(data);
        Put(data, 4, 2); Put(data, 8, 2); Put(data, 12, (uint)data.Length - 16);
        Put(data, 16, session); data[20] = type; data[21] = id;
        Put(data, 22, 1); Put(data, 26, (uint)caps.Length); Put(data, 30, 18); Put(data, 34, 9);
        for (var i = 0; i < caps.Length; i++) Put(data, 38 + i * 4, caps[i]);
        return data;
    }

    private static bool HasChannelCapability(byte[] reply, int bit)
    {
        var common = BinaryPrimitives.ReadUInt32LittleEndian(reply.AsSpan(166));
        var channels = BinaryPrimitives.ReadUInt32LittleEndian(reply.AsSpan(170));
        var offset = BinaryPrimitives.ReadUInt32LittleEndian(reply.AsSpan(174));
        if (offset < 178) throw new InvalidDataException("LinkReply 能力偏移无效");
        return channels > bit / 32 &&
               (BinaryPrimitives.ReadUInt32LittleEndian(reply.AsSpan((int)(offset + common * 4 + bit / 32 * 4))) & (1u << (bit % 32))) != 0;
    }

    // Type 112 认领包（desktopId/token/账号），对齐 realclient ClinkWire.LoginInfo
    private static byte[] LoginInfo(string desktopId, string token, string account)
    {
        var values = new[] { token, "60", "web", account }.Select(Encoding.UTF8.GetBytes).ToArray();
        var data = new byte[36 + values.Sum(v => v.Length + 1)];
        Put(data, 0, uint.Parse(desktopId));
        var offset = 36;
        for (var i = 0; i < values.Length; i++)
        {
            Put(data, 4 + i * 8, (uint)values[i].Length + 1);
            Put(data, 8 + i * 8, (uint)offset);
            values[i].CopyTo(data, offset);
            offset += values[i].Length + 1;
        }
        return data;
    }

    // Type 118 身份 JSON
    private static byte[] CustomMessage(string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        var data = new byte[8 + bytes.Length];
        Put(data, 0, (uint)bytes.Length); Put(data, 4, 8);
        bytes.CopyTo(data, 8);
        return data;
    }

    private async Task OnMessageAsync(ushort type, byte[] payload, CancellationToken ct)
    {
        // 【诊断】CTYUN_CLINK_DUMP=1 时逐帧 dump（REDQ 后收到的每一条 mini 帧进日志）
        if (_dump)
        {
            var head = Convert.ToHexString(payload, 0, Math.Min(payload.Length, 32));
            _log("info", _account, $"[dump] 帧 type={type} len={payload.Length} hex={(payload.Length > 32 ? head + "…" : head)}");
        }
        if (type == 3 && payload.Length == 8)
        {
            _ackWindow = BinaryPrimitives.ReadUInt32LittleEndian(payload.AsSpan(4));
            _untilAck = _ackWindow;
            await SendMiniAsync(1, payload[..4], ct);
        }
        else if (type == 4 && payload.Length >= 12)
        {
            await SendMiniAsync(3, payload[..12], ct);
        }

        if (type is 119 or 120 or 137)
        {
            LastPresenceAt = DateTime.Now;   // 官方客户端在场信令
            if (_claim)
                _log("warning", _account, $"检测到官方客户端在席信令 (type={type})，挂机认领将主动避让");
        }
        else if (type == 103)   // MAIN_INIT
        {
            var json = "{\"type\":1,\"userName\":\"" + Esc(_userName) + "\",\"userInfo\":\"\",\"userId\":" + _userId + "}";
            await SendMiniAsync(118, CustomMessage(json), ct);
            if (_claim)
            {
                await SendMiniAsync(112, LoginInfo(_cfg.DesktopId, _cfg.Token, _userName), ct);
                ClaimSent = true;
                if (!_earlyLogin) await SendMiniAsync(104, [], ct);
            }
            _log("info", _account, _claim ? "REDQ 握手完成，已发送 118 身份 + 112 认领" : "REDQ 握手完成，旁观者模式（118 身份，无认领）");
        }
        else if (type == 104 && _claim)
        {
            _log("info", _account, "收到服务器通道确认，认领会话就绪");
        }
    }

    private async Task ReceiveLoopAsync(CancellationToken ct)
    {
        var seg = new byte[64 * 1024];
        try
        {
            while (!ct.IsCancellationRequested && _ws.State == WebSocketState.Open)
            {
                var r = await _ws.ReceiveAsync(new ArraySegment<byte>(seg), ct);
                if (r.MessageType == WebSocketMessageType.Close) { LastCloseReason = "服务端关闭"; break; }
                BytesRecv += r.Count;
                var data = r.EndOfMessage ? seg.AsSpan(0, r.Count).ToArray() : null;
                if (!r.EndOfMessage)
                {
                    _handshake.Write(seg, 0, r.Count);
                    continue;
                }
                byte[] chunk;
                if (_handshake.Length > 0)
                {
                    _handshake.Write(seg, 0, r.Count);
                    chunk = _handshake.ToArray();
                    _handshake.SetLength(0);
                }
                else chunk = data!;
                _reader.Feed(chunk, async (t, p) => await OnMessageAsync(t, p, ct));
                if (_ackWindow > 0 && --_untilAck == 0)
                {
                    _untilAck = _ackWindow;
                    await SendMiniAsync(2, [], ct);
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { LastCloseReason = ex.Message; }
        finally
        {
            Ready = false;
            // 成功路径已在认证通过点 TrySetResult（此处幂等）；失败/提前断开路径
            // 以异常完成，让 Engine 的 WaitAsync 立刻失败而不是空等 30 秒。
            if (!_ready.Task.IsCompleted)
            {
                if (!string.IsNullOrEmpty(LastCloseReason))
                    _ready.TrySetException(new IOException("CLINK 连接在就绪前关闭: " + LastCloseReason));
                else
                    _ready.TrySetResult();
            }
        }
    }

    private sealed class FrameReader
    {
        private byte[] _buf = new byte[0];
        public void Feed(byte[] data, Func<ushort, byte[], Task> onMsg)
        {
            var merged = new byte[_buf.Length + data.Length];
            _buf.CopyTo(merged, 0);
            data.CopyTo(merged, _buf.Length);
            var off = 0;
            while (off + 6 <= merged.Length)
            {
                var type = BinaryPrimitives.ReadUInt16LittleEndian(merged.AsSpan(off));
                var size = BinaryPrimitives.ReadInt32LittleEndian(merged.AsSpan(off + 2));
                if (size < 0 || size > merged.Length - off - 6) break;
                var payload = new byte[size];
                Array.Copy(merged, off + 6, payload, 0, size);
                off += 6 + size;
                _ = onMsg(type, payload);
            }
            _buf = merged[off..];
        }
    }

    public async Task SendMiniAsync(ushort type, byte[] payload, CancellationToken ct)
    {
        if (_ws.State != WebSocketState.Open) throw new IOException("WS 未开启");
        var m = new byte[6 + payload.Length];
        BinaryPrimitives.WriteUInt16LittleEndian(m, type);
        BinaryPrimitives.WriteInt32LittleEndian(m.AsSpan(2), payload.Length);
        payload.CopyTo(m, 6);
        await SendBinaryAsync(m, ct);
    }

    private async Task SendBinaryAsync(byte[] data, CancellationToken ct)
    {
        await _sendLock.WaitAsync(ct);
        try { await _ws.SendAsync(new ArraySegment<byte>(data), WebSocketMessageType.Binary, true, ct); }
        finally { _sendLock.Release(); }
    }

    private async Task SendTextAsync(string text, CancellationToken ct)
    {
        await _sendLock.WaitAsync(ct);
        try { await _ws.SendAsync(new ArraySegment<byte>(Encoding.UTF8.GetBytes(text)), WebSocketMessageType.Text, true, ct); }
        finally { _sendLock.Release(); }
    }

    private async Task<byte[]> ReadExactAsync(int n, CancellationToken ct)
    {
        while (_handshake.Length < n)
        {
            var seg = new byte[16 * 1024];
            var r = await _ws.ReceiveAsync(new ArraySegment<byte>(seg), ct);
            if (r.MessageType == WebSocketMessageType.Close) throw new Exception("握手期间连接被关闭");
            _handshake.Write(seg, 0, r.Count);
        }
        var all = _handshake.ToArray();
        var result = all.AsSpan(0, n).ToArray();
        _handshake.SetLength(0);
        _handshake.Write(all, n, all.Length - n);
        return result;
    }

    public void Dispose()
    {
        Ready = false;
        try { _cts.Cancel(); _ws.Dispose(); } catch { }
    }

    private static void Put(byte[] data, int offset, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset), value);
}
