// =============================================================================
// CtyunDashboard.Ydpc / MqttClient.cs
// =============================================================================
// 对齐参考实现（Node.js，只读）：app/ydpc/mqtt_client.js
// —— 移动云官方 MQTT 3.1.1 over TLS (8883) 长连接保活客户端。
//
// 【2026-10-20 用户指令变更】MQTT 通道改用 MQTTnet 官方库（NuGet: MQTTnet 5.2.0.1603），
// 不再使用手写原生报文实现（CONNECT/CONNACK/SUBSCRIBE/PUBLISH/PINGREQ 的编解码交由
// MQTTnet 承担）。报文层之外的语义仍逐条对齐 mqtt_client.js：
//
//   mqtt_client.js                        → 本文件（MQTTnet 实现）
//   ──────────────────────────────────────────────────────────────────────────
//   buildMqttConnectPacket()              → MQTTnet MqttClientOptionsBuilder：
//                                            协议版本 V311（Level 0x04）、CleanSession
//                                            （0xC2 的 0x02 位）、UserName/Password 凭据、
//                                            KeepAlive u16（WithKeepAlivePeriod）
//   connect(timeoutMs)                    → MqttKeepAliveClient.StartAsync()：
//                                            · 双栈选路优先 IPv4（WithTcpServer(host, port,
//                                              AddressFamily.InterNetwork)，同时保留原始 host
//                                              做 TLS SNI/证书校验，等价 JS targetIp+servername）
//                                            · JS rejectUnauthorized:false → 默认
//                                              WithCertificateValidationHandler(_ => true)（可关）
//                                            · CONNACK returnCode!=0 → 错误文案对齐 JS errCodes 表
//   startPingLoop()                       → 内部循环：interval = max(10, floor(keepAlive*0.75)) 秒
//                                            发一次 PINGREQ（MQTTnet 自身另按 keepalive 自动 ping）
//   pingOnce()                            → PingAsync()：发 PINGREQ 并等 PINGRESP（MQTTnet
//                                            PingAsync 收到响应才返回，LastPongTime 因此更准确）
//   disconnect()（内联 0xE0 0x00）        → StopAsync()：先 DisconnectAsync(NormalDisconnection)
//                                            再释放客户端
//   lastPingTime / lastPongTime           → LastPingTime / LastPongTime（毫秒时间戳）
//   （任务书扩展）SUBSCRIBE/PUBLISH       → SubscribeAsync(topic, qos) + OnPublish 回调
//
// NativeAOT：MQTTnet 客户端路径零反射、零序列化，PublishAot 兼容。
// 依赖：csproj 中 <PackageReference Include="MQTTnet" Version="5.2.0.1603" />（应用户指令引入；
//       这是唯一一处 Ydpc/ 目录之外的改动，由本文件的需求驱动）。
// =============================================================================

using System.Buffers;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text.Json;
using MQTTnet;
using MQTTnet.Formatter;
using MQTTnet.Protocol;

namespace CtyunDashboard.Ydpc;

/// <summary>官方 /system/mqttConnect/v1 返回的 Broker 连接凭据（由 YdpcAccountClient 解析填充）。</summary>
public sealed class MqttCredential
{
    public string Host { get; set; } = "alive.soho.komect.com";
    public int Port { get; set; } = 8883;
    public string ClientId { get; set; } = "";
    public string UserName { get; set; } = "";
    /// <summary>官方 MQTT 凭证字段为 jwt（非 password）—— 由调用方把 jwt 填到这里。</summary>
    public string Password { get; set; } = "";
    public int KeepAliveSeconds { get; set; } = 60;

    /// <summary>
    /// 对齐 ydpc_client.js ensureMqttConnection 的官方返回结构解析：
    /// url 形如 "ssl://alive.soho.komect.com[:port]"（ssl/mqtts/tcp 前缀）；
    /// 官方标准 MQTTS 端口 8883（未指定或配成 443 都回退 8883，防火墙会丢 443）；
    /// 凭据字段 jwt / userName / mqttKeepAlive（默认 30s）。
    /// </summary>
    public static MqttCredential FromSohoConnectInfo(JsonElement info, string fallbackClientId)
    {
        string host = "alive.soho.komect.com";
        int port = 8883;
        string url = JsonStr(info, "url");
        if (!string.IsNullOrEmpty(url))
        {
            // 解析 ssl://host[:port] / mqtts:// / tcp://
            int schemeEnd = url.IndexOf("://", StringComparison.Ordinal);
            string rest = schemeEnd >= 0 ? url[(schemeEnd + 3)..] : url;
            int slash = rest.IndexOf('/');
            if (slash >= 0) rest = rest[..slash];
            int colon = rest.LastIndexOf(':');
            if (colon > 0 && int.TryParse(rest[(colon + 1)..], NumberStyles.Integer, CultureInfo.InvariantCulture, out int p))
            {
                host = rest[..colon];
                port = p;
            }
            else if (rest.Length > 0)
            {
                host = rest;
            }
        }
        else
        {
            string h = JsonStr(info, "host");
            if (!string.IsNullOrEmpty(h)) host = h;
            int p2 = JsonInt(info, "port", 0);
            if (p2 > 0 && p2 != 443) port = p2;
        }

        string clientId = OrDefault(JsonStr(info, "clientId"), fallbackClientId);
        string username = OrDefault(JsonStr(info, "userName"), JsonStr(info, "username"));
        string password = OrDefault(JsonStr(info, "jwt"), JsonStr(info, "password"));
        int keepAlive = JsonInt(info, "mqttKeepAlive", JsonInt(info, "keepAlive", 0));
        if (keepAlive <= 0) keepAlive = 30;

        return new MqttCredential
        {
            Host = host,
            Port = port != 443 ? port : 8883,
            ClientId = clientId,
            UserName = username,
            Password = password,
            KeepAliveSeconds = keepAlive
        };
    }

    private static string JsonStr(JsonElement e, string n)
    {
        if (e.ValueKind == JsonValueKind.Object && e.TryGetProperty(n, out JsonElement p) && p.ValueKind == JsonValueKind.String)
            return p.GetString() ?? "";
        return "";
    }

    private static int JsonInt(JsonElement e, string n, int dflt)
    {
        if (e.ValueKind == JsonValueKind.Object && e.TryGetProperty(n, out JsonElement p))
        {
            if (p.ValueKind == JsonValueKind.Number && p.TryGetInt32(out int v)) return v;
            if (p.ValueKind == JsonValueKind.String && int.TryParse(p.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out int v2)) return v2;
        }
        return dflt;
    }

    private static string OrDefault(string a, string b) => !string.IsNullOrEmpty(a) ? a : (b ?? "");
}

/// <summary>收到的官方下行 PUBLISH（由 MQTTnet 解码后转发给 OnPublish 回调）。</summary>
public sealed class MqttPublishMessage
{
    public string Topic { get; init; } = "";
    public byte[] Payload { get; init; } = Array.Empty<byte>();
    public int Qos { get; init; }
    public bool Dup { get; init; }
    public bool Retain { get; init; }
}

// -----------------------------------------------------------------------------
// MQTT 长连接保活客户端（MQTTnet 承载）
// -----------------------------------------------------------------------------
public sealed class MqttKeepAliveClient : IAsyncDisposable
{
    /// <summary>对齐 JS 默认 Broker。</summary>
    public const string DefaultHost = "alive.soho.komect.com";
    public const int DefaultPort = 8883;

    private readonly Action<string, string>? _log;
    private readonly MqttClientFactory _factory = new();
    private readonly SemaphoreSlim _ioLock = new(1, 1);
    private readonly bool _allowInsecureTls;

    private IMqttClient? _client;
    private MqttCredential _cred = new();
    private CancellationTokenSource? _pingCts;
    private Task? _pingTask;
    private long _lastPingTime;
    private long _lastPongTime;
    private Func<MqttPublishMessage, Task>? _onPublish;

    /// <summary>allowInsecureTls 默认 true，对齐 JS rejectUnauthorized:false（MQTTS 自签证书可用）。</summary>
    public MqttKeepAliveClient(Action<string, string>? log = null, bool allowInsecureTls = true)
    {
        _log = log;
        _allowInsecureTls = allowInsecureTls;
    }

    private void Log(string level, string msg) => _log?.Invoke(level, $"[MQTT] {msg}");

    public bool IsConnected => _client?.IsConnected == true;
    public long LastPingTime => Interlocked.Read(ref _lastPingTime);
    public long LastPongTime => Interlocked.Read(ref _lastPongTime);
    public MqttCredential Credential => _cred;

    /// <summary>收到官方下行 PUBLISH 时的回调（可选；异常不会拖垮接收循环）。</summary>
    public Func<MqttPublishMessage, Task>? OnPublish { get => _onPublish; set => _onPublish = value; }

    /// <summary>
    /// 建立 TLS 连接并完成 MQTT CONNECT 握手（对齐 connect(timeoutMs=15000)）。
    /// 双栈网络优先选 IPv4（消除无 IPv6 网关时的超时假死）；原始 host 保留给 TLS SNI。
    /// </summary>
    public async Task StartAsync(MqttCredential cred, int timeoutMs = 15000, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(cred);
        await StopInternalAsync().ConfigureAwait(false); // 对齐 JS connect() 开头的 disconnect()
        _cred = cred;

        int port = cred.Port > 0 && cred.Port != 443 ? cred.Port : DefaultPort; // 443 会被防火墙丢包，回退 8883
        string host = string.IsNullOrEmpty(cred.Host) ? DefaultHost : cred.Host;
        string clientId = string.IsNullOrEmpty(cred.ClientId)
            ? "client_" + Guid.NewGuid().ToString("N")[..16]
            : cred.ClientId;

        var builder = new MqttClientOptionsBuilder()
            // 双栈优先 IPv4；host 仍写入 DnsEndPoint 之外的 TLS TargetHost（SNI/证书校验不丢）
            .WithTcpServer(host, port, AddressFamily.InterNetwork)
            .WithProtocolVersion(MqttProtocolVersion.V311) // MQTT 3.1.1（协议级别 0x04）
            .WithCleanSession()                            // ConnectFlags 0xC2 的 CleanSession 位
            .WithClientId(clientId)
            .WithTimeout(TimeSpan.FromMilliseconds(Math.Max(1000, timeoutMs)))
            .WithKeepAlivePeriod(TimeSpan.FromSeconds(Math.Max(1, cred.KeepAliveSeconds)))
            .WithTlsOptions(o =>
            {
                o.WithSslProtocols(SslProtocols.Tls12 | SslProtocols.Tls13);
                if (_allowInsecureTls)
                {
                    o.WithCertificateValidationHandler(_ => true); // 对齐 JS rejectUnauthorized:false
                }
            });
        if (!string.IsNullOrEmpty(cred.UserName) || !string.IsNullOrEmpty(cred.Password))
        {
            builder.WithCredentials(cred.UserName ?? "", cred.Password ?? "");
        }

        MqttClientOptions options = builder.Build();
        IMqttClient client = _factory.CreateMqttClient();
        client.ApplicationMessageReceivedAsync += OnApplicationMessageReceivedAsync;

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(timeoutMs);
        try
        {
            MqttClientConnectResult connack = await client.ConnectAsync(options, timeoutCts.Token).ConfigureAwait(false);
            if (connack.ResultCode != MqttClientConnectResultCode.Success)
            {
                int rc = (int)connack.ResultCode;
                await DisposeClientAsync().ConfigureAwait(false);
                throw new InvalidOperationException($"MQTT 认证被拒绝: {ConnackErrorText(rc)}");
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            await DisposeClientAsync().ConfigureAwait(false);
            throw new TimeoutException($"MQTT TLS 连接超时 ({timeoutMs}ms)");
        }
        catch
        {
            await DisposeClientAsync().ConfigureAwait(false);
            throw;
        }

        _client = client;
        StartPingLoop();
        Log("success", $"🟢 MQTT 3.1.1 over TLS 握手成功 (Broker: {host}:{port})");
    }

    /// <summary>CONNACK returnCode → 中文文案（对齐 JS errCodes 表；3.1.1 回码 0..5）。</summary>
    private static string ConnackErrorText(int rc) => rc switch
    {
        1 => "协议版本不受支持",
        2 => "客户端标识符被拒绝",
        3 => "服务不可用",
        4 => "用户名或密码格式错误",
        5 => "未授权连接",
        _ => $"错误代码 {rc}"
    };

    private Task OnApplicationMessageReceivedAsync(MqttApplicationMessageReceivedEventArgs e)
    {
        MqttApplicationMessage m = e.ApplicationMessage;
        var msg = new MqttPublishMessage
        {
            Topic = m.Topic ?? "",
            Payload = m.Payload.Length > 0 ? m.Payload.ToArray() : Array.Empty<byte>(),
            Qos = (int)m.QualityOfServiceLevel,
            Dup = m.Dup,
            Retain = m.Retain
        };
        Func<MqttPublishMessage, Task>? cb = _onPublish;
        if (cb != null)
        {
            _ = Task.Run(async () =>
            {
                try { await cb(msg).ConfigureAwait(false); }
                catch { /* 回调异常不得拖垮接收循环 */ }
            });
        }
        return Task.CompletedTask;
    }

    /// <summary>对齐 startPingLoop：interval = max(10, floor(keepAlive*0.75)) 秒，周期发送 PINGREQ。
    /// （MQTTnet 另按 WithKeepAlivePeriod 自动保活；本循环负责 LastPingTime/LastPongTime 观测与 JS 节奏对齐。）</summary>
    private void StartPingLoop()
    {
        if (_pingTask != null) return;
        int intervalSec = Math.Max(10, (int)Math.Floor(_cred.KeepAliveSeconds * 0.75));
        _pingCts = new CancellationTokenSource();
        CancellationToken loopCt = _pingCts.Token;
        _pingTask = Task.Run(async () =>
        {
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(intervalSec));
            try
            {
                while (await timer.WaitForNextTickAsync(loopCt).ConfigureAwait(false))
                {
                    try
                    {
                        await PingAsync(CancellationToken.None).ConfigureAwait(false);
                    }
                    catch
                    {
                        // 与 JS 一致：保活探测失败静默（断线由 IsConnected/引擎重连处理）
                    }
                }
            }
            catch (OperationCanceledException) { }
        });
    }

    /// <summary>对齐 pingOnce：发送一次 PINGREQ 并等待 PINGRESP（MQTTnet PingAsync 收到响应才返回）。</summary>
    public async Task PingAsync(CancellationToken ct = default)
    {
        IMqttClient? client = _client;
        if (client == null || !client.IsConnected)
            throw new InvalidOperationException("MQTT 客户端未连接");
        Interlocked.Exchange(ref _lastPingTime, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        await _ioLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await client.PingAsync(ct).ConfigureAwait(false);
        }
        finally { _ioLock.Release(); }
        Interlocked.Exchange(ref _lastPongTime, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
    }

    /// <summary>SUBSCRIBE（QoS 0/1/2；保活路径默认不使用）。</summary>
    public async Task SubscribeAsync(string topic, int qos = 0, CancellationToken ct = default)
    {
        IMqttClient? client = _client;
        if (client == null || !client.IsConnected)
            throw new InvalidOperationException("MQTT 客户端未连接");
        var qosLevel = (MqttQualityOfServiceLevel)Math.Clamp(qos, 0, 2);
        await _ioLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await client.SubscribeAsync(topic, qosLevel, ct).ConfigureAwait(false);
        }
        finally { _ioLock.Release(); }
    }

    /// <summary>对齐 disconnect()：停 ping 循环、发 DISCONNECT、释放客户端。</summary>
    public async Task StopAsync()
    {
        await StopInternalAsync().ConfigureAwait(false);
    }

    private async Task StopInternalAsync()
    {
        if (_pingCts != null)
        {
            try { _pingCts.Cancel(); } catch { /* 已取消 */ }
        }
        IMqttClient? client = _client;
        if (client != null)
        {
            try
            {
                if (client.IsConnected)
                {
                    await client.DisconnectAsync(
                        MqttClientDisconnectOptionsReason.NormalDisconnection,
                        cancellationToken: CancellationToken.None).ConfigureAwait(false);
                }
            }
            catch { /* 已断开 */ }
        }
        if (_pingTask != null)
        {
            try { await _pingTask.ConfigureAwait(false); } catch { /* 收尾 */ }
        }
        try { _pingCts?.Dispose(); } catch { /* 已释放 */ }
        await DisposeClientAsync().ConfigureAwait(false);
        _pingTask = null;
        _pingCts = null;
    }

    private async Task DisposeClientAsync()
    {
        IMqttClient? client = _client;
        _client = null;
        if (client != null)
        {
            client.ApplicationMessageReceivedAsync -= OnApplicationMessageReceivedAsync;
            try { client.Dispose(); } catch { /* 已释放 */ }
        }
    }

    public async ValueTask DisposeAsync()
    {
        await StopInternalAsync().ConfigureAwait(false);
        _ioLock.Dispose();
    }
}
