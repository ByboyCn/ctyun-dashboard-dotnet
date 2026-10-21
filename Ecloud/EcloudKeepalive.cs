// =============================================================================
// CtyunDashboard.Ecloud / EcloudKeepalive.cs
// =============================================================================
// 对齐参考实现（Python，只读）：app/ecloud_engine/keepalive.py + desktop_session.py
//   ──────────────────────────────────────────────────────────────────────────
//   KeepaliveOutcome（ok 三态：true/false/null）→ EcloudKeepaliveOutcome
//   keepalive_probe()：USER_GET_INFO → USER_GET_DEVICE_INFO → PROBE_QKK_BATCHPUSH
//     三接口依次尝试；任一成功 ⇒ ok=true（单端点 401 是端点级风控，绝不据此重登）；
//     全部失败且至少一个 token 失效 ⇒ ok=false（触发重登）；
//     全部失败但均非 token 错误 ⇒ ok=null（瞬时/5xx，不重登）
//                                             → KeepaliveProbeAsync
//   _push_probe()（reportDataUtil.js PROBE_QKK_BATCHPUSH 事件体）→ PushProbeAsync
//   _is_token_expired()（hints：token/登录失效/未登录/请重新登录/授权/过期；
//     刻意不含过宽的 "access"）                → IsTokenExpired
//   desktop_session.DesktopSession             → EcloudDesktopSession
//     report_uptime()（POST /resource/desktopUptime {instanceId} → "X小时X分X秒"）
//                                             → ReportUptimeAsync（NO_UPTIME 视为桌面可能已关机）
//     renew_session_status()（静默信号 A：/session/updateSessionStatus
//         {instanceId, machineId, loginStatus:1, loginUid}）
//     report_connect_event()（静默信号 B：/machine/pushConnectEventData，
//         CloudEvents 形态 specversion/id/source/type/datacontenttype/time/data）
//     keepalive_once()（uptime 为主 + 两个静默信号：不写日志、失败全吞、互不拖累）
//                                             → KeepaliveOnceAsync
//   _is_token_expired()（desktop_session 版，同 hints）→ 同 IsTokenExpired
//
// 另对齐 Node 桥接 app/ecloud/ecloud_client.js：
//   parseUptimeSeconds()（"X小时X分X秒" → 秒；解析失败 -1，绝不猜 0）
//   UPTIME_REGRESSION_MIN_SEC=60（在线时长回退 ⇒ 平台会话记录被重建 ⇒ 疑似关机证据）
//                                             → ParseUptimeSeconds / UptimeRegressionMinSec
//
// 诚实性口径（不可放宽）：L1/L2 是 HTTP 层探针，成功 ≠ 云电脑不会被关机；
// 三态必须原样保留，把 null 压成 false 会引发每轮密码重登 → 短信轰炸。
//
// AOT：JsonElement/JsonObject 手工解包，零反射。
// =============================================================================

using System.Globalization;
using System.Text.Json.Nodes;

namespace CtyunDashboard.Ecloud;

/// <summary>一轮账号态保活结果（keepalive.KeepaliveOutcome；Ok 三态语义见类注释）。</summary>
public sealed record EcloudKeepaliveOutcome(bool? Ok, string Error = "");

public static class EcloudKeepalive
{
    /// <summary>在线时长回退告警的最小幅度（秒）：小于此值视为解析差异/抖动，不报。</summary>
    public const int UptimeRegressionMinSec = 60;

    /// <summary>L1 账号态保活探针一次（keepalive_probe 三态原样保留）。</summary>
    public static async Task<EcloudKeepaliveOutcome> KeepaliveProbeAsync(EcloudHttpUtil http, CancellationToken ct = default)
    {
        bool success = false;
        string tokenErr = ""; // token 失效样错误：仅当【全部接口失败】时才据此重登
        string lastErr = "";  // 最近一个非 token 错误（null 分支的诊断日志）

        // 1. 用户信息
        try
        {
            await http.PostAsync(EcloudConfig.Endpoints.UserGetInfo, ct: ct).ConfigureAwait(false);
            success = true;
        }
        catch (EcloudException e)
        {
            string detail = $"[{e.Code}] {e.ServerMessage}";
            if (IsTokenExpired(e)) tokenErr = tokenErr == "" ? detail : tokenErr;
            else lastErr = detail;
        }

        // 2. 桌面列表
        try
        {
            await http.PostAsync(EcloudConfig.Endpoints.UserGetDeviceInfo, ct: ct).ConfigureAwait(false);
            success = true;
        }
        catch (EcloudException e)
        {
            string detail = $"[{e.Code}] {e.ServerMessage}";
            if (IsTokenExpired(e)) tokenErr = tokenErr == "" ? detail : tokenErr;
            else lastErr = detail;
        }

        // 3. 探针上报（模拟客户端正常上报；失败不影响保活判定）
        try
        {
            await PushProbeAsync(http, ct).ConfigureAwait(false);
            success = true;
        }
        catch (EcloudException e)
        {
            string detail = $"[{e.Code}] {e.ServerMessage}";
            if (IsTokenExpired(e)) tokenErr = tokenErr == "" ? detail : tokenErr;
            else if (lastErr == "") lastErr = detail;
        }

        if (success)
        {
            // 任一接口成功 → 会话仍有效（端点级 401 是风控/抖动，绝不重登）
            return new EcloudKeepaliveOutcome(true);
        }
        if (tokenErr != "")
        {
            // 全部失败且至少一个 token 失效 → 真失效，需重登
            return new EcloudKeepaliveOutcome(false, tokenErr);
        }
        // 全部失败但均为非 token 错误（瞬时/服务端故障）→ null，避免误触发密码重登
        return new EcloudKeepaliveOutcome(null, lastErr);
    }

    /// <summary>上报一条探针事件（_push_probe；reportDataUtil.js 283-291）。</summary>
    private static async Task PushProbeAsync(EcloudHttpUtil http, CancellationToken ct)
    {
        long nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var evt = new JsonObject
        {
            ["eventSeq"] = nowMs.ToString(CultureInfo.InvariantCulture),
            ["eventCode"] = EcloudConfig.LoginType.Password.ToString(CultureInfo.InvariantCulture),
            ["eventName"] = "keepalive",
            ["eventType"] = "1",
            ["eventValue"] = "1",
            ["eventStatus"] = "0",
            ["apiTime"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture),
            ["appVersion"] = EcloudConfig.ClientVersion,
        };
        await http.PostAsync(EcloudConfig.Endpoints.ProbeQkkBatchPush, new JsonObject
        {
            ["list"] = new JsonArray(evt),
        }, ct: ct).ConfigureAwait(false);
    }

    /// <summary>token 失效判定（keepalive._is_token_expired；hints 刻意收窄，"access" 会误伤）。</summary>
    public static bool IsTokenExpired(EcloudException e)
    {
        string msg = (e.ServerMessage ?? "").ToLowerInvariant();
        return msg.Contains("token") || msg.Contains("登录失效") || msg.Contains("未登录") ||
               msg.Contains("请重新登录") || msg.Contains("授权") || msg.Contains("过期");
    }

    /// <summary>
    /// "X小时X分X秒" → 秒；无法解析一律 -1（未知，绝不猜 0）（对齐 parseUptimeSeconds）。
    /// 【2026-10-21 真机修复】支持部分单位形态："45秒"、"5分30秒"、"1小时5分"、"0分23秒"。
    /// </summary>
    public static long ParseUptimeSeconds(string? text)
    {
        string s = text ?? "";
        long hours = 0, minutes = 0, seconds = 0;
        bool any = false;
        int hIdx = s.IndexOf("小时", StringComparison.Ordinal);
        if (hIdx > 0 && TryParseBackwardsDigits(s, hIdx, out hours)) any = true;
        int mIdx = s.IndexOf("分", StringComparison.Ordinal);
        if (mIdx > 0 && TryParseBackwardsDigits(s, mIdx, out minutes)) any = true;
        int sIdx = s.IndexOf("秒", StringComparison.Ordinal);
        if (sIdx > 0 && TryParseBackwardsDigits(s, sIdx, out seconds)) any = true;
        return any ? hours * 3600 + minutes * 60 + seconds : -1;
    }

    /// <summary>从 idx 往前取连续数字（对应正则 (\d+)\s*单位 的捕获语义）。</summary>
    private static bool TryParseBackwardsDigits(string s, int idx, out long value)
    {
        value = 0;
        int i = idx;
        while (i > 0 && (s[i - 1] == ' ' || s[i - 1] == '\u00a0')) i--;
        long mul = 1;
        bool any = false;
        while (i > 0 && s[i - 1] >= '0' && s[i - 1] <= '9')
        {
            value += (s[i - 1] - '0') * mul;
            mul *= 10;
            i--;
            any = true;
        }
        return any;
    }
}

// -----------------------------------------------------------------------------
// L2 桌面会话保活（desktop_session.DesktopSession）
// -----------------------------------------------------------------------------
public sealed class EcloudDesktopSession
{
    private readonly EcloudHttpUtil _http;
    private readonly string _loginUid; // 跨轮稳定（服务端会话状态机据此识别同一登录会话）

    public string InstanceId { get; }
    public string MachineId { get; }
    public string MachineName { get; }
    public string LastUptime { get; private set; } = "";
    public string LastError { get; private set; } = "";
    public bool LastErrorTokenExpired { get; private set; }
    public string ConnectId { get; private set; } = Guid.NewGuid().ToString();

    public EcloudDesktopSession(EcloudHttpUtil http, string instanceId,
        string machineId = "", string machineName = "", string loginUid = "")
    {
        _http = http;
        InstanceId = instanceId;
        MachineId = machineId;
        MachineName = machineName;
        _loginUid = loginUid != "" ? loginUid : Guid.NewGuid().ToString();
    }

    /// <summary>
    /// 查询/刷新桌面运行时长（保活核心）。
    /// 【2026-10-21 真机修复】服务端解密后的形态有两种（真机抓包均已出现）：
    ///   ① {"uptime":"X小时X分X秒"}（对象 + 标准字段）
    ///   ② {"state":"OK","body":"16小时0分23秒","errorCode":"200"} —— body 直接是时长**字符串**；
    ///      HandleResponse 对非对象 body 回落整个信封，因此这里必须在信封里认出 body 字段。
    /// Python 母本 desktop_session.report_uptime 对非 dict 响应本就 str(resp) 兜底，本修复对齐该语义。
    /// </summary>
    public async Task<string> ReportUptimeAsync(CancellationToken ct = default)
    {
        var resp = await _http.PostAsync(EcloudConfig.Endpoints.DesktopUptime, new JsonObject
        {
            ["instanceId"] = InstanceId,
        }, ct: ct).ConfigureAwait(false);

        string? uptime = ExtractUptimeText(resp);
        if (string.IsNullOrEmpty(uptime) || uptime == "None")
            throw new EcloudException("NO_UPTIME", $"desktopUptime 未返回运行时长，桌面可能已关机: {resp.ToJsonString()}");
        LastUptime = uptime;
        LastError = "";
        LastErrorTokenExpired = false;
        return uptime;
    }

    /// <summary>从解密响应中提取时长文本；识别不了返回 null（调用方按 NO_UPTIME 处理）。</summary>
    internal static string? ExtractUptimeText(JsonObject? resp)
    {
        if (resp == null) return null;
        // 形态②：信封 body 字段直接是时长字符串（{"state":"OK","body":"16小时0分23秒"}）
        if (resp["body"] is JsonValue bv && bv.TryGetValue<string>(out var bodyStr) && LooksLikeUptime(bodyStr))
            return bodyStr;
        // 形态①：标准字段
        foreach (var k in new[] { "uptime", "upTime", "runningTime", "duration" })
        {
            if (resp[k] is JsonValue v && v.TryGetValue<string>(out var s) && LooksLikeUptime(s)) return s;
        }
        // 兜底：任意字符串字段长得像时长（覆盖未知信封形态，绝不把无单位杂串当时长）
        foreach (var p in resp)
        {
            if (p.Value is JsonValue v && v.TryGetValue<string>(out var sv) && LooksLikeUptime(sv)) return sv;
        }
        return null;
    }

    /// <summary>像不像时长文本：含任一时间单位（"45秒"/"5分30秒"/"16小时0分23秒" 等部分单位形态均算）。</summary>
    private static bool LooksLikeUptime(string? s) =>
        !string.IsNullOrEmpty(s) && s != "None" &&
        (s.Contains("小时", StringComparison.Ordinal) || s.Contains("分", StringComparison.Ordinal) || s.Contains("秒", StringComparison.Ordinal));


    /// <summary>
    /// 会话状态续期（静默信号 A）：POST /session/updateSessionStatus ——
    /// machineConnect 需要真实 ticket（仅真实连接握手产生），故用无票的本接口承载
    /// "会话在场"语义。真机 2026-09-27 验证被接受（响应 "ok"）。
    /// 纪律：不写日志、失败由调用方吞掉。
    /// </summary>
    private async Task<bool> RenewSessionStatusAsync(CancellationToken ct)
    {
        if (InstanceId == "" || MachineId == "") return false;
        await _http.PostAsync(EcloudConfig.Endpoints.UpdateSessionStatus, new JsonObject
        {
            ["instanceId"] = InstanceId,
            ["machineId"] = MachineId,
            ["loginStatus"] = 1,
            ["loginUid"] = _loginUid,
        }, ct: ct).ConfigureAwait(false);
        return true;
    }

    /// <summary>
    /// 连接事件上报（静默信号 B）：POST /machine/pushConnectEventData ——
    /// CloudEvents 形态（真机 2026-09-27 逐字段试探确认，服务端响应 "ok"）。
    /// 纪律同上。
    /// </summary>
    private async Task<bool> ReportConnectEventAsync(CancellationToken ct)
    {
        if (InstanceId == "" || MachineId == "") return false;
        await _http.PostAsync(EcloudConfig.Endpoints.PushConnectEvent, new JsonObject
        {
            ["specversion"] = "1.0",
            ["id"] = Guid.NewGuid().ToString(),
            ["source"] = "ecloud-cloudpc",
            ["type"] = "machine.connect",
            ["datacontenttype"] = "application/json",
            ["time"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            ["data"] = new JsonObject
            {
                ["instanceId"] = InstanceId,
                ["machineId"] = MachineId,
            },
        }, ct: ct).ConfigureAwait(false);
        return true;
    }

    /// <summary>
    /// 执行一次桌面保活（keepalive_once）：report_uptime 为主；静默附带两个会话侧信号
    /// （独立 try —— 一个失败不拖累另一个；任何静默失败绝不影响返回值）。
    /// </summary>
    public async Task<bool> KeepaliveOnceAsync(CancellationToken ct = default)
    {
        bool ok = false;
        try
        {
            await ReportUptimeAsync(ct).ConfigureAwait(false);
            ok = true;
        }
        catch (EcloudException e)
        {
            LastError = $"[{e.Code}] {e.ServerMessage}";
            LastErrorTokenExpired = EcloudKeepalive.IsTokenExpired(e);
        }
        foreach (Func<CancellationToken, Task<bool>> signal in new[] { RenewSessionStatusAsync, ReportConnectEventAsync })
        {
            try { await signal(ct).ConfigureAwait(false); }
            catch { /* 静默信号失败全吞 */ }
        }
        return ok;
    }
}
