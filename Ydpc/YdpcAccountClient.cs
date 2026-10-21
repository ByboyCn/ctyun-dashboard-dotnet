// =============================================================================
// CtyunDashboard.Ydpc / YdpcAccountClient.cs
// =============================================================================
// 对齐参考实现（Node.js，只读）：
//   · app/ydpc/ydpc_client.js      —— 组合 Soho/CAG/MQTT 三通道；login / refreshVms /
//                                    sendHeartbeat / pingCag / ensureMqttConnection /
//                                    controlPower；runWithGrade 的 tokenRetry 重登重试语义；
//                                    isYdpcVmOff 关机判定；「假成功」防线（没做事必须 success=false）
//   · app/ydpc/product_route.js    —— classifyZteError（G2 软/硬失败三分类）+ shouldTripBreaker
//
// 逐函数对齐清单：
//   ydpc_client.js                     → 本文件
//   ──────────────────────────────────────────────────────────────────────────
//   constructor + this.sohoClient      → YdpcAccountClient（持有 SohoClient/CagClient/MqttKeepAliveClient）
//   login()                            → LoginAsync()（SOHO 鉴权 + 成功/失败日志）
//   refreshVms()（简化版）             → GetVmsAsync()（保证登录 → listCloudPcs；底座嗅探/
//                                        差量合并归引擎层，这里只给权威机器列表）
//   isYdpcVmOff()                      → IsVmOff()（关机/停止/未开机/到期/未知 + 23/16/0）
//   sendHeartbeat()                    → KeepaliveOnceAsync 内 SOHO 心跳步（含 pointEvent 埋点）
//   pingCag()                          → KeepaliveOnceAsync 内 CAG 握手步（含「没材料先拒绝」/
//                                        「SCG 无 CAG 通道」两类 skipped）
//   ensureMqttConnection()             → EnsureMqttAsync()（5 分钟失败冷却 + 官方凭据解析）
//   runWithGrade()                     → RunStepAsync()（tokenRetry ⇒ 重登一次再试；
//                                        success===false / skip 信号 ⇒ 记 skipped，不算失败）
//   controlPower(shutdown/reboot)      → ShutdownAsync() / RebootAsync()
//   classifyZteError()/shouldTripBreaker → YdpcErrors.Classify()/ShouldTripBreaker()
//
// 熔断/重试语义（简化版，完整引擎调度由 lead 统一写）：
//   · tokenRetry（会话/token 失效）→ 重新登录一次后重试该步；重试成功即视同本轮成功；
//   · soft（维护/升级/时长耗尽/限流/已关机）→ 只告警不熔断；
//   · hard（TLS/DNS/网络层/未知）→ 记异常并置 TripBreaker=true，调用方可熔断本轮后续拨号；
//   · skipped（机器已关机 / SCG 无 CAG 通道 / CAG 材料缺失）→ 既不记成功也不当失败告警。
//
// NativeAOT：全文件零反射、零序列化；SOHO 响应经 JsonElement 解析。
// =============================================================================

using System.Globalization;
using System.Text.Json;

namespace CtyunDashboard.Ydpc;

// -----------------------------------------------------------------------------
// G2 失败分级（product_route.js classifyZteError 移植；顺序即优先级：tokenRetry → hard → soft）
// -----------------------------------------------------------------------------
public enum YdpcErrorKind
{
    None = 0,
    /// <summary>会话 / token 失效 → 重登后重试即可，不当成链路故障。</summary>
    TokenRetry = 1,
    /// <summary>已知非致命（维护 / 升级 / 时长耗尽 / 已关机 / 限流）→ 只告警不熔断。</summary>
    Soft = 2,
    /// <summary>真异常（TLS / DNS / 网络层与一切未知错误）→ 兜底熔断。</summary>
    Hard = 3
}

public static class YdpcErrors
{
    // tokenRetry：/1000100/、\b4001\b、\b4003\b、未登录、未授权、鉴权失败、登录失效、已失效、
    //             会话、重新登录、unauthorized(i)、\b401\b、token(i)、accessToken(i)
    private static readonly string[] TokenRetryPlain = { "1000100", "未登录", "未授权", "鉴权失败", "登录失效", "已失效", "会话", "重新登录" };
    private static readonly string[] TokenRetryWords = { "4001", "4003", "401" };
    private static readonly string[] TokenRetryIc = { "unauthorized", "token" };

    // hard：CERT_(i)、UNABLE_TO_VERIFY(i)、self[-_ ]?signed(i)、证书、ENOTFOUND(i)、EAI_AGAIN(i)、
    //       \bDNS\b(i)、getaddrinfo(i)、ECONNREFUSED(i)、ECONNRESET(i)、EPIPE(i)、ETIMEDOUT(i)、
    //       EHOSTUNREACH(i)、ENETUNREACH(i)、socket hang up(i)、超时、timeout(i)
    private static readonly string[] HardPlain = { "证书", "超时" };
    private static readonly string[] HardSelfSignedIc = { "self-signed", "self_signed", "self signed" };
    private static readonly string[] HardIc =
    {
        "cert_", "unable_to_verify", "enotfound", "eai_again", "getaddrinfo",
        "econnrefused", "econnreset", "epipe", "etimedout", "ehostunreach", "enetunreach",
        "socket hang up", "timeout"
    };
    private static readonly string[] HardWordsIc = { "dns" };

    // soft：用完、已用尽、计费周期、欠费、时长、到期、维护、升级、已关机、未开机、关机、
    //       启动中、正在启动、启动时间过长、\bbusy\b(i)、too many(i)、限流、频繁、稍后重试、
    //       请稍候、\b104\b
    private static readonly string[] SoftPlain =
    {
        "用完", "已用尽", "计费周期", "欠费", "时长", "到期", "维护", "升级",
        "已关机", "未开机", "关机", "启动中", "正在启动", "启动时间过长", "限流", "频繁", "稍后重试", "请稍候"
    };
    private static readonly string[] SoftIc = { "too many" };
    private static readonly string[] SoftWordsIc = { "busy", "104" };

    /// <summary>对齐 classifyZteError：空/非字符串输入一律 hard（fail-safe：宁可多报不静默降级）。</summary>
    public static YdpcErrorKind Classify(string? text)
    {
        string s = (text ?? "").Trim();
        if (s.Length == 0) return YdpcErrorKind.Hard;

        foreach (string p in TokenRetryPlain) if (s.Contains(p, StringComparison.Ordinal)) return YdpcErrorKind.TokenRetry;
        foreach (string w in TokenRetryWords) if (ContainsWord(s, w)) return YdpcErrorKind.TokenRetry;
        string lower = s.ToLowerInvariant();
        foreach (string p in TokenRetryIc) if (lower.Contains(p, StringComparison.Ordinal)) return YdpcErrorKind.TokenRetry;

        foreach (string p in HardPlain) if (s.Contains(p, StringComparison.Ordinal)) return YdpcErrorKind.Hard;
        foreach (string p in HardSelfSignedIc) if (lower.Contains(p, StringComparison.Ordinal)) return YdpcErrorKind.Hard;
        foreach (string p in HardIc) if (lower.Contains(p, StringComparison.Ordinal)) return YdpcErrorKind.Hard;
        foreach (string w in HardWordsIc) if (ContainsWord(s, w)) return YdpcErrorKind.Hard;

        foreach (string p in SoftPlain) if (s.Contains(p, StringComparison.Ordinal)) return YdpcErrorKind.Soft;
        foreach (string p in SoftIc) if (lower.Contains(p, StringComparison.Ordinal)) return YdpcErrorKind.Soft;
        foreach (string w in SoftWordsIc) if (ContainsWord(s, w)) return YdpcErrorKind.Soft;

        return YdpcErrorKind.Hard;
    }

    /// <summary>对齐 shouldTripBreaker：只有 hard 需要把本轮标记为异常（tokenRetry/soft 均不熔断）。</summary>
    public static bool ShouldTripBreaker(YdpcErrorKind kind) => kind == YdpcErrorKind.Hard;

    /// <summary>\b 词边界匹配（等价 JS \b&lt;word&gt;\b；词字符 = [A-Za-z0-9_]）。</summary>
    private static bool ContainsWord(string s, string word)
    {
        int start = 0;
        while (start <= s.Length - word.Length)
        {
            int idx = s.IndexOf(word, start, StringComparison.Ordinal);
            if (idx < 0) return false;
            bool leftOk = idx == 0 || !IsWordChar(s[idx - 1]);
            int end = idx + word.Length;
            bool rightOk = end >= s.Length || !IsWordChar(s[end]);
            if (leftOk && rightOk) return true;
            start = idx + 1;
        }
        return false;
    }

    private static bool IsWordChar(char c) => c == '_' || char.IsAsciiLetterOrDigit(c);
}

// -----------------------------------------------------------------------------
// 账号配置与结果载体
// -----------------------------------------------------------------------------
public sealed class YdpcAccountOptions
{
    public string Name { get; set; } = "";
    public string User { get; set; } = "";
    public string Password { get; set; } = "";
    /// <summary>'main'（和家亲主号）| 'sub'（独立子号）。</summary>
    public string AccountType { get; set; } = "main";
    /// <summary>设备码（缺省由 SohoClient 随机生成）。</summary>
    public string? DeviceCode { get; set; }
    public int KeepaliveIntervalSec { get; set; } = 600;

    // —— 通道开关（对齐 account.features，缺省全开；单机开关归引擎层） ——
    public bool KeepAlive { get; set; } = true;
    public bool ControlPlaneKeepalive { get; set; } = true;
    public bool MqttKeepAlive { get; set; } = true;
    public bool DataPlaneKeepalive { get; set; } = true;
}

/// <summary>一次完整保活轮的结果（每台机器每轮一个）。</summary>
public sealed class KeepaliveRoundResult
{
    public bool Success { get; internal set; }
    /// <summary>本轮没做任何实事（已关机 / 无材料 / SCG 无通道）。</summary>
    public bool Skipped { get; internal set; }
    public string Message { get; internal set; } = "";
    public bool HeartbeatOk { get; internal set; }
    public bool CagOk { get; internal set; }
    public bool MqttEnsured { get; internal set; }
    public YdpcErrorKind FailureKind { get; internal set; } = YdpcErrorKind.None;
    public string FailureText { get; internal set; } = "";
    /// <summary>是否应当熔断本轮后续拨号（对齐 shouldTripBreaker）。</summary>
    public bool TripBreaker => YdpcErrors.ShouldTripBreaker(FailureKind);
    public List<string> Actions { get; } = new();
}

// -----------------------------------------------------------------------------
// 组合客户端
// -----------------------------------------------------------------------------
public sealed class YdpcAccountClient : IAsyncDisposable
{
    private readonly Action<string, string>? _log;
    private readonly YdpcAccountOptions _options;
    private readonly CagClient _cag;
    private DateTime _lastMqttFailedAtUtc;
    private List<SohoVm> _vms = new();

    public SohoClient Soho { get; }
    public MqttKeepAliveClient? Mqtt { get; private set; }

    /// <summary>最近一次 GetVmsAsync 的机器列表（对齐 account.vms 的权威快照）。</summary>
    public IReadOnlyList<SohoVm> Vms => _vms;

    public string AccountName => string.IsNullOrEmpty(_options.Name) ? _options.User : _options.Name;

    /// <summary>候选 userServiceId（对齐 vms?.[0]?.userServiceId 兜底）。</summary>
    public string? DefaultUserServiceId => _vms.Count > 0
        ? (string.IsNullOrEmpty(_vms[0].UserServiceIdText) ? _vms[0].UserServiceId.ToString(CultureInfo.InvariantCulture) : _vms[0].UserServiceIdText)
        : null;

    public int SuccessCount { get; private set; }
    public int ErrorCount { get; private set; }

    public YdpcAccountClient(YdpcAccountOptions options, Action<string, string>? log = null)
    {
        _options = options ?? new YdpcAccountOptions();
        _log = log;
        Soho = new SohoClient(log, deviceId: _options.DeviceCode, accountType: _options.AccountType);
        _cag = new CagClient(log);
    }

    private void Log(string level, string msg) => _log?.Invoke(level, $"[{AccountName}] {msg}");

    // -----------------------------------------------------------------------
    // 登录 / 机器列表
    // -----------------------------------------------------------------------

    /// <summary>对齐 login()：SOHO 鉴权登录（成功/失败都落日志）。</summary>
    public async Task<SohoLoginResult> LoginAsync(CancellationToken ct = default)
    {
        try
        {
            Log("info", $"正在向中国移动 SOHO 认证中心登录 (类型: {(_options.AccountType == "sub" ? "独立子账号" : "和家亲主账号")})...");
            SohoLoginResult res = await Soho.LoginAsync(_options.User, _options.Password, _options.AccountType, cancellationToken: ct).ConfigureAwait(false);
            Log("success", $"✅ SOHO 鉴权登录成功 (UserId: {res.UserId})");
            return res;
        }
        catch (Exception e)
        {
            Log("error", $"❌ SOHO 登录失败: {e.Message}");
            throw;
        }
    }

    private async Task EnsureLoginAsync(CancellationToken ct)
    {
        if (string.IsNullOrEmpty(Soho.SohoToken)) await LoginAsync(ct).ConfigureAwait(false);
    }

    /// <summary>
    /// 对齐 refreshVms()（简化版）：保证登录 → 拉取权威机器列表。
    /// 底座嗅探 / 差量合并 / 单机开关保留归引擎层 —— 引擎可用 CagRoute.ResolveVmRoute + Vms[i].Raw 完成。
    /// </summary>
    public async Task<List<SohoVm>> GetVmsAsync(CancellationToken ct = default)
    {
        try
        {
            await EnsureLoginAsync(ct).ConfigureAwait(false);
            List<SohoVm> vms = await Soho.ListCloudPcsAsync(ct).ConfigureAwait(false);
            _vms = vms;
            return vms;
        }
        catch (Exception e)
        {
            Log("error", $"刷新云电脑列表异常: {e.Message}");
            throw;
        }
    }

    /// <summary>对齐 isYdpcVmOff()：关机/停止/未开机/到期/未知 或 vmStatus/vmStatusCode ∈ {23,16,0}。</summary>
    public static bool IsVmOff(SohoVm? vm)
    {
        if (vm == null) return false;
        string st = (vm.VmStatus ?? "").Trim();
        if (st.Contains("关机", StringComparison.Ordinal) || st.Contains("停止", StringComparison.Ordinal) ||
            st.Contains("未开机", StringComparison.Ordinal) || st.Contains("到期", StringComparison.Ordinal) ||
            st.Contains("未知", StringComparison.Ordinal)) return true;
        if (st is "23" or "16" or "0") return true;
        if (long.TryParse(vm.VmStatusCode, NumberStyles.Integer, CultureInfo.InvariantCulture, out long code) &&
            code is 23 or 16 or 0) return true;
        return false;
    }

    // -----------------------------------------------------------------------
    // 一次完整保活轮
    // -----------------------------------------------------------------------

    /// <summary>
    /// 一次完整保活轮（对齐 runCycle 单机部分：SOHO 心跳 + 埋点 + ZTEC CAG 握手 + MQTT 保活）。
    ///   · 机器已关机 → skipped（假成功防线：没做事必须 Success=false，不当成完成）；
    ///   · SOHO 心跳 / CAG 握手各自独立分级；tokenRetry 自动重登一次再试；
    ///   · CAG 材料缺失 / SCG 底座 → 连拨都不拨，记 skipped；
    ///   · MQTT 为尽力而为（5 分钟失败冷却），异常不影响控制面结论。
    /// </summary>
    public async Task<KeepaliveRoundResult> KeepaliveOnceAsync(
        string? userServiceId = null, int cagHoldSeconds = 3, CancellationToken ct = default)
    {
        string usid = userServiceId ?? DefaultUserServiceId ?? "";
        if (string.IsNullOrEmpty(usid)) throw new InvalidOperationException("未找到有效的 userServiceId");

        SohoVm? vm = _vms.Find(v => v.UserServiceIdText == usid ||
                                    v.UserServiceId.ToString(CultureInfo.InvariantCulture) == usid);
        var result = new KeepaliveRoundResult();

        // ── 关机守门：与 sendHeartbeat/pingCag 的待命分支同口径 ──
        if (vm != null && IsVmOff(vm))
        {
            result.Skipped = true;
            result.Success = false;
            result.Message = "云电脑处于关机状态";
            Log("info", $"云电脑 [{vm.VmName}] 当前处于已关机状态，心跳守护待命中。");
            return result;
        }

        await EnsureLoginAsync(ct).ConfigureAwait(false);

        // ── 步骤 1：SOHO 心跳（+ 官方活跃度埋点，fire-and-forget）──
        if (_options.ControlPlaneKeepalive)
        {
            StepOutcome hb = await RunStepAsync("SOHO 心跳", async t =>
            {
                await Soho.HeartbeatAsync(usid, t).ConfigureAwait(false); // JS 不校验返回 code：成功 = 不抛
            }, ct).ConfigureAwait(false);

            if (hb.Ok)
            {
                result.HeartbeatOk = true;
                result.Actions.Add(hb.Retried ? "SOHO 心跳（重登后重试成功）" : "SOHO 心跳");
                Log("info", $"💓 SOHO 心跳保持成功 (userServiceId: {usid})");
                // 对齐 JS：pointEvent 异步触发、失败静默
                long? usidNum = SohoClient.JsParseLeadingInt(usid);
                if (usidNum.HasValue)
                {
                    _ = Soho.PointEventAsync("heartbeat", $"\"userServiceId\":{usidNum.Value.ToString(CultureInfo.InvariantCulture)}", ct)
                        .ContinueWith(static t => { _ = t.Exception; }, TaskScheduler.Default);
                }
            }
            else
            {
                MergeFailure(result, "SOHO 心跳", hb);
            }
        }

        // ── 步骤 2：ZTEC CAG 握手（材料缺失 / SCG 底座 → skipped）──
        if (_options.ControlPlaneKeepalive)
        {
            StepOutcome cag = await RunStepAsync("CAG 握手", async t =>
            {
                JsonElement faJson = await Soho.GetFirmAuthAsync(usid, t).ConfigureAwait(false);
                CagFirmAuth firmAuth = CagFirmAuth.FromJson(faJson);
                if (string.IsNullOrEmpty(firmAuth.EffectiveCagHost))
                {
                    // 【防线对齐】材料缺失 ⇒ 连拨都不拨，不当网络故障
                    throw new CagMaterialMissingException("该机器未下发 CAG 连接材料（cagIp 缺失），本次未发起握手");
                }
                CagRouteKind kind = CagRoute.ResolveVmRoute(vm?.SpuCode, firmAuth).Kind;
                if (kind == CagRouteKind.Scg)
                    throw new YdpcSkipSignalException("SCG 底座无 CAG 通道，本次未发起握手");

                Log("info", $"正在向中兴 CAG 网关 ({firmAuth.EffectiveCagHost}:{firmAuth.EffectiveCagPort}) 发起 ZTEC TCP 三阶段握手...");
                await _cag.AuthHoldAsync(firmAuth, cagHoldSeconds, 15000, t).ConfigureAwait(false);
            }, ct).ConfigureAwait(false);

            if (cag.Ok)
            {
                result.CagOk = true;
                result.Actions.Add(cag.Retried ? "CAG 握手（重登后重试成功）" : "CAG 握手");
                SuccessCount++;
                Log("success", "🟢 ZTEC CAG TCP 三阶段握手成功，网关返回 200 OK！");
            }
            else
            {
                MergeFailure(result, "CAG 握手", cag);
            }
        }

        // ── 步骤 3：官方 MQTT 长连接（尽力而为，异常不影响控制面结论）──
        if (_options.MqttKeepAlive)
        {
            try
            {
                result.MqttEnsured = await EnsureMqttAsync(ct).ConfigureAwait(false);
            }
            catch (Exception e)
            {
                Log("warning", $"MQTT 链路维护异常: {e.Message}");
            }
        }

        // ── 汇总 ──
        bool anyAction = result.HeartbeatOk || result.CagOk;
        result.Success = anyAction && result.FailureKind != YdpcErrorKind.Hard;
        if (!anyAction && string.IsNullOrEmpty(result.Message))
            result.Message = result.FailureText.Length > 0 ? $"保活未完成: {result.FailureText}" : "保活未完成";

        // 熔断计数（对齐 JS：hard 才算真实 error 数）
        if (result.FailureKind == YdpcErrorKind.Hard) ErrorCount++;

        Log(result.Success ? "success" : (result.Skipped ? "info" : "error"),
            $"保活轮结束: {(result.Success ? "✅ " + string.Join(" + ", result.Actions) : result.Skipped ? "⏸ 已跳过" : "❌ " + result.Message)}" +
            (result.TripBreaker ? "（本轮触发熔断标记）" : ""));

        return result;
    }

    private sealed class StepOutcome
    {
        public bool Ok { get; private init; }
        public bool Skipped { get; private init; }
        public string Text { get; private init; } = "";
        public YdpcErrorKind Kind { get; private init; } = YdpcErrorKind.None;
        public bool Retried { get; private init; }

        public static StepOutcome Good(bool retried = false) => new() { Ok = true, Retried = retried };
        public static StepOutcome Skip(string text) => new() { Skipped = true, Text = text };
        public static StepOutcome Fail(YdpcErrorKind kind, string text, bool retried) =>
            new() { Ok = false, Skipped = false, Kind = kind, Text = text, Retried = retried };
    }

    /// <summary>「本次没做事」信号（对齐 JS 返回 success:false 的 skipped 语义）。</summary>
    private sealed class YdpcSkipSignalException : Exception
    {
        public YdpcSkipSignalException(string message) : base(message) { }
    }

    /// <summary>
    /// 对齐 runWithGrade()：执行一步并做 G2 分级。
    /// tokenRetry ⇒ 重登一次后重试；重试成功视同成功；skip 信号 ⇒ skipped，不算失败。
    /// </summary>
    private async Task<StepOutcome> RunStepAsync(string label, Func<CancellationToken, Task> action, CancellationToken ct)
    {
        try
        {
            await action(ct).ConfigureAwait(false);
            return StepOutcome.Good();
        }
        catch (YdpcSkipSignalException e)
        {
            Log("info", $"{label} 跳过: {e.Message}");
            return StepOutcome.Skip(e.Message);
        }
        catch (CagMaterialMissingException e)
        {
            Log("info", $"{label} 跳过: {e.Message}");
            return StepOutcome.Skip(e.Message);
        }
        catch (OperationCanceledException)
        {
            throw; // 取消不属于失败分级，直接上抛给调用方
        }
        catch (Exception e1)
        {
            YdpcErrorKind kind = YdpcErrors.Classify(e1.Message);
            if (kind != YdpcErrorKind.TokenRetry)
                return StepOutcome.Fail(kind, e1.Message, retried: false);

            // 会话失效 → 重登一次再试
            bool reloginOk;
            try
            {
                await LoginAsync(ct).ConfigureAwait(false);
                reloginOk = true;
            }
            catch
            {
                reloginOk = false;
            }
            if (!reloginOk)
                return StepOutcome.Fail(kind, e1.Message, retried: false);

            try
            {
                await action(ct).ConfigureAwait(false);
                Log("info", $"{label} 命中会话失效，重登后重试成功");
                return StepOutcome.Good(retried: true);
            }
            catch (YdpcSkipSignalException e2) { return StepOutcome.Skip(e2.Message); }
            catch (CagMaterialMissingException e2) { return StepOutcome.Skip(e2.Message); }
            catch (Exception e2)
            {
                return StepOutcome.Fail(YdpcErrors.Classify(e2.Message), e2.Message, retried: true);
            }
        }
    }

    private void MergeFailure(KeepaliveRoundResult result, string label, StepOutcome step)
    {
        if (step.Skipped)
        {
            result.Skipped = true;
            if (string.IsNullOrEmpty(result.Message)) result.Message = step.Text;
            return;
        }
        // 单调升级：Hard > Soft > TokenRetry
        if (step.Kind > result.FailureKind) result.FailureKind = step.Kind;
        if (string.IsNullOrEmpty(result.FailureText)) result.FailureText = $"{label}: {step.Text}";
        string level = step.Kind == YdpcErrorKind.Soft ? "warning" : "error";
        string tag = step.Kind == YdpcErrorKind.Soft ? "软失败(不熔断)" : (step.Retried ? "重登后仍失效" : "异常");
        Log(level, $"{label}{tag}: {step.Text}");
    }

    // -----------------------------------------------------------------------
    // 官方 MQTT 长连接（对齐 ensureMqttConnection）
    // -----------------------------------------------------------------------

    /// <summary>
    /// 确保 MQTT 长连接在线（5 分钟失败冷却；全关机时不连）。
    /// 返回当前是否有可用 MQTT 连接。单机保活开关归引擎层（本方法不做单机判断）。
    /// </summary>
    public async Task<bool> EnsureMqttAsync(CancellationToken ct = default)
    {
        if (!_options.MqttKeepAlive)
        {
            if (Mqtt != null)
            {
                await Mqtt.DisposeAsync().ConfigureAwait(false);
                Mqtt = null;
            }
            return false;
        }

        // 智能全关机感知：名下所有云电脑均已关机 → 不连（运行中的机器仍正常保活）
        bool allOff = _vms.Count > 0 && _vms.All(IsVmOff);
        if (allOff)
        {
            if (Mqtt != null)
            {
                await Mqtt.DisposeAsync().ConfigureAwait(false);
                Mqtt = null;
            }
            return false;
        }

        if (Mqtt != null && Mqtt.IsConnected) return true;

        // 防频繁重试退避：上次失败后至少冷却 5 分钟
        if (_lastMqttFailedAtUtc != default && DateTime.UtcNow - _lastMqttFailedAtUtc < TimeSpan.FromMinutes(5))
            return Mqtt != null && Mqtt.IsConnected;

        try
        {
            await EnsureLoginAsync(ct).ConfigureAwait(false);
            JsonElement res = await Soho.GetMqttConnectInfoAsync(ct).ConfigureAwait(false);

            // 注意：不用 bool 中间变量 —— 确定性赋值分析无法穿过它，dataEl 会被判未赋值
            if (res.ValueKind != JsonValueKind.Object ||
                !res.TryGetProperty("code", out JsonElement codeEl) ||
                codeEl.ValueKind != JsonValueKind.Number ||
                codeEl.GetInt32() != 2000 ||
                !res.TryGetProperty("data", out JsonElement dataEl) ||
                dataEl.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            string fallbackClientId = $"cl_{Tail(_options.User, 4)}_{ToBase36(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds())}";
            MqttCredential cred = MqttCredential.FromSohoConnectInfo(dataEl, fallbackClientId);

            if (Mqtt != null) await Mqtt.DisposeAsync().ConfigureAwait(false);
            Mqtt = new MqttKeepAliveClient(_log, allowInsecureTls: true); // 对齐 JS rejectUnauthorized:false
            await Mqtt.StartAsync(cred, 10000, ct).ConfigureAwait(false);
            _lastMqttFailedAtUtc = default;
            Log("success", $"🟢 官方 MQTT 3.1.1 over TLS 链路已连接保持 (Broker: {cred.Host}:{cred.Port})");
            return true;
        }
        catch (Exception e)
        {
            _lastMqttFailedAtUtc = DateTime.UtcNow;
            Log("warning", $"MQTT 链路连接异常: {e.Message} (已转入5分钟静默退避)");
            return false;
        }
    }

    private static string Tail(string s, int n) => s.Length <= n ? s : s[^n..];

    private static string ToBase36(long value)
    {
        const string chars = "0123456789abcdefghijklmnopqrstuvwxyz";
        if (value == 0) return "0";
        bool neg = value < 0;
        ulong v = neg ? (ulong)-value : (ulong)value;
        var sb = new System.Text.StringBuilder();
        while (v > 0)
        {
            sb.Insert(0, chars[(int)(v % 36)]);
            v /= 36;
        }
        return neg ? "-" + sb.ToString() : sb.ToString();
    }

    // -----------------------------------------------------------------------
    // 官方电源指令（controlPower 的 shutdown/reboot 分支）
    // -----------------------------------------------------------------------

    /// <summary>官方关机/断开（对齐 controlPower('shutdown') → sohoClient.shutdownVm）。</summary>
    public async Task<PowerOpResult> ShutdownAsync(string vmId, CancellationToken ct = default)
    {
        await EnsureLoginAsync(ct).ConfigureAwait(false);
        Log("info", $"正在向移动爱家下发【关机/断开】指令 (userServiceId: {vmId})...");
        PowerOpResult res = await Soho.PowerOffAsync(vmId, ct).ConfigureAwait(false);
        Log("success", $"✅ 云电脑关机/断开指令已生效！({res.Message})");
        return res;
    }

    /// <summary>官方重启（对齐 controlPower('reboot') → sohoClient.rebootVm）。</summary>
    public async Task<PowerOpResult> RebootAsync(string vmId, CancellationToken ct = default)
    {
        await EnsureLoginAsync(ct).ConfigureAwait(false);
        Log("info", $"正在向移动爱家下发【重启】指令 (userServiceId: {vmId})...");
        PowerOpResult res = await Soho.RebootAsync(vmId, ct).ConfigureAwait(false);
        Log("success", $"✅ 云电脑重启指令已生效！({res.Message})");
        return res;
    }

    public async ValueTask DisposeAsync()
    {
        if (Mqtt != null) await Mqtt.DisposeAsync().ConfigureAwait(false);
        Soho.Dispose();
    }
}
