// =============================================================================
// CtyunDashboard.Ydpc / YdpcRuntime.cs
// =============================================================================
// 移动云两条产品线（ydpc-soho / ydpc-ecloud）的账号运行时：Engine 保活调度与
// /api/ydpc/* 路由共用的唯一入口。职责对齐参考实现：
//   · soho：组合已交付的 YdpcAccountClient（SohoClient/CagClient/MqttClient），
//     保活一轮 = refreshVms + SOHO 心跳 + CAG 握手 + MQTT（ydpc_client.js runCycle 同构）
//   · ecloud：app/ecloud/ecloud_client.js（Node 桥接）+ sidecar.py 的 C# 原生替代：
//       ensureSession（token 恢复 → 密码登录）                     → EnsureEcloudSessionAsync
//       accessToken 25 分钟主动续期（ECLOUD_TOKEN_REFRESH_MS 默认 25*60*1000，
//         平台 TTL 约 30 分钟，提前 ~5 分钟静默续期消除周期性 401）→ 25min 续期块
//       session.relogin 冷却期（sidecar _RELOGIN_COOLDOWN_SEC 默认 1200s，
//         防 401 风暴 → 短信轰炸）                                → EcloudReloginAsync
//       keepalive.l1（三态：true/false/null，null 绝不重登）        → EcloudKeepalive.KeepaliveProbeAsync
//       keepalive.l2（desktopUptime + 静默信号，loginUid 跨轮稳定） → EcloudDesktopSession
//       desktop.list / desktop.power                              → SyncDesktopsAsync / PowerAsync
//   会话持久化：EncSession（SM4，Db.Protect）JSON =
//     {username, deviceUid, mobile, accessToken, loginUid, lastTokenRefreshAt, savedAt}
//     —— 对齐 sidecar _persist_sessions「只存非敏感字段，绝不写密码」；密码在 EncPassword。
//   LastSessionRenew 语义对齐天翼 AccountRuntime：每次登录/恢复/续期打点。
//   失败分级：复用 YdpcErrors（G2 tokenRetry/soft/hard）—— hard 才写 Row.LastError 并熔断。
// =============================================================================

using System.Collections.Concurrent;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using CtyunDashboard.CtYun;
using CtyunDashboard.Ecloud;
using CtyunDashboard.Persist;

namespace CtyunDashboard.Ydpc;

public enum YdpcPlatform { Soho, Ecloud }

public sealed class YdpcAccountRuntime
{
    /// <summary>ecloud accessToken 主动续期周期（对齐 ECLOUD_TOKEN_REFRESH_MS 默认 25 分钟）。</summary>
    public static readonly TimeSpan TokenRefreshInterval = TimeSpan.FromMinutes(25);
    /// <summary>重登冷却期（对齐 sidecar _RELOGIN_COOLDOWN_SEC 默认 1200s）。</summary>
    public static readonly TimeSpan ReloginCooldown = TimeSpan.FromSeconds(1200);

    private static readonly ConcurrentDictionary<string, long> LastUptimeSeconds = new();

    public SmAccount Row { get; private set; }
    public DateTime NextRunAt { get; internal set; } = DateTime.MinValue;
    public DateTime LastSessionRenew { get; private set; }
    public DateTime LastRoundAt { get; private set; }
    public bool NeedsInteractive { get; private set; }
    public string NeedsInteractiveBranch { get; private set; } = "";

    private YdpcAccountClient? _soho;
    private EcloudHttpUtil? _ecloudHttp;
    private readonly object _ecloudGate = new();

    public YdpcPlatform Platform =>
        Row.Platform.Contains("ecloud", StringComparison.OrdinalIgnoreCase) ? YdpcPlatform.Ecloud : YdpcPlatform.Soho;

    /// <summary>移动爱家底层协议：SCG（深信服，走 SCG 数据面）/ ZTE（默认，走 SOHO 心跳+CAG）。</summary>
    public bool IsScg => Row.Protocol.Trim().Equals("SCG", StringComparison.OrdinalIgnoreCase);

    public YdpcAccountRuntime(SmAccount row) { Row = row; }

    /// <summary>ReloadAll 时同步最新落盘行（保留内存会话态：冷却期/交互标记/驱动实例）。</summary>
    public void RefreshRow(SmAccount row) => Row = row;

    private void Log(string level, string msg) => Svc.Logs.Write(level, "Ydpc", Row.Name, msg);

    // -----------------------------------------------------------------------
    // soho：组合已交付驱动（稳定 deviceId 由账号 Id 派生，跨重启不变）
    // -----------------------------------------------------------------------
    private YdpcAccountClient Soho()
    {
        if (_soho != null) return _soho;
        string deviceCode = StableSohoDeviceCode();
        var opts = new YdpcAccountOptions
        {
            Name = string.IsNullOrEmpty(Row.Name) ? Row.User : Row.Name,
            User = Row.User,
            Password = Row.EncPassword != "" ? Svc.Db.Unprotect(Row.EncPassword) : "",
            AccountType = "main",
            DeviceCode = deviceCode,
            KeepAlive = Row.KeepaliveEnabled,
            ControlPlaneKeepalive = true,
            MqttKeepAlive = true,
        };
        _soho = new YdpcAccountClient(opts, (level, msg) => Svc.Logs.Write(level, "Ydpc", opts.Name, msg));
        return _soho;
    }

    /// <summary>SN-MAC 形态的稳定设备码（SHA256("ydpc:"+accountId) 派生，等价 genDeviceId 形状）。</summary>
    private string StableSohoDeviceCode()
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes("ydpc:" + Row.Id));
        string hex = Convert.ToHexString(hash).ToLowerInvariant();
        string sn = hex[..11].ToUpperInvariant();
        string mac = $"{hex[11..13]}:{hex[13..15]}:{hex[15..17]}:{hex[17..19]}:{hex[19..21]}:{hex[21..23]}";
        return $"{sn}-{mac}";
    }

    // -----------------------------------------------------------------------
    // Engine 调度入口：一轮保活（异常在这里收敛为 G2 分级，绝不外抛打崩 Tick）
    // -----------------------------------------------------------------------
    public async Task RunKeepaliveRoundAsync(CancellationToken ct = default)
    {
        LastRoundAt = DateTime.Now;
        var hadError = Row.LastError != null; // 【Bug 2 修复】先拍快照：L1 通过分支会先把内存 LastError 置 null，事后判断就再也看不到"曾带错"
        try
        {
            if (Platform == YdpcPlatform.Soho)
            {
                // 【协议分流】ZTE=SOHO 心跳 + CAG 握手；SCG=深信服数据面（scg_route.py 移植）
                if (IsScg) await ScgRoundAsync(ct).ConfigureAwait(false);
                else await SohoRoundAsync(ct).ConfigureAwait(false);
            }
            else await EcloudRoundAsync(ct).ConfigureAwait(false);
            // 本轮未写回任何错误、且开始前带错 → 视为已恢复，**落盘**清除
            // （旧实现只清内存不落盘，卡片永远停在旧的「会话失效」上）
            if (hadError && Row.LastError == null && !NeedsInteractive)
            {
                Svc.Db.UpdateAccount(Row);
                Log("info", "上一轮错误已恢复，LastError 已清除");
            }
        }
        catch (OperationCanceledException) { /* 停机 */ }
        catch (Exception e)
        {
            var kind = YdpcErrors.Classify(e.Message);
            if (kind == YdpcErrorKind.Hard)
            {
                Row.LastError = e.Message;
                Svc.Db.UpdateAccount(Row);
                Log("error", $"保活轮硬失败(熔断本轮): {e.Message}");
            }
            else
            {
                Log("warning", $"保活轮软失败(不熔断): {e.Message}");
            }
        }
    }

    private async Task SohoRoundAsync(CancellationToken ct)
    {
        var soho = Soho();
        try
        {
            await soho.GetVmsAsync(ct).ConfigureAwait(false); // refreshVms（含自动重登）
        }
        catch (Exception e)
        {
            // 列表失败不阻断：凭旧 Vms 继续心跳（JS 版 refreshVms 失败也是回落 account.vms）
            Log("warning", $"刷新云电脑列表异常: {e.Message}");
        }
        var usid = soho.DefaultUserServiceId;
        if (usid == null)
        {
            Log("info", "名下暂无云电脑，本轮保活跳过");
            return;
        }
        var r = await soho.KeepaliveOnceAsync(usid, 3, ct).ConfigureAwait(false);
        if (r.Success)
        {
            Row.LastError = null;
            Row.LastLoginAt = Db.Now();
            Svc.Db.UpdateAccount(Row);
            _ = Svc.NotifyHubField.SendAsync(Row.Name, $"移动云保活完成 - {Row.Name}",
                $"SOHO 心跳 ✓（ZTE 通道）\n下次保活: {Math.Clamp(Row.PulseIntervalSeconds, 60, 604800) / 3600.0:0.#} 小时后");
        }
        else if (r.Skipped)
        {
            Log("info", $"保活轮跳过: {r.Message}");
        }
        else if (r.TripBreaker)
        {
            Row.LastError = r.FailureText != "" ? r.FailureText : r.Message;
            Svc.Db.UpdateAccount(Row);
            Log("error", $"保活轮硬失败: {Row.LastError}");
            _ = Svc.NotifyHubField.SendAsync(Row.Name, $"移动云保活失败 - {Row.Name}", Row.LastError);
        }
        else
        {
            Log("warning", $"保活轮软失败(不熔断): {r.FailureText}");
            _ = Svc.NotifyHubField.SendAsync(Row.Name, $"移动云保活异常 - {Row.Name}", r.FailureText != "" ? r.FailureText : r.Message);
        }
    }

    // -----------------------------------------------------------------------
    // SCG 深信服数据面（scg_route.py 移植；run_scg_keepalive 的 forever 软恢复
    // 压缩进单轮：最多 3 次尝试，失败指数退避后重拉 connect-info 续连——
    // CEM 502/维护/VM 批量下线按母本口径一律软恢复，绝不熔断账号）
    // -----------------------------------------------------------------------
    private async Task ScgRoundAsync(CancellationToken ct)
    {
        var soho = Soho();
        if (string.IsNullOrEmpty(soho.Soho.SohoToken)) await soho.LoginAsync(ct).ConfigureAwait(false);
        var usid = soho.DefaultUserServiceId
            ?? throw new InvalidOperationException("名下暂无云电脑，SCG 保活跳过");
        string deviceId = StableSohoDeviceCode();

        Exception? last = null;
        for (int attempt = 1; attempt <= 3; attempt++)
        {
            try
            {
                if (attempt > 1)
                {
                    // 对齐 run_scg_keepalive 指数退避：5s×2^(n-1)，上限 60s
                    int delay = (int)Math.Min(ScgConsts.ForeverBackoffCapS,
                        ScgConsts.ForeverBackoffBaseS * Math.Pow(2, attempt - 2));
                    await Task.Delay(TimeSpan.FromSeconds(delay), ct).ConfigureAwait(false);
                    if (string.IsNullOrEmpty(soho.Soho.SohoToken)) await soho.LoginAsync(ct).ConfigureAwait(false);
                }

                // reconnect_fn 语义：每次尝试都重取 firm-auth 材料（IP/port/authCode 可能已轮换）
                var firm = await soho.Soho.GetFirmAuthAsync(usid, ct).ConfigureAwait(false);
                string scAuthCode = firm.TryGetProperty("scAuthCode", out var sac) && sac.ValueKind == JsonValueKind.String ? sac.GetString() ?? "" : "";
                string vmId = firm.TryGetProperty("vmId", out var vm) && vm.ValueKind == JsonValueKind.String ? vm.GetString() ?? "" : "";
                if (scAuthCode == "" || vmId == "")
                    throw new InvalidOperationException("firm-auth 未下发 scAuthCode/vmId（SCG 材料缺失，通常表示机器未就绪）");

                // 冷启动慢路径整体 140s（lead 口径）：oauth + getConnectInfo + ready 轮询
                using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                connectCts.CancelAfter(TimeSpan.FromSeconds(140));
                var (scgIp, scgPort, authCode, _, ready) =
                    await ScgRoute.GetConnectInfoAsync(scAuthCode, vmId, deviceId, connectCts.Token).ConfigureAwait(false);
                Log("info", $"SCG 连接信息已获取: {scgIp}:{scgPort} ready={ready}（authCode 已轮换={authCode != scAuthCode}）");

                await using var conn = await ScgRoute.ConnectScgAsync(scgIp, scgPort, authCode, vmId, 10000, ct).ConfigureAwait(false);
                var hs = await ScgRoute.SpiceHandshakeAsync(conn, vmId, ct).ConfigureAwait(false);
                Log(hs.SpiceOk ? "success" : "warning",
                    $"SCG 握手: 通道 {string.Join("/", hs.ConnectedChannels)} spice={(hs.SpiceOk ? "OK" : "未完成")} (spiceSessionId={hs.SpiceSessionId})");

                // 会话切片覆盖整个调度间隔（母本 forever 语义：切片间不断链）
                int holdSec = Math.Clamp(Row.PulseIntervalSeconds - 15, 60, 3300);
                var hold = await ScgRoute.HoldAsync(conn, hs.SessionId, hs.SpiceOk, holdSec,
                    sohoHeartbeatAsync: async token => await soho.Soho.HeartbeatAsync(usid, token).ConfigureAwait(false),
                    onSlowPlaneError: e => Log("warning", $"SCG 慢平面 SOHO 心跳失败: {e.Message}"),
                    ct).ConfigureAwait(false);
                Log("success",
                    $"SCG 保活切片完成: hold={hold.WallSeconds:F0}s frames={hold.Frames} heartbeats={hold.Heartbeats}(soho {hold.SohoHeartbeats}) switchEcho={hold.TrunkSwitchReplies}");
                last = null;
                break;
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception e)
            {
                last = e;
                var tags = ScgRoute.ClassifySoftFailure(e);
                Log("warning",
                    $"SCG 第 {attempt}/3 次失败（recoverable={tags.Recoverable} maintenance={tags.PlatformMaintenance} reason={tags.FailReason}）: {tags.Error}");
            }
        }

        if (last != null)
        {
            // 母本口径：SCG 异常一律 recoverable → 软失败只告警不熔断；卡片可见
            Row.LastError = "SCG: " + last.Message;
            Svc.Db.UpdateAccount(Row);
            Log("error", $"SCG 保活轮失败（软失败，下轮重拉材料续连）: {last.Message}");
            return;
        }
        Row.LastError = null;
        Row.LastLoginAt = Db.Now();
        Svc.Db.UpdateAccount(Row);
    }

    /// <summary>桌面登出（logout.py desktop_logout；桌面被占用时释放会话锁）。</summary>
    public async Task<JsonElement> LogoutDesktopAsync(string? userServiceId, CancellationToken ct = default)
    {
        if (Platform == YdpcPlatform.Ecloud)
            throw new InvalidOperationException("桌面会话锁释放仅适用于移动爱家（ydpc-soho）账号");
        var soho = Soho();
        if (string.IsNullOrEmpty(soho.Soho.SohoToken)) await soho.LoginAsync(ct).ConfigureAwait(false);
        var usid = !string.IsNullOrEmpty(userServiceId) ? userServiceId : soho.DefaultUserServiceId
            ?? throw new InvalidOperationException("未找到有效的 userServiceId");
        return await soho.Soho.LogoutDesktopAsync(usid, ct).ConfigureAwait(false);
    }

    /// <summary>账号登出（logout.py account_logout）：/login/logout/v1 + 清本地 sohoToken/userId。</summary>
    public async Task<JsonElement> AccountLogoutAsync(CancellationToken ct = default)
    {
        if (Platform == YdpcPlatform.Ecloud)
            throw new InvalidOperationException("账号登出仅适用于移动爱家（ydpc-soho）账号");
        var res = await Soho().Soho.AccountLogoutAsync(ct).ConfigureAwait(false);
        Row.LastLoginAt = null;
        Svc.Db.UpdateAccount(Row);
        return res;
    }

    // -----------------------------------------------------------------------
    // ecloud：会话管理
    // -----------------------------------------------------------------------
    private sealed class EcloudSessionState
    {
        public string DeviceUid = "";
        public string Mobile = "";
        public string AccessToken = "";
        public string LoginUid = "";
        public long LastTokenRefreshAt; // ms；0 = 尚未建立/恢复
    }

    private EcloudSessionState _state = new();

    /// <summary>从落盘 EncSession 恢复（对齐 op_session_restore：只存非敏感字段）。</summary>
    private void LoadSession()
    {
        _state = new EcloudSessionState();
        if (Row.EncSession == "") return;
        try
        {
            using var doc = JsonDocument.Parse(Svc.Db.Unprotect(Row.EncSession));
            var j = doc.RootElement;
            _state.DeviceUid = j.TryGetProperty("deviceUid", out var d) && d.ValueKind == JsonValueKind.String ? d.GetString() ?? "" : "";
            _state.Mobile = j.TryGetProperty("mobile", out var m) && m.ValueKind == JsonValueKind.String ? m.GetString() ?? "" : "";
            _state.AccessToken = j.TryGetProperty("accessToken", out var a) && a.ValueKind == JsonValueKind.String ? a.GetString() ?? "" : "";
            _state.LoginUid = j.TryGetProperty("loginUid", out var l) && l.ValueKind == JsonValueKind.String ? l.GetString() ?? "" : "";
            _state.LastTokenRefreshAt = j.TryGetProperty("lastTokenRefreshAt", out var t) && t.ValueKind == JsonValueKind.Number ? t.GetInt64() : 0;
        }
        catch
        {
            // 会话文件不可读 → 视为无会话（对齐 _load_persisted 的容错）
        }
    }

    private void PersistSession()
    {
        var obj = new JsonObject
        {
            ["username"] = Row.User,
            ["deviceUid"] = _state.DeviceUid,
            ["mobile"] = _state.Mobile,
            ["accessToken"] = _state.AccessToken,
            ["loginUid"] = _state.LoginUid,
            ["lastTokenRefreshAt"] = _state.LastTokenRefreshAt,
            ["savedAt"] = Db.Now(),
        };
        Row.EncSession = Svc.Db.Protect(JsonSerializer.Serialize(obj, AppJson.Default.JsonObject));
        Svc.Db.UpdateAccount(Row);
    }

    private EcloudHttpUtil EcloudHttp()
    {
        lock (_ecloudGate)
        {
            if (_ecloudHttp != null) return _ecloudHttp;
            if (_state.DeviceUid == "") LoadSession();
            if (_state.DeviceUid == "")
            {
                // 设备指纹必须跨运行稳定（变化触发"未授信设备"）→ 首见生成并立即持久化
                _state.DeviceUid = Guid.NewGuid().ToString();
                PersistSession();
            }
            _ecloudHttp = new EcloudHttpUtil(EcloudDevice.BuildCommonParams(_state.DeviceUid, Environment.MachineName));
            if (_state.AccessToken != "") _ecloudHttp.SetToken(_state.AccessToken);
            if (_state.LoginUid == "") { _state.LoginUid = Guid.NewGuid().ToString(); PersistSession(); }
            return _ecloudHttp;
        }
    }

    private void ResetEcloudHttp(string? newToken)
    {
        lock (_ecloudGate)
        {
            _ecloudHttp?.Dispose();
            _ecloudHttp = new EcloudHttpUtil(EcloudDevice.BuildCommonParams(_state.DeviceUid, Environment.MachineName));
            if (!string.IsNullOrEmpty(newToken)) _ecloudHttp.SetToken(newToken);
        }
    }

    /// <summary>确保可用会话：token 恢复优先，否则密码登录（对齐 ensureSession / session.restore）。</summary>
    private async Task<bool> EnsureEcloudSessionAsync(CancellationToken ct)
    {
        var http = EcloudHttp();
        if (http.AccessToken != null)
        {
            if (_state.LastTokenRefreshAt == 0) { _state.LastTokenRefreshAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(); PersistSession(); }
            LastSessionRenew = DateTime.Now; // 恢复即视为会话在场（真实年龄未知，401 路径兜底）
            return true;
        }
        var (ok, msg) = await EcloudReloginAsync(quiet: false, force: false, ct).ConfigureAwait(false);
        if (!ok && msg != "") Log("warning", $"会话建立失败: {msg}");
        return ok;
    }

    /// <summary>
    /// 密码重登刷新 token（对齐 op_session_relogin）：冷却期 + 限流记账，杜绝 401 风暴。
    /// force=true 时跳过冷却（面板显式重登）。
    /// </summary>
    public async Task<(bool Ok, string Message)> EcloudReloginAsync(bool quiet, bool force, CancellationToken ct = default)
    {
        var now = DateTimeOffset.UtcNow;
        if (!force && _reloginAtUtc != default && now - _reloginAtUtc < ReloginCooldown)
        {
            int wait = (int)(ReloginCooldown - (now - _reloginAtUtc)).TotalSeconds;
            Log("warning", $"重登被冷却期拦截（还需 {wait}s），本轮不重登 —— 防止短信轰炸");
            return (false, $"冷却期内（{wait}s 后允许）");
        }
        _reloginAtUtc = now;
        EcloudLoginRateLimiter.RecordAttempt(Row.User);

        if (Row.EncPassword == "")
        {
            Log("error", "重登缺少密码（本地无凭据）");
            return (false, "本地无凭据，无法自动重登");
        }
        string password = Svc.Db.Unprotect(Row.EncPassword);
        if (_state.DeviceUid == "") LoadSession();
        var http = new EcloudHttpUtil(EcloudDevice.BuildCommonParams(
            _state.DeviceUid != "" ? _state.DeviceUid : Guid.NewGuid().ToString(), Environment.MachineName));
        var r = await EcloudLogin.LoginWithPasswordAsync(http, Row.User, password, ct).ConfigureAwait(false);

        if (r.Status == EcloudLoginStatus.Success)
        {
            _state.AccessToken = r.AccessToken;
            _state.Mobile = r.Mobile != "" ? r.Mobile : _state.Mobile;
            _state.LastTokenRefreshAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            if (_state.DeviceUid == "")
            {
                // http 的 commonParams 里带了本次使用的 deviceUid（可能首见生成）——回收
                _state.DeviceUid = http.CommonParams["deviceUid"] is JsonValue dv && dv.TryGetValue<string>(out var du) ? du : Guid.NewGuid().ToString();
            }
            if (_state.LoginUid == "") _state.LoginUid = Guid.NewGuid().ToString();
            PersistSession();
            ResetEcloudHttp(r.AccessToken);
            LastSessionRenew = DateTime.Now;
            NeedsInteractive = false;
            NeedsInteractiveBranch = "";
            Row.LastError = null;
            Row.LastLoginAt = Db.Now();
            Svc.Db.UpdateAccount(Row);
            if (!quiet) Log("success", "重登成功，token 已刷新");
            else Log("info", "🔁 凭证已按周期静默续期（平台 accessToken 约 30 分钟有效，提前续期避免 401）");
            return (true, "");
        }

        if (EcloudLoginStatus.IsInteractive(r.Status))
        {
            NeedsInteractive = true;
            NeedsInteractiveBranch = r.Status;
            string msg = $"登录需要短信验证（{r.Status}），请在面板完成登录后再恢复自动保活";
            Row.LastError = msg;
            Svc.Db.UpdateAccount(Row);
            Log("error", msg);
            return (false, msg);
        }

        string err = r.Error != "" ? r.Error : $"status={r.Status}";
        Log("error", $"重登未成功: {err}");
        return (false, err);
    }

    private DateTimeOffset _reloginAtUtc;

    /// <summary>面板显式重登（soho=密码登录；ecloud=密码重登，跳过冷却）。</summary>
    public async Task<bool> ReloginAsync(CancellationToken ct = default)
    {
        if (Platform == YdpcPlatform.Soho)
        {
            try
            {
                await Soho().LoginAsync(ct).ConfigureAwait(false);
                Row.LastError = null;
                Row.LastLoginAt = Db.Now();
                Svc.Db.UpdateAccount(Row);
                LastSessionRenew = DateTime.Now;
                return true;
            }
            catch (Exception e)
            {
                Row.LastError = e.Message;
                Svc.Db.UpdateAccount(Row);
                return false;
            }
        }
        var (ok, msg) = await EcloudReloginAsync(quiet: false, force: true, ct).ConfigureAwait(false);
        if (!ok && msg != "") Log("error", $"重登未成功: {msg}");
        return ok;
    }

    /// <summary>后台自动重登（冷却把关；quiet=true 不打误导性"重登成功"日志）。</summary>
    private Task<(bool Ok, string Message)> EcloudAutoReloginAsync(CancellationToken ct) => EcloudReloginAsync(quiet: true, force: false, ct);

    // -----------------------------------------------------------------------
    // ecloud：一轮保活（25min 续期 → L1 → L2 逐台）
    // -----------------------------------------------------------------------
    private async Task EcloudRoundAsync(CancellationToken ct)
    {
        if (NeedsInteractive)
        {
            Log("info", "等待面板交互式登录（短信验证），本轮保活跳过");
            return;
        }
        if (!await EnsureEcloudSessionAsync(ct).ConfigureAwait(false))
        {
            Log("warning", "会话不可用（重登未完成），本轮保活跳过");
            return;
        }

        // ── 凭证主动续期（对齐 Node runCycle 的 25min 续期块）──────────────
        var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        if (_state.LastTokenRefreshAt != 0 && nowMs - _state.LastTokenRefreshAt >= (long)TokenRefreshInterval.TotalMilliseconds)
        {
            try
            {
                var (ok, msg) = await EcloudAutoReloginAsync(ct).ConfigureAwait(false);
                if (!ok && msg.Contains("冷却", StringComparison.Ordinal))
                {
                    // 冷却期内不强行重登；不推进时间戳，下一轮再试
                }
                else if (!ok)
                {
                    Log("warning", $"凭证周期续期失败（将回落为 401 触发重登）: {msg}");
                }
            }
            catch (Exception e)
            {
                Log("warning", $"凭证周期续期失败（将回落为 401 触发重登）: {e.Message}");
            }
        }

        // ── L1 账号态探针（三态原样保留）──────────────────────────────────
        var outcome = await EcloudKeepalive.KeepaliveProbeAsync(EcloudHttp(), ct).ConfigureAwait(false);
        if (outcome.Ok == true)
        {
            Row.LastError = null;
            Log("success", "L1 账号态探针通过（HTTP 层探针 ≠ 云电脑不会被关机）");
        }
        else if (outcome.Ok == false)
        {
            Log("warning", $"L1 保活判定 token 失效（服务端: {outcome.Error}），尝试重登刷新 token");
            var (relogged, msg) = await EcloudAutoReloginAsync(ct).ConfigureAwait(false);
            if (relogged) Log("success", "重登成功，token 已刷新，下轮继续");
            else if (msg.Contains("冷却", StringComparison.Ordinal)) Log("warning", $"重登处于冷却期，本轮跳过 —— 防止短信轰炸");
            else Log("error", $"重登未成功: {msg}");
            Row.LastError = relogged ? null : $"L1 token 失效（{outcome.Error}）";
            Svc.Db.UpdateAccount(Row);
        }
        else
        {
            // ok=null：全端点失败但都不是 token 错误 —— 🔴 绝不可重登（防短信轰炸）
            Log("warning", $"L1 本轮失败但非 token 失效（{outcome.Error}）→ 按设计不重登，下轮重试");
        }

        // ── L2 桌面登记保活（逐台）────────────────────────────────────────
        var l2Lines = new List<string>();
        foreach (var desk in Svc.Db.DesktopsOf(Row.Id).Where(d => d.KeepaliveEnabled))
        {
            var (machineId, poolUid) = ParseDesktopRaw(desk.RawJson);
            var ds = new EcloudDesktopSession(EcloudHttp(), desk.DesktopId, machineId, desk.Name, _state.LoginUid);
            bool ok = await ds.KeepaliveOnceAsync(ct).ConfigureAwait(false);
            Svc.Db.TouchPulse(Row.Id, desk.DesktopId);
            if (ok)
            {
                // 在线时长回退 = 平台侧会话记录被重建 ⇒ 疑似关机证据（Node parseUptimeSeconds 纪律）
                long upNow = EcloudKeepalive.ParseUptimeSeconds(ds.LastUptime);
                long upPrev = LastUptimeSeconds.GetValueOrDefault(Row.Id + ":" + desk.DesktopId, -1);
                if (upNow >= 0 && upPrev >= 0 && upNow < upPrev - EcloudKeepalive.UptimeRegressionMinSec)
                    Log("warning", $"[{desk.Name}] 平台在线时长回退: {upPrev}s → {upNow}s —— 平台侧会话记录被重建，疑似发生过关机/重启");
                if (upNow >= 0) LastUptimeSeconds[Row.Id + ":" + desk.DesktopId] = upNow;
                // 【Bug 1 配套】时长解析成功 ⇒ 桌面确实在运行：状态归一为运行中（lead 指令）
                if (desk.UseStatus != 1 || desk.UseStatusText != "运行中")
                {
                    desk.UseStatus = 1;
                    desk.UseStatusText = "运行中";
                    Svc.Db.UpdateDesktop(desk);
                }
                Log("success", $"[{desk.Name}] L2 桌面登记成功{(ds.LastUptime != "" ? $" · 在线时长 {ds.LastUptime}" : "")}");
                l2Lines.Add($"✅ {desk.Name}" + (ds.LastUptime != "" ? $"（在线 {ds.LastUptime}）" : ""));
            }
            else
            {
                Log("warning", $"[{desk.Name}] L2 桌面登记失败: {ds.LastError}");
                l2Lines.Add($"❌ {desk.Name}（{ds.LastError}）");
                if (ds.LastErrorTokenExpired)
                {
                    Log("warning", $"[{desk.Name}] L2 报告 token 失效，请求重登");
                    await EcloudAutoReloginAsync(ct).ConfigureAwait(false);
                }
            }
        }

        // ── 保活轮完成 → 企业微信等渠道推送（NotifyHub 按系统设置分发）──────
        var l1Text = outcome.Ok == true ? "✅ 通过" : outcome.Ok == false ? "❌ token 失效" : "⚠️ 端点失败";
        var body = $"L1 账号探针 {l1Text}";
        if (l2Lines.Count > 0) body += "\n" + string.Join("\n", l2Lines);
        body += $"\n下次保活: {Math.Clamp(Row.PulseIntervalSeconds, 60, 604800) / 3600.0:0.#} 小时后";
        _ = Svc.NotifyHubField.SendAsync(Row.Name, $"移动云保活完成 - {Row.Name}", body);
    }

    private static (string MachineId, string PoolUid) ParseDesktopRaw(string rawJson)
    {
        if (rawJson == "") return ("", "");
        try
        {
            using var doc = JsonDocument.Parse(rawJson);
            var j = doc.RootElement;
            string mid = j.TryGetProperty("machineId", out var m) && m.ValueKind == JsonValueKind.String ? m.GetString() ?? "" : "";
            string pool = j.TryGetProperty("resourcePoolUid", out var p) && p.ValueKind == JsonValueKind.String ? p.GetString() ?? "" : "";
            return (mid, pool);
        }
        catch { return ("", ""); }
    }

    // -----------------------------------------------------------------------
    // 同步桌面列表（/sync；返回摘要文案）
    // -----------------------------------------------------------------------
    public async Task<string> SyncDesktopsAsync(CancellationToken ct = default)
    {
        if (Platform == YdpcPlatform.Soho)
        {
            var soho = Soho();
            var vms = await soho.GetVmsAsync(ct).ConfigureAwait(false);
            var list = vms.Select(v => (
                Id: v.UserServiceId.ToString(CultureInfo.InvariantCulture),
                Name: v.VmName,
                UseStatus: long.TryParse(v.VmStatusCode, NumberStyles.Integer, CultureInfo.InvariantCulture, out var sc) ? (int)sc : 0,
                UseStatusText: v.VmStatus,
                Spec: v.SkuName != "" ? v.SkuName : (v.Cpu != "" ? $"{v.Cpu}核{v.Memory}G" : ""),
                Raw: v.Raw.ValueKind == JsonValueKind.Object ? v.Raw.GetRawText() : ""
            )).ToList();
            Svc.Db.SyncDesktops(Row, list);
            return $"已同步云电脑列表（{list.Count} 台）";
        }

        if (!await EnsureEcloudSessionAsync(ct).ConfigureAwait(false))
            throw new InvalidOperationException("会话不可用（未登录或需要短信验证）");
        var desks = await EcloudDesktops.GetDesktopsWithStatusAsync(EcloudHttp(), ct).ConfigureAwait(false);
        var mapped = desks.Select(d => (
            Id: d.InstanceId,
            Name: d.MachineName != "" ? d.MachineName : d.InstanceId,
            UseStatus: d.PowerState == "on" ? 1 : d.PowerState == "off" ? 23 : 0,
            UseStatusText: d.PowerState == "on" ? "运行中" : d.PowerState == "off" ? "已关机" : "状态未知",
            Spec: d.OriginCompanyCode,
            Raw: d.ToRawJson().ToJsonString()
        )).ToList();
        Svc.Db.SyncDesktops(Row, mapped);
        Log("info", $"已同步桌面列表（{mapped.Count} 台）");
        return $"已同步桌面列表（{mapped.Count} 台）";
    }

    // -----------------------------------------------------------------------
    // 电源操作（soho: shutdown|reboot；ecloud: poweron|shutdown|reboot）
    // -----------------------------------------------------------------------
    public async Task<(bool Ok, string Message)> PowerAsync(string desktopId, string action, CancellationToken ct = default)
    {
        if (Platform == YdpcPlatform.Soho)
        {
            var soho = Soho();
            var res = action.ToLowerInvariant() switch
            {
                "shutdown" or "poweroff" or "poweroffnow" => await soho.ShutdownAsync(desktopId, ct).ConfigureAwait(false),
                "reboot" or "restart" => await soho.RebootAsync(desktopId, ct).ConfigureAwait(false),
                _ => throw new InvalidOperationException("移动爱家通道不支持该电源操作（仅 shutdown/reboot；开机走 CAG 通道，尚未接入）"),
            };
            Log("success", $"[{desktopId}] 电源指令[{action}] 已生效: {res.Message}");
            return (res.Success, res.Message);
        }

        if (!await EnsureEcloudSessionAsync(ct).ConfigureAwait(false))
            throw new InvalidOperationException("会话不可用（未登录或需要短信验证）");
        var op = action.ToLowerInvariant() switch
        {
            "poweron" or "startup" or "start" or "available" => "available",
            "shutdown" or "poweroff" => "shutdown",
            "reboot" or "restart" => "restart",
            _ => throw new InvalidOperationException($"不支持的电源操作: {action}"),
        };
        var desk = Svc.Db.DesktopsOf(Row.Id).FirstOrDefault(d => d.DesktopId == desktopId);
        if (desk == null) throw new InvalidOperationException("未找到该云电脑（请先「同步桌面」拉取列表）");
        var (machineId, poolUid) = ParseDesktopRaw(desk.RawJson);
        var (ok, message) = await EcloudDevice.PowerAsync(EcloudHttp(), machineId, desk.Name, op, poolUid, ct).ConfigureAwait(false);
        Log("success", $"[{desk.Name}] ✅ 已下发【{EcloudDevice.OperateCn(op)}】指令，平台已受理 (operate={op})");
        return (ok, message);
    }

    // -----------------------------------------------------------------------
    // 交互式登录（面板）：发码 / 完成短信分支 / 面板密码重登
    // -----------------------------------------------------------------------
    public async Task SendEcloudSmsAsync(string branch, string mobile, CancellationToken ct = default)
    {
        mobile = mobile != "" ? mobile : _state.Mobile;
        if (mobile == "") throw new InvalidOperationException("发送短信需要 mobile（密码登录未返回手机号，无法发码）");
        await EcloudLogin.SendSmsForBranchAsync(EcloudHttp(), branch, mobile, Row.User, ct).ConfigureAwait(false);
        _state.Mobile = mobile;
        PersistSession();
        Log("success", $"验证码已下发至 {MaskMobile(mobile)} (branch={branch})");
    }

    public async Task<EcloudLoginResult> CompleteEcloudSmsAsync(string branch, string code, bool isTemporary, CancellationToken ct = default)
    {
        var r = await EcloudLogin.CompleteSmsBranchAsync(
            EcloudHttp(), branch, _state.Mobile, Row.User,
            Row.EncPassword != "" ? Svc.Db.Unprotect(Row.EncPassword) : "",
            code, null, isTemporary, ct).ConfigureAwait(false);
        if (r.Status == EcloudLoginStatus.Success)
        {
            _state.AccessToken = r.AccessToken;
            _state.LastTokenRefreshAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            PersistSession();
            ResetEcloudHttp(r.AccessToken);
            LastSessionRenew = DateTime.Now;
            NeedsInteractive = false;
            NeedsInteractiveBranch = "";
            Row.LastError = null;
            Row.LastLoginAt = Db.Now();
            Svc.Db.UpdateAccount(Row);
            Log("success", "✅ 短信验证通过，登录成功");
        }
        else
        {
            Log("warning", $"短信验证未完成: {r.Error}");
        }
        return r;
    }

    private static string MaskMobile(string m)
    {
        var s = (m ?? "").Trim();
        return s.Length >= 7 ? $"{s[..3]}****{s[^4..]}" : "***";
    }

    /// <summary>删除账号时的资源清理（Engine/Ydpc 侧）。</summary>
    public async Task DisposeResourcesAsync()
    {
        if (_soho != null) await _soho.DisposeAsync().ConfigureAwait(false);
        lock (_ecloudGate) { _ecloudHttp?.Dispose(); _ecloudHttp = null; }
    }
}

// -----------------------------------------------------------------------------
// 交互式登录的暂存会话（add 流程的 need_* 分支：后续短信端点用同一 http 实例续完）
// 对齐 sidecar._SESSIONS 的「sessionId → 会话」持有语义。
// -----------------------------------------------------------------------------
public sealed class EcloudPendingLogin
{
    public required EcloudHttpUtil Http { get; init; }
    public required string Username { get; init; }
    public required string Password { get; init; }
    public required string DeviceUid { get; init; }
    public string Mobile { get; set; } = "";
    public string? LoginCode { get; set; }
    public string Branch { get; set; } = "";
}

public static class EcloudPendingLogins
{
    private static readonly ConcurrentDictionary<string, EcloudPendingLogin> Pending = new();

    public static void Put(string key, EcloudPendingLogin login) => Pending[key] = login;
    public static EcloudPendingLogin? Take(string key) => Pending.TryGetValue(key, out var p) ? p : null;
    public static bool TryGet(string key, out EcloudPendingLogin? login) => Pending.TryGetValue(key, out login);
    public static void Remove(string key) => Pending.TryRemove(key, out _);
}
