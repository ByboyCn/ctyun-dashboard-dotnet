using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CtyunDashboard.Persist;
using CtyunDashboard.Ydpc;

namespace CtyunDashboard.CtYun;

/// <summary>
/// 单账号运行时：登录态管理、桌面同步、旁观者脉冲/挂机认领会话、官方任务（打卡/AI/兑换）。
/// 协议对齐 dashboard server.js + app/tasks/native_tasks.js。
/// </summary>
public sealed class AccountRuntime
{
    private readonly Db _db;
    private readonly LogHub _log;
    private readonly AppSettings _settings;
    public SmAccount Row;   // 非 readonly：账号设置保存后由 ReloadAll 换入最新行
    private CyApi? _api;
    private readonly SemaphoreSlim _claimGate = new(1, 1);
    public volatile bool HangRunning;
    public DateTime? HangUntil;
    private List<(string Name, int Current, int Total, int Status, int Points)> _tasks = [];

    public string Id => Row.Id;
    public string Name => string.IsNullOrEmpty(Row.Name) ? Row.User : Row.Name;

    public AccountRuntime(Db db, LogHub log, AppSettings settings, SmAccount row)
    {
        _db = db; _log = log; _settings = settings; Row = row;
    }

    private void Log(string level, string msg) => _log.Write(level, "CtYun", Name, msg);

    /// <summary>密钥重协商/会话变化后刷新落盘登录态。</summary>
    private void RefreshPersistedSession()
    {
        try
        {
            var api = Api();
            if (!api.LoggedIn) return;
            var snapshot = _db.Protect(api.ExportSession());
            if (snapshot != Row.EncSession)
            {
                Row.EncSession = snapshot;
                _db.UpdateAccount(Row);
            }
        }
        catch { }
    }

    private CyApi Api()
    {
        if (_api != null) return _api;
        _api = new CyApi(Row.User, (lv, acc, msg) => _log.Write(lv, "CtYun", Name, msg));
        _api.ReLoginHandler = ReLoginAsync;
        _api.SessionChanged += RefreshPersistedSession;
        return _api;
    }

    /// <summary>上次主动续期时间（启动后 12 小时开始，每 12 小时一轮）。</summary>
    public DateTime LastSessionRenew { get; set; } = DateTime.Now.AddHours(12);

    /// <summary>会话免密续期（genLoginToken→tokenLogin），失败自动回退密码重登。</summary>
    public async Task<bool> RenewSessionAsync()
    {
        try
        {
            if (!await EnsureLoginAsync()) return false;
            await Api().RenewAsync();
            RefreshPersistedSession();
            Log("success", "会话免密续期成功（token 已轮转，登录态已落盘）");
            return true;
        }
        catch (Exception ex)
        {
            Log("warning", "免密续期失败: " + ex.Message + "，回退密码重登");
            return await ReLoginAsync();
        }
    }

    // ---------- 登录态 ----------
    private DateTime _reloginCooldownUntil;   // 自动重登失败后的冷却（防 30060/30090 风控循环）
    private CyApi? _captchaApi;               // 验证码重验证专用会话（图验 key 与 Cookie 绑定同一实例）

    public async Task<bool> EnsureLoginAsync()
    {
        var api = Api();
        if (api.LoggedIn) return true;
        if (DateTime.Now < _reloginCooldownUntil)
        {
            Row.LastError = "需要图形验证码：请在卡片上完成「验证码重新验证」";
            _db.UpdateAccount(Row);
            return false;
        }
        if (Row.EncSession != "" && api.ImportSession(_db.Unprotect(Row.EncSession)))
        {
            Log("info", "已从本地登录态恢复会话");
            return true;
        }
        return await ReLoginAsync();
    }

    public async Task<bool> ReLoginAsync()
    {
        var api = Api();
        api.InvalidateSession();
        if (string.IsNullOrEmpty(Row.EncPassword))
        {
            Log("warning", "本地无凭据，无法自动重登（请扫码或重新验证）");
            return false;
        }
        var pwd = _db.Unprotect(Row.EncPassword);
        var r = await api.LoginAsync(Row.User, pwd, null);
        if (r.Code != 0 || !api.LoggedIn)
        {
            // 30060/30090 = 服务端要求图形验证码（风控标记）：暂停自动重登 10 分钟，
            // 提示用户走「验证码重新验证」，绝不循环重试加剧风控
            var captchaRequired = r.Code is 30060 or 30090 || api.NeedsCaptcha || r.Msg.Contains("验证码");
            Row.LastError = captchaRequired
                ? "需要图形验证码：请在卡片上完成「验证码重新验证」"
                : "登录失败: " + r.Code + " " + r.Msg;
            if (captchaRequired) { api.MarkNeedsCaptcha(); _reloginCooldownUntil = DateTime.Now.AddMinutes(10); }
            _db.UpdateAccount(Row);
            return false;
        }
        Row.EncSession = _db.Protect(api.ExportSession());
        Row.LastLoginAt = Db.Now();
        Row.LastError = null;
        _reloginCooldownUntil = DateTime.MinValue;
        _db.UpdateAccount(Row);
        Log("success", "登录成功，登录态已加密落盘");
        return true;
    }

    /// <summary>取验证码图（「验证码重新验证」流程第一步；实例缓存保证 Cookie/key 绑定一致）。</summary>
    public async Task<(byte[] Image, string Key)> BeginCaptchaReloginAsync()
    {
        _captchaApi ??= new CyApi(Row.User, (lv, acc, msg) => _log.Write(lv, "CtYun", Name, msg));
        if (_captchaApi.Eid == "") await _captchaApi.NegotiateAsync();
        var (img, key) = await _captchaApi.GetCaptchaAsync();
        return (img, key);
    }

    /// <summary>带图形验证码重新登录（解除 30060/30090 风控标记），成功即刷新落盘登录态。</summary>
    public async Task<bool> ReloginWithCaptchaAsync(string captchaCode)
    {
        var api = _captchaApi;
        if (api == null || Row.EncPassword == "") return false;
        var pwd = _db.Unprotect(Row.EncPassword);
        var r = await api.LoginAsync(Row.User, pwd, captchaCode);
        if (r.Code != 0 || !api.LoggedIn) return false;
        Row.EncSession = _db.Protect(api.ExportSession());
        Row.LastLoginAt = Db.Now();
        Row.LastError = null;
        _reloginCooldownUntil = DateTime.MinValue;
        _db.UpdateAccount(Row);
        Log("success", "验证码重新验证成功，登录态已刷新");
        return true;
    }

    // ---------- 桌面 ----------
    public async Task<List<SmDesktop>> SyncDesktopsAsync()
    {
        await EnsureLoginAsync();
        var list = await Api().GetAllDesktopsAsync();
        RefreshPersistedSession();
        _db.SyncDesktops(Row, list.Select(d => (d.Id, d.Name, d.UseStatus, d.UseStatusText, d.Spec, d.RawJson)).ToList());
        return _db.DesktopsOf(Row.Id);
    }

    internal List<(string Name, int Current, int Total, int Status, int Points)> TasksSnapshot => _tasks;

    // ---------- 旁观者脉冲 / 认领会话 ----------
    private DateTime _lastSkipLog;

    /// <summary>对一台云电脑执行一次保活会话。claim=false 旁观者脉冲；claim=true 认领（挂机/打卡）。</summary>
    public async Task<bool> PulseSessionAsync(SmDesktop desk, bool claim, int holdSec, string reason)
    {
        if (!_claimGate.Wait(0))
        {
            if ((DateTime.Now - _lastSkipLog).TotalSeconds >= 60)   // 认领期间每台每分钟只刷一条，避免 172 台 × 5 秒刷屏
            {
                _lastSkipLog = DateTime.Now;
                Log("info", "[" + desk.Name + "] 存在进行中的认领会话，本次" + reason + "跳过（后续跳过日志静默）");
            }
            return false;
        }
        var hookOk = false;
        var hookErr = "";
        var startedAt = DateTime.Now;
        try
        {
            if (!await EnsureLoginAsync()) { hookErr = "未登录"; return false; }
            var (info, _) = await Api().GetConnectInfoAsync(desk.DesktopId);
            RefreshPersistedSession();
            if (info.ValueKind != JsonValueKind.Object)
            {
                hookErr = "云电脑未就绪（可能开机中/已关机）";
                Log("warning", "[" + desk.Name + "] " + hookErr + "，跳过");
                return false;
            }
            var cfg = ClinkConfig.FromResponse(info);
            using var channel = new ClinkMain(cfg, Name, (lv, acc, msg) => _log.Write(lv, Name, acc, msg));
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await channel.ConnectAsync(Api().UserName, Api().UserId, claim, cts.Token);
            await channel.ReadyTask.WaitAsync(TimeSpan.FromSeconds(30));

            var deadline = startedAt.AddSeconds(holdSec);
            while (DateTime.Now < deadline)
            {
                await Task.Delay(3000);
                if (!channel.Ready)
                {
                    Log("warning", "[" + desk.Name + "] [" + reason + "] 通道中断 (保持 " + HoldSecs(startedAt) + "s): " + channel.LastCloseReason);
                    break;
                }
                // 挂机认领中检测到官方客户端在场 → 主动避让
                if (claim && channel.LastPresenceAt is { } at && at > startedAt)
                {
                    Log("warning", "[" + desk.Name + "] 挂机中检测到官方客户端接入，主动让位避让 (已保持 " + HoldSecs(startedAt) + "s)");
                    break;
                }
            }

            var held = HoldSecs(startedAt);
            hookOk = channel.HandshakeDone;
            if (!hookOk) hookErr = channel.LastCloseReason;
            Log(claim ? "success" : "info",
                "[" + desk.Name + "] " + reason + "会话结束 (保持 " + held + "s | 103握手=" + channel.HandshakeDone +
                " 112认领=" + channel.ClaimSent + " 收 " + channel.BytesRecv / 1024.0 + "KB)");
            return channel.HandshakeDone;
        }
        catch (Exception ex)
        {
            hookErr = ex.Message;
            Log("warning", "[" + desk.Name + "] " + reason + "异常: " + ex.Message);
            return false;
        }
        finally
        {
            _db.TouchPulse(Row.Id, desk.DesktopId);
            try { await Api().QuitConnectAsync(desk.DesktopId); } catch { }
            _ = PulseHook.FireAsync(_db, Name, desk.DesktopId, DesktopCodeOf(desk), desk.Name, hookOk, hookErr, HoldSecs(startedAt), reason);
            _claimGate.Release();
        }
    }

    /// <summary>desktopCode：官方原始字段优先，缺省回退 desktopId。</summary>
    internal static string DesktopCodeOf(SmDesktop desk)
    {
        if (desk.RawJson == "") return desk.DesktopId;
        try
        {
            using var doc = JsonDocument.Parse(desk.RawJson);
            var code = CyApi.GetStr(doc.RootElement, "desktopCode");
            return code != "" ? code : desk.DesktopId;
        }
        catch { return desk.DesktopId; }
    }

    private static int HoldSecs(DateTime from) => (int)(DateTime.Now - from).TotalSeconds;

    // ---------- 电源 ----------
    public async Task<string> PowerAsync(string desktopId, string action)
    {
        await EnsureLoginAsync();
        var (op, cn) = action.ToLowerInvariant() switch
        {
            "poweron" or "start" => (1, "开机"),
            "awake" or "wakeup" or "resume" => (18, "唤醒"),
            "shutdown" or "poweroff" => (2, "关机"),
            _ => (3, "重启"),
        };
        var r = await Api().OperateAsync(desktopId, op);
        // 开机/唤醒双重信令互补回退（对齐 server.js Triple Link）
        if (r.Code != 0 && (op == 1 || op == 18))
        {
            var alt = op == 1 ? 18 : 1;
            Log("info", "主信令(" + op + ")未成功(" + r.Msg + ")，尝试互补信令(" + alt + ")...");
            r = await Api().OperateAsync(desktopId, alt);
        }
        var ok = r.Code == 0;
        Log(ok ? "success" : "error", "电源指令[" + cn + "] " + desktopId + ": " + (ok ? "已生效" : r.Msg));
        return ok ? "" : r.Msg;
    }

    // ---------- 官方任务中心 ----------
    public async Task<bool> RefreshOfficialTasksAsync()
    {
        try
        {
            if (!await EnsureLoginAsync()) return false;
            var tl = await Api().GetTaskListAsync();
            if (tl.Code != 0 || tl.Data.ValueKind != JsonValueKind.Array)
            {
                if (CyApi.IsAuthExpired(tl.Code, tl.Msg)) await ReLoginAsync();
                Log("warning", "任务中心刷新失败 code=" + tl.Code + " " + tl.Msg);
                return false;
            }
            var tasks = new List<(string, int, int, int, int)>();
            foreach (var t in tl.Data.EnumerateArray())
            {
                var name = t.TryGetProperty("taskDefName", out var n) ? n.GetString() ?? "" : "";
                var cur = t.TryGetProperty("currentProgress", out var c) ? c.GetInt32() : 0;
                var total = t.TryGetProperty("totalProgress", out var tt) ? tt.GetInt32() : 1;
                var st = t.TryGetProperty("status", out var s) ? s.GetInt32() : 0;
                var pts = 100;
                if (t.TryGetProperty("pointsList", out var pl) && pl.ValueKind == JsonValueKind.Array && pl.GetArrayLength() > 0 &&
                    pl[0].TryGetProperty("value", out var pv)) pts = pv.GetInt32();
                tasks.Add((name, cur, total, st, pts));
            }
            _tasks = tasks;

            var today = Db.Today();
            Mark(ref tasks, today, "sign", "登录");
            Mark(ref tasks, today, "ai", "AI对话");
            var hang = tasks.FirstOrDefault(x => x.Item1.Contains("使用1小时"));
            if (hang.Item1 != null)
            {
                Row.HangMinutesToday = hang.Item2 / 60;
                if (hang.Item4 == 2 || (hang.Item3 > 0 && hang.Item2 >= hang.Item3))
                    if (Row.LastHangTime == null || !Row.LastHangTime.StartsWith(today)) Row.LastHangTime = Db.Now();
            }

            var pt = await Api().GetUserPointsAsync();
            if (pt.Code == 0 && pt.Data.ValueKind == JsonValueKind.Array && pt.Data.GetArrayLength() > 0)
            {
                foreach (var p in pt.Data.EnumerateArray())
                {
                    var willOut = p.TryGetProperty("willOutDate", out var wo) && wo.ValueKind == JsonValueKind.True;
                    if (!willOut && p.TryGetProperty("points", out var pp)) { Row.Points = pp.GetInt32(); break; }
                }
            }
            _db.UpdateAccount(Row);
            return true;
        }
        catch (Exception ex)
        {
            Log("warning", "任务中心访问失败: " + ex.Message);
            return false;
        }
    }

    private void Mark(ref List<(string Name, int Current, int Total, int Status, int Points)> tasks, string today, string kind, string contains)
    {
        var t = tasks.FirstOrDefault(x => x.Name.Contains(contains));
        if (t.Name == null) return;
        if (t.Status == 2 || (t.Total > 0 && t.Current >= t.Total))
        {
            if (kind == "sign" && (Row.LastSignTime == null || !Row.LastSignTime.StartsWith(today))) Row.LastSignTime = Db.Now();
            if (kind == "ai" && (Row.LastAiTime == null || !Row.LastAiTime.StartsWith(today))) Row.LastAiTime = Db.Now();
            if (kind == "hang" && (Row.LastHangTime == null || !Row.LastHangTime.StartsWith(today))) Row.LastHangTime = Db.Now();
        }
    }

    public bool IsTaskDoneToday(string kind) => kind switch
    {
        "sign" => Row.LastSignTime?.StartsWith(Db.Today()) == true,
        "ai" => Row.LastAiTime?.StartsWith(Db.Today()) == true,
        "hang" => Row.LastHangTime?.StartsWith(Db.Today()) == true,
        _ => false,
    };

    // ---------- 打卡：短认领会话 ----------
    public async Task<string> SignTaskAsync()
    {
        if (!Row.AutoSign) return "打卡开关已关闭";
        if (HangRunning) return "挂机会话进行中，打卡复用挂机认领";
        await RefreshOfficialTasksAsync();
        if (IsTaskDoneToday("sign")) return "今日打卡已达成";
        var desks = _db.DesktopsOf(Row.Id).Where(d => d.TaskEnabled).ToList();
        if (desks.Count == 0) return "名下无可用云电脑";
        var target = desks.FirstOrDefault(d => d.UseStatus == 25 || d.UseStatusText == "运行中") ?? desks[0];
        var ok = await PulseSessionAsync(target, claim: true, holdSec: 25, reason: "打卡认领");
        await Task.Delay(3000);
        await RefreshOfficialTasksAsync();
        return IsTaskDoneToday("sign") ? "打卡完成 (+100积分)"
             : ok ? "认领已下发，等待官方落账确认（稍后自动复检）" : "认领会话未完成";
    }

    // ---------- 挂机 1 小时 ----------
    public async Task<string> HangTaskAsync()
    {
        if (!Row.AutoHang) return "挂机开关已关闭";
        if (HangRunning) return "挂机已在进行中";
        await RefreshOfficialTasksAsync();
        if (IsTaskDoneToday("hang")) return "今日挂机任务已达成";
        var desks = _db.DesktopsOf(Row.Id).Where(d => d.TaskEnabled).ToList();
        if (desks.Count == 0) return "名下无可用云电脑";
        var target = desks.FirstOrDefault(d => d.UseStatus == 25 || d.UseStatusText == "运行中") ?? desks[0];
        HangRunning = true;
        HangUntil = DateTime.Now.AddSeconds(3600);
        try
        {
            Log("info", "[" + target.Name + "] 开始 1 小时挂机认领（时长任务）...");
            var ok = await PulseSessionAsync(target, claim: true, holdSec: 3600, reason: "挂机");
            await RefreshOfficialTasksAsync();
            return ok && IsTaskDoneToday("hang") ? "挂机达成 (+100积分)" : ok ? "挂机会话结束，等待官方计时落账" : "挂机会话中断";
        }
        finally
        {
            HangRunning = false;
            HangUntil = null;
        }
    }

    // ---------- AI 智能对话 ----------
    private static readonly string[] Prompts =
    [
        "今天北京天气怎么样？（请用一句话回答）",
        "给我讲一个冷笑话。（简短回答）",
        "来一首唐诗。（简短回答）",
        "空腹可以吃饭吗？（幽默简短回答）",
        "推荐一部经典的科幻电影。（简明扼要）",
        "人工智能未来发展趋势是什么？（简明扼要）",
        "怎样保持良好的身心健康？（简短回答）",
        "请用一句话分享今天的正能量心情。",
    ];

    public async Task<string> AiChatTaskAsync()
    {
        if (!Row.AutoAi) return "AI 对话开关已关闭";
        if (IsTaskDoneToday("ai")) return "今日 AI 对话已达成";
        const string service = "https://eaichat.ctyun.cn:443/chat/#/aichat";
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(45) };

        var sysJson = await http.GetStringAsync("https://gwyilian.ctyun.cn/server/eaiSysInfo");
        using (var doc = JsonDocument.Parse(sysJson))
        {
            if (!doc.RootElement.TryGetProperty("data", out var dfield) || dfield.ValueKind != JsonValueKind.String)
                return "eaiSysInfo 返回异常";
            var raw = dfield.GetString()!.Replace("\r", "").Replace("\n", "");
            var dec = AesEcbDecrypt("chinatelecom@cnn", Convert.FromBase64String(raw));
            using var gdoc = JsonDocument.Parse(dec);
            if (!gdoc.RootElement.TryGetProperty("sso", out var sso)) return "未能提取 SSO 公钥配置";
            var ssopk = sso.TryGetProperty("ssopk", out var pk) ? pk.GetString() : null;
            var ssopkid = sso.TryGetProperty("ssopkid", out var pkid) ? pkid.GetString() : "";
            if (string.IsNullOrEmpty(ssopk)) return "SSO 公钥为空";
            return await AiChatFlowAsync(http, service, ssopk, ssopkid ?? "");
        }
    }

    private async Task<string> AiChatFlowAsync(HttpClient http, string service, string ssopk, string ssopkid)
    {
        // 2. CAS Ticket（会话失效自动重登一次）
        var ticketRes = await Api().GetCasTicketAsync(service);
        if (ticketRes.Code == 40010 || ticketRes.Data.ValueKind != JsonValueKind.Object ||
            !ticketRes.Data.TryGetProperty("ticket", out _))
        {
            Log("info", "CAS 票据失效，重新登录后重试...");
            if (!await ReLoginAsync()) return "重新登录失败，无法获取 CAS 票据";
            ticketRes = await Api().GetCasTicketAsync(service);
        }
        if (ticketRes.Data.ValueKind != JsonValueKind.Object || !ticketRes.Data.TryGetProperty("ticket", out var tk))
            return "获取 CAS Ticket 失败: " + ticketRes.Msg;
        var ticket = tk.GetString()!;

        // 3. 随机 clientKey RSA-PKCS1 加密 → ticketAuthorize 换 sessionKey
        var clientKey = RandomString(16);
        var pem = "-----BEGIN PUBLIC KEY-----\n" + ssopk + "\n-----END PUBLIC KEY-----";
        using var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        var encClientKey = Convert.ToHexString(rsa.Encrypt(Encoding.UTF8.GetBytes(clientKey), RSAEncryptionPadding.Pkcs1)).ToLowerInvariant();

        var form = new Dictionary<string, string>
        {
            ["loginType"] = "iamTicket", ["clientId"] = "eaiapp", ["iamTicket"] = ticket,
            ["redirectUri"] = service, ["clientKey"] = encClientKey, ["clientKeyId"] = ssopkid,
        };
        var authResp = await http.PostAsync("https://eaichat.ctyun.cn/sso/login/v2/iam/ticketAuthorize", new FormUrlEncodedContent(form));
        var authText = await authResp.Content.ReadAsStringAsync();
        using var adoc = JsonDocument.Parse(authText);
        if (adoc.RootElement.TryGetProperty("resultCode", out var rc) && rc.GetInt32() != 0)
            return "SSO 鉴权失败: " + (adoc.RootElement.TryGetProperty("resultMsg", out var rm) ? rm.GetString() : authText);
        if (!adoc.RootElement.TryGetProperty("data", out var adata) || !adata.TryGetProperty("sessionKey", out var skEl))
            return "SSO 响应缺 sessionKey";
        var sk = AesEcbDecrypt(clientKey, Convert.FromBase64String(skEl.GetString()!));

        string ylToken = "", ylSsid = "";
        foreach (var hv in authResp.Headers.GetValues("Set-Cookie") ?? Enumerable.Empty<string>())
        {
            if (hv.StartsWith("YL-Token=")) ylToken = hv[9..hv.IndexOf(';')];
            if (hv.StartsWith("YL-Ssid=")) ylSsid = hv[8..hv.IndexOf(';')];
        }

        // 4. 发送对话
        var prompt = Prompts[Random.Shared.Next(Prompts.Length)];
        var bodyObj = new System.Text.Json.Nodes.JsonObject
        {
            ["key_model"] = "telechat",
            ["messages"] = new System.Text.Json.Nodes.JsonArray(
                new System.Text.Json.Nodes.JsonObject { ["role"] = "user", ["content"] = prompt }),
            ["stream"] = false, ["client_retry"] = true, ["web_search"] = false,
        };
        var body = System.Text.Json.JsonSerializer.Serialize(bodyObj, AppJson.Default.JsonObject);
        var ts = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString();
        var rnd = RandomString(8);
        var webSign = CyCrypto.Sha256Hex(CyCrypto.Md5Hex(body) + "&" + sk + "&" + ts + "&" + rnd);

        var req = new HttpRequestMessage(HttpMethod.Post, "https://eaichat.ctyun.cn/ai/portal/v3/openai/chat/completions")
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };
        req.Headers.Add("Cookie", "YL-Token=" + ylToken + "; YL-Ssid=" + ylSsid);
        req.Headers.Add("YL-Authorization", ylToken);
        req.Headers.Add("Referer", "https://eaichat.ctyun.cn/chat/");
        req.Headers.Add("Origin", "https://eaichat.ctyun.cn");
        req.Headers.Add("x-client-trace-id", Guid.NewGuid().ToString());
        req.Headers.Add("x-eai-source", "web-eai");
        req.Headers.Add("x-eai-version", "202060305");
        req.Headers.Add("YL-Main-Version", "202060305");
        req.Headers.Add("YL-Product-Id", "5");
        req.Headers.Add("Web-Signature", webSign);
        req.Headers.Add("Web-Random", rnd);
        req.Headers.Add("Web-Timestamp", ts);

        var chatResp = await http.SendAsync(req);
        if (!chatResp.IsSuccessStatusCode) return "AI 对话接口异常 (HTTP " + (int)chatResp.StatusCode + ")";
        Log("success", "AI 对话完成: \"" + prompt + "\"");
        await RefreshOfficialTasksAsync();
        return IsTaskDoneToday("ai") ? "AI 对话完成 (+100积分)" : "AI 对话已发送，等待官方落账";
    }

    internal static string AesEcbDecrypt(string key, byte[] cipher)
    {
        using var aes = Aes.Create();
        aes.Key = Encoding.UTF8.GetBytes(key);
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.PKCS7;
        using var dec = aes.CreateDecryptor();
        return Encoding.UTF8.GetString(dec.TransformFinalBlock(cipher, 0, cipher.Length));
    }

    internal static string RandomString(int n)
    {
        const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        var buf = new char[n];
        for (var i = 0; i < n; i++) buf[i] = chars[Random.Shared.Next(chars.Length)];
        return new string(buf);
    }

    public async Task<ApiResult> GetRewardsAsync()
    {
        await EnsureLoginAsync();
        return await Api().GetRewardsAsync();
    }

    // ---------- 自动兑换 ----------
    public async Task<string> RedeemAsync(string prodId, string prodName, int costPoints, int times, string desktopId)
    {
        await EnsureLoginAsync();
        var total = costPoints * times;
        await RefreshOfficialTasksAsync();
        if (Row.Points > 0 && Row.Points < total) return "积分不足：现有 " + Row.Points + "，需要 " + total;

        var needDesktop = prodId is "17000397" or "17000398"; // 升配/扩容类需绑机
        var attrs = new System.Text.Json.Nodes.JsonArray();
        if (needDesktop && desktopId != "")
            attrs.Add((System.Text.Json.Nodes.JsonNode)new System.Text.Json.Nodes.JsonObject { ["attrKey"] = "bindDesktopId", ["attrVal"] = long.Parse(desktopId) });
        else
            attrs.Add((System.Text.Json.Nodes.JsonNode)new System.Text.Json.Nodes.JsonObject { ["attrKey"] = "mobilephone" });

        var order = new System.Text.Json.Nodes.JsonObject
        {
            ["busiChannel"] = "010", ["orderType"] = 1, ["pointType"] = 1, ["points"] = total,
            ["sku"] = new System.Text.Json.Nodes.JsonArray(new System.Text.Json.Nodes.JsonObject
            {
                ["execSort"] = 1, ["prodId"] = long.Parse(prodId), ["attrs"] = attrs,
            }),
        };
        var body = System.Text.Json.JsonSerializer.Serialize(order, AppJson.Default.JsonObject);

        string lastError = "";
        for (var attempt = 1; attempt <= 3; attempt++)
        {
            if (attempt > 1) await Task.Delay(3000);
            var r = await Api().PlaceOrderAsync(body);
            if (r.Code == 0)
            {
                Log("success", "兑换成功 [" + prodName + "] x" + times + "，共 " + total + " 积分");
                _ = Svc.NotifyHubField.SendAsync(Row.Name, "积分兑换成功 - " + Name, "账号 [" + Name + "] 成功兑换 [" + prodName + "] x" + times + "，共 " + total + " 积分");
                await RefreshOfficialTasksAsync();
                return "";
            }
            lastError = r.Msg;
            if (lastError.Contains("不足") || lastError.Contains("风控") || lastError.Contains("频繁") || lastError.Contains("上限"))
                break;
        }
        Log("error", "兑换失败: " + lastError);
        return lastError;
    }
}

/// <summary>保活引擎：多账号注册表 + 高精度时间戳时间轮（每台云电脑独立周期）。</summary>
public sealed class Engine
{
    private readonly Db _db;
    private readonly LogHub _log;
    private readonly ConcurrentDictionary<string, AccountRuntime> _runtimes = new();
    private readonly ConcurrentDictionary<string, YdpcAccountRuntime> _ydpc = new();
    private readonly ConcurrentDictionary<string, byte> _busy = new();
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _pulseGates = new();   // 每账号脉冲并发闸（防 172 台齐发）
    private Timer? _timer;
    public DateTime StartedAt { get; } = DateTime.Now;

    public Engine(Db db, LogHub log) { _db = db; _log = log; }

    public int Count => _runtimes.Count;
    public AccountRuntime? Get(string id) => _runtimes.TryGetValue(id, out var r) ? r : null;
    public List<AccountRuntime> All() => [.. _runtimes.Values];

    // ---- 移动云（ydpc-soho / ydpc-ecloud）运行时表：与天翼 _runtimes 完全隔离 ----
    public YdpcAccountRuntime? GetYdpc(string id) => _ydpc.TryGetValue(id, out var r) ? r : null;
    public List<YdpcAccountRuntime> YdpcAll() => [.. _ydpc.Values];

    public YdpcAccountRuntime EnsureYdpc(SmAccount row)
    {
        if (_ydpc.TryGetValue(row.Id, out var existing)) { existing.RefreshRow(row); return existing; }
        var rt = new YdpcAccountRuntime(row);
        _ydpc[row.Id] = rt;
        return rt;
    }

    public void RemoveYdpc(string id)
    {
        if (_ydpc.TryRemove(id, out var old)) _ = old.DisposeResourcesAsync();
    }

    public void ReloadAll()
    {
        var settings = _db.GetSettings();
        var rows = _db.Accounts().Where(a => a.Platform == "ctyun").ToList();
        var ids = rows.Select(r => r.Id).ToHashSet();
        foreach (var id in _runtimes.Keys.Where(id => !ids.Contains(id)).ToList()) _runtimes.TryRemove(id, out _);
        foreach (var row in rows)
        {
            if (_runtimes.TryGetValue(row.Id, out var exist))
                exist.Row = row;    // 已有运行时：换入最新行（保存后的开关/间隔立即生效）
            else
                _runtimes[row.Id] = new AccountRuntime(_db, _log, settings, row);
        }

        // ---- 移动云（ydpc-*）：独立运行时表；更新走 RefreshRow 保留内存会话态 ----
        var yrows = _db.Accounts().Where(a => a.Platform.StartsWith("ydpc")).ToList();
        var yids = yrows.Select(r => r.Id).ToHashSet();
        foreach (var id in _ydpc.Keys.Where(id => !yids.Contains(id)).ToList())
        {
            if (_ydpc.TryRemove(id, out var old)) _ = old.DisposeResourcesAsync();
        }
        foreach (var row in yrows) EnsureYdpc(row);
    }

    public void Start()
    {
        ReloadAll();
        _timer ??= new Timer(_ => _ = TickAsync(), null, 5000, 5000);
    }

    private async Task TickAsync()
    {
        var settings = _db.GetSettings();
        var now = DateTime.Now;

        // 会话主动续期：每 12 小时无感轮转一次 token，杜绝会话自然过期
        foreach (var rt in _runtimes.Values)
        {
            if (rt.HangRunning) continue;
            if (now < rt.LastSessionRenew) continue;
            rt.LastSessionRenew = now.AddHours(12);
            var target = rt;
            _ = Task.Run(async () =>
            {
                try { await target.RenewSessionAsync(); } catch { }
            });
        }

        foreach (var rt in _runtimes.Values)
        {
            if (!rt.Row.KeepaliveEnabled) continue;
            List<SmDesktop> desks;
            try { desks = _db.DesktopsOf(rt.Row.Id).Where(d => d.KeepaliveEnabled).ToList(); }
            catch { continue; }
            foreach (var desk in desks)
            {
                var interval = Math.Clamp(desk.KeepaliveInterval ?? rt.Row.PulseIntervalSeconds, 10, 604800);   // 10 秒 ~ 7 天
                var last = desk.LastPulseAt != null && DateTime.TryParse(desk.LastPulseAt, out var t) ? t : DateTime.MinValue;
                if ((now - last).TotalSeconds < interval) continue;
                var key = rt.Row.Id + ":" + desk.DesktopId;
                if (!_busy.TryAdd(key, 0)) continue;
                var gate = _pulseGates.GetOrAdd(rt.Row.Id, _ => new SemaphoreSlim(3, 3));   // 每账号最多 3 路并发脉冲（172 台齐发会把连接打爆）
                _ = Task.Run(async () =>
                {
                    try
                    {
                        await gate.WaitAsync();
                        try
                        {
                            if (!rt.HangRunning)
                                await rt.PulseSessionAsync(desk, claim: false, holdSec: Math.Clamp(settings.KeepAliveSeconds, 15, 60), reason: "脉冲");
                        }
                        finally { gate.Release(); }
                    }
                    catch { }
                    finally { _busy.TryRemove(key, out _); }
                });
            }
        }

        // ---- 移动云（ydpc-soho / ydpc-ecloud）：账号级周期调度（ydpc 集成；天翼逻辑不受影响）----
        foreach (var rt in _ydpc.Values)
        {
            if (!rt.Row.KeepaliveEnabled) continue;
            var interval = Math.Clamp(rt.Row.PulseIntervalSeconds, 60, 604800);
            if (DateTime.Now < rt.NextRunAt) continue;
            var key = "ydpc:" + rt.Row.Id;
            if (!_busy.TryAdd(key, 0)) continue;
            _ = Task.Run(async () =>
            {
                try { await rt.RunKeepaliveRoundAsync(); }
                catch { }
                finally
                {
                    rt.NextRunAt = DateTime.Now.AddSeconds(interval);
                    _busy.TryRemove(key, out _);
                }
            });
        }
    }

    public void NotifySettingsChanged()
    {
        foreach (var rt in _runtimes.Values)
        {
            var row = _db.AccountById(rt.Row.Id);
            if (row != null) rt.Row.PulseIntervalSeconds = row.PulseIntervalSeconds;
        }
    }
}

/// <summary>全局服务定位（Program 初始化时赋值；AOT 环境避免过度 DI 反射）。</summary>
public static class Svc
{
    public static Db Db = null!;
    public static LogHub Logs = null!;
    public static Engine Engine = null!;
    public static NotifyHub NotifyHubField = null!;
    public static Scheduler Scheduler = null!;
    public static DateTime StartedAt = DateTime.Now;
}
