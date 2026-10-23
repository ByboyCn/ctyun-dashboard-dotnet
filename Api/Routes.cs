using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Google.Protobuf;
using CtyunDashboard.CtYun;
using CtyunDashboard.DesktopView;
using CtyunDashboard.Ecloud;
using CtyunDashboard.Persist;
using CtyunDashboard.Ydpc;
using Api = CtyunDashboard.Api;

namespace CtyunDashboard;

/// <summary>Protobuf API 路由（契约见 proto/api.proto 底部端点表）。请求体 = 请求消息二进制，响应 = Envelope。</summary>
public static class Routes
{
    private static readonly Dictionary<string, CyApi> QrSessions = new();
    private static readonly Dictionary<string, string> QrOwner = new();
    private static readonly Dictionary<string, (byte[] Img, string Key)> CaptchaCache = new();

    public static void Map(WebApplication app)
    {
        // ---- 认证 ----
        MapPost<Api.LoginReq>(app, "/api/auth/login", async (ctx, req) =>
        {
            var user = Svc.Db.FindUser(req.Username);
            if (user == null || !Auth.Verify(req.Password, user.PwdHash, user.Salt))
            {
                Svc.Logs.Write("warning", "Auth", req.Username, "登录失败：" + (user == null ? "用户不存在" : "密码错误"));
                return (1, null);
            }
            var token = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
            Svc.Db.InsertSession(new SmSession { Token = token, UserId = user.Id, ExpiresAt = DateTime.Now.AddDays(30).ToString("yyyy-MM-dd HH:mm:ss") });
            Svc.Db.PurgeExpiredSessions();
            ctx.Response.Cookies.Append("sid", token, new CookieOptions { HttpOnly = true, SameSite = SameSiteMode.Lax, MaxAge = TimeSpan.FromDays(30) });
            return (0, new Api.UserReply { Id = user.Id, Username = user.Username, Role = user.Role });
        });
        MapPost<Api.Empty>(app, "/api/auth/logout", (ctx, _) =>
        {
            if (ctx.Request.Cookies.TryGetValue("sid", out var sid)) Svc.Db.DeleteSession(sid);
            ctx.Response.Cookies.Delete("sid");
            return Task.FromResult<(int, IMessage?)>(new(0, null));
        });
        MapGet(app, "/api/auth/me", ctx => Task.FromResult(UserReply(ctx)));
        MapPost<Api.ChangePwdReq>(app, "/api/auth/changepwd", (ctx, req) =>
        {
            var user = CurrentUser(ctx)!;
            if (!Auth.Verify(req.OldPwd, user.PwdHash, user.Salt))
                return Task.FromResult<(int, IMessage?)>(new(1, new Api.BoolReply { Detail = "旧密码错误" }));
            (user.PwdHash, user.Salt) = Auth.HashPassword(req.NewPwd);
            Svc.Db.UpdateUser(user);
            return Task.FromResult<(int, IMessage?)>(new(0, new Api.BoolReply { Ok = true }));
        });

        // ---- 用户管理 ----
        MapGet(app, "/api/users", ctx =>
        {
            if (CurrentUser(ctx)?.Role != "admin") return Task.FromResult<(int, IMessage?)>(new(1, null));
            var list = new Api.UserList();
            foreach (var u in Svc.Db.Users())
                list.Items.Add(new Api.UserItem { Id = u.Id, Username = u.Username, Role = u.Role, CreatedAt = u.CreatedAt });
            return Task.FromResult<(int, IMessage?)>(new(0, list));
        });
        MapPost<Api.CreateUserReq>(app, "/api/users", (ctx, req) =>
        {
            if (CurrentUser(ctx)?.Role != "admin") return Task.FromResult<(int, IMessage?)>(new(1, null));
            if (Svc.Db.FindUser(req.Username) != null)
                return Task.FromResult<(int, IMessage?)>(new(1, new Api.BoolReply { Detail = "用户名已存在" }));
            var (hash, salt) = Auth.HashPassword(req.Password);
            var u = new SmUser { Id = Db.NewId(), Username = req.Username, Role = req.Role == "admin" ? "admin" : "user", PwdHash = hash, Salt = salt, CreatedAt = Db.Now() };
            Svc.Db.InsertUser(u);
            return Task.FromResult<(int, IMessage?)>(new(0, new Api.UserReply { Id = u.Id, Username = u.Username, Role = u.Role }));
        });
        MapPost<Api.ResetPwdReq>(app, "/api/users/{id}/resetpwd", (ctx, req) =>
        {
            if (CurrentUser(ctx)?.Role != "admin") return Task.FromResult<(int, IMessage?)>(new(1, null));
            var u = Svc.Db.UserById(ctx.Request.RouteValues["id"]!.ToString()!);
            if (u == null) return Task.FromResult<(int, IMessage?)>(new(1, new Api.BoolReply { Detail = "用户不存在" }));
            (u.PwdHash, u.Salt) = Auth.HashPassword(req.Password);
            Svc.Db.UpdateUser(u);
            return Task.FromResult<(int, IMessage?)>(new(0, new Api.BoolReply { Ok = true }));
        });
        MapPost<Api.IdReq>(app, "/api/users/{id}/delete", (ctx, req) =>
        {
            var me = CurrentUser(ctx)!;
            if (me.Role != "admin" || req.Id == me.Id) return Task.FromResult<(int, IMessage?)>(new(1, null));
            Svc.Db.DeleteUser(req.Id);
            return Task.FromResult<(int, IMessage?)>(new(0, new Api.BoolReply { Ok = true }));
        });

        // ---- 账号卡片 ----
        MapGet(app, "/api/accounts", ctx =>
        {
            var me = CurrentUser(ctx)!;
            var list = new Api.AccountList();
            foreach (var rt in Svc.Engine.All())
            {
                if (me.Role != "admin" && rt.Row.Owner != me.Username) continue;
                var card = new Api.AccountCard
                {
                    Id = rt.Row.Id, Platform = rt.Row.Platform, Name = rt.Name,
                    UserMasked = MaskUser(rt.Row.User), Owner = rt.Row.Owner,
                    Online = rt.Row.LastError == null && rt.Row.LastLoginAt != null,
                    KeepaliveEnabled = rt.Row.KeepaliveEnabled, PulseInterval = rt.Row.PulseIntervalSeconds,
                    AutoSign = rt.Row.AutoSign, AutoAi = rt.Row.AutoAi, AutoHang = rt.Row.AutoHang, AutoRedeem = rt.Row.AutoRedeem,
                    Points = rt.Row.Points, HangMinutesToday = rt.Row.HangMinutesToday,
                    LastSignTime = rt.Row.LastSignTime ?? "", LastAiTime = rt.Row.LastAiTime ?? "", LastHangTime = rt.Row.LastHangTime ?? "",
                    StatusText = rt.HangRunning ? "挂机中" : (rt.Row.LastError ?? "运行中"),
                    LastError = rt.Row.LastError ?? "",
                };
                foreach (var d in Svc.Db.DesktopsOf(rt.Row.Id))
                {
                    var interval = Math.Clamp(d.KeepaliveInterval ?? rt.Row.PulseIntervalSeconds, 10, 3300);
                    var last = d.LastPulseAt != null && DateTime.TryParse(d.LastPulseAt, out var t) ? t : DateTime.MinValue;
                    card.Desktops.Add(new Api.DesktopInfo
                    {
                        DesktopId = d.DesktopId, Name = d.Name, UseStatus = d.UseStatus,
                        UseStatusText = d.UseStatusText, Spec = d.Spec,
                        KeepaliveEnabled = d.KeepaliveEnabled, TaskEnabled = d.TaskEnabled,
                        KeepaliveInterval = d.KeepaliveInterval ?? 0,
                        LastPulseAt = d.LastPulseAt ?? "",
                        ConnectUrl = "https://pc.ctyun.cn/#/desktop?id=" +
                                     Convert.ToBase64String(Encoding.UTF8.GetBytes(d.DesktopId)),
                        RawJson = d.RawJson,
                    });
                    var next = (long)Math.Max(0, interval - (DateTime.Now - last).TotalSeconds);
                    if (card.NextPulseInSec == 0 || next < card.NextPulseInSec) card.NextPulseInSec = next;
                }
                foreach (var t in rt.TasksSnapshot)
                    card.Tasks.Add(new Api.TaskProgress { Name = t.Item1, Current = t.Item2, Total = t.Item3, Status = t.Item4, Points = t.Item5 });
                list.Items.Add(card);
            }
            return Task.FromResult<(int, IMessage?)>(new(0, list));
        });

        MapGet(app, "/api/account/captcha", async ctx =>
        {
            var user = ctx.Request.Query["user"].ToString();
            var api = new CyApi(user, (_, _, _) => { });
            await api.NegotiateAsync();
            var (img, key) = await api.GetCaptchaAsync();
            CaptchaCache[user] = (img, key);
            return (0, (IMessage?)new Api.CaptchaImage { Image = "data:image/jpeg;base64," + Convert.ToBase64String(img), Key = key });
        });

        MapPost<Api.AddAccountReq>(app, "/api/account/add", async (ctx, req) =>
        {
            var me = CurrentUser(ctx)!;
            var api = new CyApi(req.User, (_, _, _) => { });
            await api.NegotiateAsync();
            var r = await api.LoginAsync(req.User, req.Password, string.IsNullOrEmpty(req.CaptchaCode) ? null : req.CaptchaCode);
            if (r.Code != 0)
            {
                var (img, key) = await api.GetCaptchaAsync();
                CaptchaCache[req.User] = (img, key);
                return (2, (IMessage?)new Api.NeedCaptcha { Need = true, Image = "data:image/jpeg;base64," + Convert.ToBase64String(img), Key = key });
            }
            var row = new SmAccount
            {
                Id = Db.NewId(), Platform = "ctyun", Owner = me.Username,
                Name = req.Name != "" ? req.Name : req.User, User = req.User,
                EncPassword = Svc.Db.Protect(req.Password),
                EncSession = Svc.Db.Protect(api.ExportSession()),
                LastLoginAt = Db.Now(), AddedAt = Db.Now(),
            };
            Svc.Db.InsertAccount(row);
            Svc.Engine.ReloadAll();
            _ = Task.Run(async () =>
            {
                var rt = Svc.Engine.Get(row.Id);
                if (rt != null)
                {
                    await rt.SyncDesktopsAsync();
                    await rt.RefreshOfficialTasksAsync();
                }
            });
            return (0, (IMessage?)new Api.BoolReply { Ok = true, Detail = row.Id });
        });

        MapPost<Api.QrGenerateReq>(app, "/api/account/qrcode/generate", async (ctx, req) =>
        {
            var api = new CyApi("qr-" + Db.NewId()[..6], (_, _, _) => { });
            await api.NegotiateAsync();
            var (qrId, qrUrl) = await api.GenQrCodeAsync();
            QrSessions[qrId] = api;
            QrOwner[qrId] = CurrentUser(ctx)!.Username;
            return (0, (IMessage?)new Api.QrGenerateReply { QrId = qrId, QrUrl = qrUrl });
        });
        MapGet(app, "/api/account/qrcode/status", async ctx =>
        {
            var qrId = ctx.Request.Query["qrId"].ToString();
            if (!QrSessions.TryGetValue(qrId, out var api))
                return (1, (IMessage?)new Api.QrStatusReply { Status = "expired" });
            var (codeStatus, loginToken) = await api.GetQrStatusAsync(qrId);
            if (loginToken != null)
            {
                var lr = await api.TokenLoginAsync(loginToken);
                if (lr.Code == 0 && api.LoggedIn)
                {
                    var row = new SmAccount
                    {
                        Id = Db.NewId(), Platform = "ctyun",
                        Owner = QrOwner.GetValueOrDefault(qrId, "admin"),
                        Name = api.UserName != "" ? api.UserName : qrId,
                        User = api.UserName != "" ? api.UserName : qrId,
                        EncSession = Svc.Db.Protect(api.ExportSession()),
                        LastLoginAt = Db.Now(), AddedAt = Db.Now(),
                    };
                    Svc.Db.InsertAccount(row);
                    Svc.Engine.ReloadAll();
                    QrSessions.Remove(qrId);
                    QrOwner.Remove(qrId);
                    return (0, (IMessage?)new Api.QrStatusReply { Status = "confirmed", AccId = row.Id });
                }
                return (0, (IMessage?)new Api.QrStatusReply { Status = "scanned" });
            }
            return (0, (IMessage?)new Api.QrStatusReply
            {
                Status = codeStatus switch { 1 => "scanned", 3 => "expired", _ => "waiting" },
            });
        });

        MapPost<Api.UpdateAccountReq>(app, "/api/account/{id}/update", (ctx, req) =>
        {
            var row = Svc.Db.AccountById(req.Id);
            if (row == null || !CanAccess(ctx, row)) return Task.FromResult<(int, IMessage?)>(new(1, null));
            if (req.Name != "") row.Name = req.Name;
            row.KeepaliveEnabled = req.KeepaliveEnabled;
            if (req.PulseInterval > 0) row.PulseIntervalSeconds = Math.Clamp(req.PulseInterval, 10, 604800);
            row.AutoSign = req.AutoSign; row.AutoAi = req.AutoAi; row.AutoHang = req.AutoHang; row.AutoRedeem = req.AutoRedeem;
            if (req.RedeemStrategy != "") row.RedeemStrategy = req.RedeemStrategy;
            if (req.RedeemDay > 0) row.RedeemDay = req.RedeemDay;
            if (req.RedeemStepDays > 0) row.RedeemStepDays = req.RedeemStepDays;
            row.RedeemProdId = req.RedeemProdId; row.RedeemProdName = req.RedeemProdName;
            if (req.RedeemCost > 0) row.RedeemCostPoints = req.RedeemCost;
            Svc.Db.UpdateAccount(row);
            Svc.Engine.ReloadAll();
            return Task.FromResult<(int, IMessage?)>(new(0, new Api.BoolReply { Ok = true }));
        });
        MapPost<Api.IdReq>(app, "/api/account/{id}/delete", (ctx, req) =>
        {
            var row = Svc.Db.AccountById(req.Id);
            if (row == null || !CanAccess(ctx, row)) return Task.FromResult<(int, IMessage?)>(new(1, null));
            Svc.Db.DeleteAccount(req.Id);
            Svc.Engine.ReloadAll();
            return Task.FromResult<(int, IMessage?)>(new(0, new Api.BoolReply { Ok = true }));
        });
        MapPost<Api.IdReq>(app, "/api/account/{id}/relogin", async (ctx, req) =>
        {
            var rt = Svc.Engine.Get(req.Id);
            if (rt == null || !CanAccess(ctx, rt.Row)) return (1, null);
            var ok = await rt.ReLoginAsync();
            return (ok ? 0 : 1, (IMessage?)new Api.BoolReply { Ok = ok });
        });
        MapGet(app, "/api/account/{id}/desktops", async ctx =>
        {
            var rt = EngineOf(ctx);
            if (rt == null) return (1, null);
            var desks = await rt.SyncDesktopsAsync();
            var list = new Api.DesktopList();
            foreach (var d in desks)
                list.Items.Add(new Api.DesktopInfo
                {
                    DesktopId = d.DesktopId, Name = d.Name, UseStatus = d.UseStatus, UseStatusText = d.UseStatusText,
                    Spec = d.Spec, KeepaliveEnabled = d.KeepaliveEnabled, TaskEnabled = d.TaskEnabled,
                    KeepaliveInterval = d.KeepaliveInterval ?? 0, LastPulseAt = d.LastPulseAt ?? "",
                    ConnectUrl = "https://pc.ctyun.cn/#/desktop?id=" +
                                 Convert.ToBase64String(Encoding.UTF8.GetBytes(d.DesktopId)),
                    RawJson = d.RawJson,
                });
            return (0, (IMessage?)list);
        });
        MapPost<Api.IdReq>(app, "/api/account/{id}/sync", async (ctx, req) =>
        {
            var rt = EngineOf(ctx, req.Id);
            if (rt == null) return (1, null);
            await rt.SyncDesktopsAsync();
            await rt.RefreshOfficialTasksAsync();
            return (0, (IMessage?)new Api.BoolReply { Ok = true });
        });
        MapPost<Api.PowerReq>(app, "/api/account/{id}/power", async (ctx, req) =>
        {
            var rt = EngineOf(ctx, req.Id);
            if (rt == null) return (1, null);
            var err = await rt.PowerAsync(req.DesktopId, req.Action);
            return (err == "" ? 0 : 1, (IMessage?)new Api.BoolReply { Ok = err == "", Detail = err });
        });
        MapPost<Api.PrefsReq>(app, "/api/account/{id}/prefs", (ctx, req) =>
        {
            var rt = EngineOf(ctx, req.Id);
            if (rt == null) return Task.FromResult<(int, IMessage?)>(new(1, null));
            var d = Svc.Db.DesktopsOf(req.Id).FirstOrDefault(x => x.DesktopId == req.DesktopId);
            if (d == null) return Task.FromResult<(int, IMessage?)>(new(1, new Api.BoolReply { Detail = "桌面不存在" }));
            d.KeepaliveEnabled = req.KeepaliveEnabled;
            d.TaskEnabled = req.TaskEnabled;
            d.KeepaliveInterval = req.KeepaliveInterval > 0 ? Math.Clamp(req.KeepaliveInterval, 10, 604800) : null;
            Svc.Db.UpdateDesktop(d);
            return Task.FromResult<(int, IMessage?)>(new(0, new Api.BoolReply { Ok = true }));
        });
        MapPost<Api.PrefsBatchReq>(app, "/api/account/{id}/prefs/batch", (ctx, req) =>
        {
            var rt = EngineOf(ctx, req.Id);
            if (rt == null) return Task.FromResult<(int, IMessage?)>(new(1, null));
            var desks = Svc.Db.DesktopsOf(req.Id);
            var targets = req.DesktopIds.Count > 0
                ? desks.Where(d => req.DesktopIds.Contains(d.DesktopId)).ToList()
                : desks;
            var interval = Math.Clamp(req.KeepaliveInterval, 10, 604800);
            var updated = 0;
            foreach (var d in targets)
            {
                if (req.SetKeepalive) d.KeepaliveEnabled = req.KeepaliveEnabled;
                if (req.SetTask) d.TaskEnabled = req.TaskEnabled;
                if (req.SetInterval) d.KeepaliveInterval = req.KeepaliveInterval > 0 ? interval : null;
                Svc.Db.UpdateDesktop(d);
                updated++;
            }
            Svc.Logs.Write("info", "Batch", rt.Name, $"批量配置已下发：{updated} 台" +
                (req.SetInterval ? $" · 间隔={interval}s" : "") +
                (req.SetKeepalive ? $" · 保活={(req.KeepaliveEnabled ? "开" : "关")}" : "") +
                (req.SetTask ? $" · 任务={(req.TaskEnabled ? "开" : "关")}" : ""));
            return Task.FromResult<(int, IMessage?)>(new(0, new Api.BoolReply { Ok = true, Detail = updated.ToString() }));
        });
        MapPost<Api.RunTaskReq>(app, "/api/account/{id}/task/run", async (ctx, req) =>
        {
            var rt = EngineOf(ctx, req.Id);
            if (rt == null) return (1, null);
            var result = await Svc.Scheduler.ExecuteAsync(rt, req.Task, "手动触发");
            return (0, (IMessage?)new Api.BoolReply { Ok = result.Contains("完成") || result.Contains("达成") || result == "", Detail = result });
        });
        MapGet(app, "/api/account/{id}/points", ctx =>
        {
            var rt = EngineOf(ctx);
            if (rt == null) return Task.FromResult<(int, IMessage?)>(new(1, null));
            var reply = new Api.PointsReply { Points = rt.Row.Points };
            foreach (var t in rt.TasksSnapshot)
                reply.Tasks.Add(new Api.TaskProgress { Name = t.Item1, Current = t.Item2, Total = t.Item3, Status = t.Item4, Points = t.Item5 });
            return Task.FromResult<(int, IMessage?)>(new(0, reply));
        });
        MapGet(app, "/api/rewards", async ctx =>
        {
            var rt = EngineOf(ctx);
            if (rt == null) return (1, null);
            var raw = await rt.GetRewardsAsync();
            return (0, (IMessage?)ParseRewards(raw));
        });
        MapPost<Api.RedeemReq>(app, "/api/redeem", async (ctx, req) =>
        {
            var rt = EngineOf(ctx, req.AccId);
            if (rt == null) return (1, null);
            var err = await rt.RedeemAsync(req.ProdId, req.ProdName, req.CostPoints, Math.Max(1, req.Times), req.DesktopId);
            return (err == "" ? 0 : 1, (IMessage?)new Api.BoolReply { Ok = err == "", Detail = err });
        });

        // ---- 设置 ----
        MapGet(app, "/api/settings", ctx =>
        {
            if (CurrentUser(ctx)?.Role != "admin") return Task.FromResult<(int, IMessage?)>(new(1, null));
            return Task.FromResult<(int, IMessage?)>(new(0, ToSettingsMsg(Svc.Db.GetSettings())));
        });
        MapPost<Api.SettingsMsg>(app, "/api/settings", (ctx, req) =>
        {
            if (CurrentUser(ctx)?.Role != "admin") return Task.FromResult<(int, IMessage?)>(new(1, null));
            var s = new AppSettings
            {
                PulseIntervalSeconds = req.PulseIntervalSeconds, KeepAliveSeconds = req.KeepAliveSeconds,
                ExecuteTime = [.. req.ExecuteTime], SignCron = req.SignCron, AiCron = req.AiCron,
                HangCron = req.HangCron, RedeemCron = req.RedeemCron,
                RedeemMode = req.RedeemMode, RedeemModeDay = req.RedeemModeDay, RedeemModeStepDays = req.RedeemModeStepDays,
                NotifyOnErrorOnly = req.NotifyOnErrorOnly, Title = req.Title, Subtitle = req.Subtitle,
            HookUrl = req.HookUrl,
            };
            foreach (var c in req.NotifyChannels)
                s.NotifyChannels.Add(new NotifyChannel { Type = c.Type, Url = c.Url, Secret = c.Secret, AccScope = c.AccScope });
            Svc.Db.SaveSettings(s);
            Svc.Engine.NotifySettingsChanged();
            return Task.FromResult<(int, IMessage?)>(new(0, new Api.BoolReply { Ok = true }));
        });

        // ---- 日志 ----
        MapPost<Api.LogQuery>(app, "/api/logs/recent", (ctx, req) =>
        {
            var list = new Api.LogList();
            foreach (var l in Svc.Logs.RecentFromDb(Math.Clamp(req.Limit, 1, 1000), req.Level, req.Scope, req.Account))
                list.Items.Add(new Api.LogItem { Ts = l.Ts, Level = l.Level, Scope = l.Scope, Account = l.Account, Msg = l.Msg });
            return Task.FromResult<(int, IMessage?)>(new(0, list));
        });
        app.MapGet("/api/logs/stream", async ctx =>
        {
            if (CurrentUser(ctx) == null) { ctx.Response.StatusCode = 401; return; }
            var sub = Svc.Logs.Subscribe(
                ctx.Request.Query["level"].ToString(),
                ctx.Request.Query["scope"].ToString(),
                ctx.Request.Query["account"].ToString());
            try { await sub.PumpAsync(ctx, ctx.RequestAborted); }
            finally { Svc.Logs.Unsubscribe(sub); }
        });

        // ---- 系统 ----
        MapGet(app, "/api/system/info", ctx =>
        {
            var up = DateTime.Now - Svc.StartedAt;
            return Task.FromResult<(int, IMessage?)>(new(0, new Api.SystemInfo
            {
                Version = "2.3.1-dotnet-aot", StartedAt = Svc.StartedAt.ToString("yyyy-MM-dd HH:mm:ss"),
                UptimeSec = (long)up.TotalSeconds, Runtime = "nativeaot", AccountCount = Svc.Engine.Count,
            }));
        });

        // ---- 移动云（ydpc-soho / ydpc-ecloud）：账号体系与保活（驱动 Ydpc/ + Ecloud/） ----
        MapGet(app, "/api/ydpc/accounts", ctx =>
        {
            var me = CurrentUser(ctx)!;
            var list = new Api.AccountList();
            foreach (var row in Svc.Db.Accounts().Where(a => a.Platform.StartsWith("ydpc")))
            {
                if (me.Role != "admin" && row.Owner != me.Username) continue;
                var rt = Svc.Engine.GetYdpc(row.Id);
                var card = new Api.AccountCard
                {
                    Id = row.Id, Platform = row.Platform, Name = row.Name, UserMasked = MaskUser(row.User),
                    Owner = row.Owner, KeepaliveEnabled = row.KeepaliveEnabled, PulseInterval = row.PulseIntervalSeconds,
                    Online = string.IsNullOrEmpty(row.LastError) && (row.LastLoginAt != null || Svc.Engine.GetYdpc(row.Id) != null),
                    StatusText = rt is { NeedsInteractive: true } ? "需要短信验证（请在面板完成登录）"
                        : row.LastError ?? (row.LastLoginAt != null ? "运行中" : "未登录"),
                    LastError = row.LastError ?? "",
                };
                foreach (var d in Svc.Db.DesktopsOf(row.Id))
                {
                    card.Desktops.Add(new Api.DesktopInfo
                    {
                        DesktopId = d.DesktopId, Name = d.Name, UseStatus = d.UseStatus,
                        UseStatusText = d.UseStatusText, Spec = d.Spec,
                        KeepaliveEnabled = d.KeepaliveEnabled, TaskEnabled = d.TaskEnabled,
                        KeepaliveInterval = d.KeepaliveInterval ?? row.PulseIntervalSeconds,
                        LastPulseAt = d.LastPulseAt ?? "", RawJson = d.RawJson, ConnectUrl = "",
                    });
                }
                if (rt != null)
                    card.NextPulseInSec = Math.Max(0, (long)(rt.NextRunAt - DateTime.Now).TotalSeconds);
                list.Items.Add(card);
            }
            return Task.FromResult<(int, IMessage?)>(new(0, list));
        });

        // 添加账号：platform=ydpc-soho → SohoClient 登录（图形验证码回显 code=2）；
        //           platform=ydpc-ecloud → Ecloud 密码登录（NEED_* 分支 code=2 + need_sms）
        MapGet(app, "/api/account/{id}/relogin/captcha", async ctx =>
        {
            var rt = EngineOf(ctx);
            if (rt == null) return (1, null);
            var (img, key) = await rt.BeginCaptchaReloginAsync();
            return (0, (IMessage?)new Api.CaptchaImage { Image = "data:image/jpeg;base64," + Convert.ToBase64String(img), Key = key });
        });
        MapPost<Api.CaptchaVerifyReq>(app, "/api/account/{id}/relogin/captcha/verify", async (ctx, req) =>
        {
            var rt = EngineOf(ctx, req.Id);
            if (rt == null) return (1, null);
            var ok = await rt.ReloginWithCaptchaAsync(req.CaptchaCode);
            Svc.Engine.ReloadAll();
            return (ok ? 0 : 1, (IMessage?)new Api.BoolReply
            {
                Ok = ok,
                Detail = ok ? "验证码重新验证成功，登录态已刷新" : "验证码错误或已过期，请重试",
            });
        });

        // ---- 短信验证设备（30060/30090 风控正解：图码→短信码→绑定设备）----
        MapGet(app, "/api/account/{id}/sms/captcha", async ctx =>
        {
            var rt = EngineOf(ctx);
            if (rt == null) return (1, null);
            var img = await rt.BeginSmsVerificationAsync();
            return (0, (IMessage?)new Api.CaptchaImage { Image = "data:image/jpeg;base64," + Convert.ToBase64String(img), Key = "" });
        });
        MapPost<Api.CaptchaVerifyReq>(app, "/api/account/{id}/sms/send", async (ctx, req) =>
        {
            var rt = EngineOf(ctx, req.Id);
            if (rt == null) return (1, null);
            var (ok, msg) = await rt.SendSmsCodeAsync(req.CaptchaCode);
            return (ok ? 0 : 1, (IMessage?)new Api.BoolReply { Ok = ok, Detail = msg });
        });
        MapPost<Api.CaptchaVerifyReq>(app, "/api/account/{id}/sms/verify", async (ctx, req) =>
        {
            var rt = EngineOf(ctx, req.Id);
            if (rt == null) return (1, null);
            var (ok, msg) = await rt.VerifySmsBindAsync(req.CaptchaCode);
            return (ok ? 0 : 1, (IMessage?)new Api.BoolReply { Ok = ok, Detail = msg });
        });

        MapPost<Api.AddAccountReq>(app, "/api/ydpc/account/add", async (ctx, req) =>
        {
            var me = CurrentUser(ctx)!;
            if (req.Platform.Contains("ecloud", StringComparison.OrdinalIgnoreCase))
            {
                if (req.User == "" || req.Password == "")
                    return (1, (IMessage?)new Api.BoolReply { Detail = "需要账号与密码" });
                var (locked, lockErr, _) = EcloudLoginRateLimiter.Guard(req.User);
                if (locked)
                    return (1, (IMessage?)new Api.BoolReply { Ok = false, Detail = lockErr });

                var deviceUid = Guid.NewGuid().ToString();
                var http = new EcloudHttpUtil(EcloudDevice.BuildCommonParams(deviceUid, Environment.MachineName));
                var r = await EcloudLogin.LoginWithPasswordAsync(http, req.User, req.Password, ctx.RequestAborted);
                if (r.Status == EcloudLoginStatus.Success)
                {
                    var row = new SmAccount
                    {
                        Id = Db.NewId(), Platform = "ydpc-ecloud", Owner = me.Username,
                        Name = req.Name != "" ? req.Name : req.User, User = req.User,
                        EncPassword = Svc.Db.Protect(req.Password),
                        EncSession = Svc.Db.Protect(EcloudSessionJson(req.User, deviceUid, r.Mobile, r.AccessToken, Guid.NewGuid().ToString())),
                        LastLoginAt = Db.Now(), AddedAt = Db.Now(), PulseIntervalSeconds = 300,
                    };
                    Svc.Db.InsertAccount(row);
                    Svc.Engine.ReloadAll();
                    Svc.Logs.Write("success", "Ydpc", row.Name, "✅ 移动公众账号登录成功，已接入保活调度");
                    _ = Task.Run(async () => { try { await Svc.Engine.GetYdpc(row.Id)!.SyncDesktopsAsync(); } catch { } });
                    // 成功统一 BoolReply（ok=true, detail=accId），与天翼 add 契约一致
                    return (0, (IMessage?)new Api.BoolReply { Ok = true, Detail = row.Id });
                }
                if (EcloudLoginStatus.IsInteractive(r.Status))
                {
                    // 短信类分支：暂存本次 http（会话态在内存），待 sms 端点续完
                    var pendingId = "pending:" + Db.NewId();
                    EcloudPendingLogins.Put(pendingId, new EcloudPendingLogin
                    {
                        Http = http, Username = req.User, Password = req.Password, DeviceUid = deviceUid,
                        Mobile = r.Mobile, LoginCode = r.LoginCode, Branch = r.Status,
                    });
                    Svc.Logs.Write("warning", "Ydpc", req.User, $"登录分支: {r.Status}，等待短信验证");
                    return (2, (IMessage?)new Api.YdpcLoginBranch
                    {
                        Status = r.Status, AccId = pendingId, Mobile = r.Mobile,
                        LoginCode = r.LoginCode ?? "", NeedSms = true, ErrorCode = r.ErrorCode,
                    });
                }
                // 失败统一 BoolReply（ok=false, detail=人话错误），前端直接展示 detail
                return (1, (IMessage?)new Api.BoolReply { Ok = false, Detail = r.Error });
            }

            // ---- ydpc-soho ----
            string password = req.Password;
            string? verificationCode = req.CaptchaCode != "" ? req.CaptchaCode : null;
            string? randomCode = null;
            if (verificationCode != null && YdpcSohoCaptcha.TryGetValue(req.User, out var pendingCaptcha))
            {
                password = pendingCaptcha.Password;
                randomCode = pendingCaptcha.RandomCode;
            }
            if (req.User == "" || password == "")
                return (1, (IMessage?)new Api.BoolReply { Detail = "需要账号与密码" });

            var soho = new SohoClient((level, msg) => Svc.Logs.Write(level, "Ydpc", req.User, msg));
            try
            {
                await soho.LoginAsync(req.User, password, "main", verificationCode ?? "", randomCode ?? "", ctx.RequestAborted);
                var row = new SmAccount
                {
                    Id = Db.NewId(), Platform = "ydpc-soho", Owner = me.Username,
                    Name = req.Name != "" ? req.Name : req.User, User = req.User,
                    EncPassword = Svc.Db.Protect(password),
                    LastLoginAt = Db.Now(), AddedAt = Db.Now(), PulseIntervalSeconds = 600,
                    Protocol = NormalizeYdpcProtocol(req.Protocol),
                };
                Svc.Db.InsertAccount(row);
                Svc.Engine.ReloadAll();
                YdpcSohoCaptcha.TryRemove(req.User, out _);
                Svc.Logs.Write("success", "Ydpc", row.Name, "✅ 移动爱家账号登录成功，已接入保活调度");
                _ = Task.Run(async () => { try { await Svc.Engine.GetYdpc(row.Id)!.SyncDesktopsAsync(); } catch { } });
                return (0, (IMessage?)new Api.BoolReply { Ok = true, Detail = row.Id });
            }
            catch (Exception e)
            {
                var msg = e.Message;
                if (msg.Contains("验证码", StringComparison.Ordinal))
                {
                    var (img, random) = await soho.GetVerificationCodeAsync(ctx.RequestAborted);
                    YdpcSohoCaptcha[req.User] = (password, random);
                    Svc.Logs.Write("warning", "Ydpc", req.User, "登录需要图形验证码，已回显");
                    return (2, (IMessage?)new Api.NeedCaptcha { Need = true, Image = img, Key = req.User });
                }
                Svc.Logs.Write("error", "Ydpc", req.User, "❌ 登录失败: " + msg);
                return (1, (IMessage?)new Api.BoolReply { Ok = false, Detail = msg });
            }
            finally { soho.Dispose(); }
        });

        // 短信发码（ecloud need_* 分支后必须调用，否则手机收不到码）
        MapPost<Api.YdpcSmsReq>(app, "/api/ydpc/account/sms/send", async (ctx, req) =>
        {
            if (req.AccId.StartsWith("pending:", StringComparison.Ordinal))
            {
                if (!EcloudPendingLogins.TryGet(req.AccId, out var p) || p == null)
                    return (1, (IMessage?)new Api.YdpcLoginBranch { Status = "failed", Error = "待验证会话不存在或已过期，请重新提交账号密码" });
                if (p.Branch != req.Branch)
                    return (1, (IMessage?)new Api.YdpcLoginBranch { Status = "failed", Error = $"分支不匹配（应为 {p.Branch}）" });
                var mobile = req.Mobile != "" ? req.Mobile : p.Mobile;
                if (mobile == "")
                    return (1, (IMessage?)new Api.YdpcLoginBranch { Status = "failed", Error = "发送短信需要 mobile（密码登录未返回手机号）" });
                await EcloudLogin.SendSmsForBranchAsync(p.Http, req.Branch, mobile, p.Username, ctx.RequestAborted);
                p.Mobile = mobile;
                Svc.Logs.Write("success", "Ydpc", p.Username, $"📲 验证码已下发至 {MaskMobile(mobile)} (branch={req.Branch})");
                return (0, (IMessage?)new Api.YdpcLoginBranch { Status = req.Branch, AccId = req.AccId, Mobile = mobile });
            }
            var rt = YdpcOf(ctx, req.AccId);
            if (rt == null) return (1, null);
            await rt.SendEcloudSmsAsync(req.Branch, req.Mobile, ctx.RequestAborted);
            return (0, (IMessage?)new Api.YdpcLoginBranch { Status = req.Branch, AccId = req.AccId });
        });

        // 短信验证完成（pending → 落库成账号；已有账号 → 恢复会话）
        MapPost<Api.YdpcSmsReq>(app, "/api/ydpc/account/sms/verify", async (ctx, req) =>
        {
            var me = CurrentUser(ctx)!;
            if (req.AccId.StartsWith("pending:", StringComparison.Ordinal))
            {
                if (!EcloudPendingLogins.TryGet(req.AccId, out var p) || p == null)
                    return (1, (IMessage?)new Api.YdpcLoginBranch { Status = "failed", Error = "待验证会话不存在或已过期，请重新提交账号密码" });
                var r = await EcloudLogin.CompleteSmsBranchAsync(p.Http, req.Branch, p.Mobile, p.Username, p.Password,
                    req.Code, p.LoginCode, req.IsTemporary, ctx.RequestAborted);
                if (r.Status != EcloudLoginStatus.Success)
                    return (1, (IMessage?)new Api.YdpcLoginBranch { Status = r.Status, Error = r.Error, Mobile = r.Mobile });
                var row = new SmAccount
                {
                    Id = Db.NewId(), Platform = "ydpc-ecloud", Owner = me.Username,
                    Name = p.Username, User = p.Username,
                    EncPassword = Svc.Db.Protect(p.Password),
                    EncSession = Svc.Db.Protect(EcloudSessionJson(p.Username, p.DeviceUid, p.Mobile != "" ? p.Mobile : r.Mobile, r.AccessToken, Guid.NewGuid().ToString())),
                    LastLoginAt = Db.Now(), AddedAt = Db.Now(), PulseIntervalSeconds = 300,
                };
                Svc.Db.InsertAccount(row);
                Svc.Engine.ReloadAll();
                EcloudPendingLogins.Remove(req.AccId);
                Svc.Logs.Write("success", "Ydpc", row.Name, "✅ 短信验证通过，移动公众账号已接入保活调度");
                return (0, (IMessage?)new Api.YdpcLoginBranch { Status = "success", AccId = row.Id });
            }
            var rt = YdpcOf(ctx, req.AccId);
            if (rt == null) return (1, null);
            var done = await rt.CompleteEcloudSmsAsync(req.Branch, req.Code, req.IsTemporary, ctx.RequestAborted);
            return done.Status == EcloudLoginStatus.Success
                ? (0, (IMessage?)new Api.YdpcLoginBranch { Status = "success", AccId = req.AccId })
                : (1, (IMessage?)new Api.YdpcLoginBranch { Status = done.Status, Error = done.Error });
        });

        MapPost<Api.IdReq>(app, "/api/ydpc/account/{id}/relogin", async (ctx, req) =>
        {
            var rt = YdpcOf(ctx, req.Id);
            if (rt == null) return (1, null);
            var ok = await rt.ReloginAsync(ctx.RequestAborted);
            return (ok ? 0 : 1, (IMessage?)new Api.BoolReply
            {
                Ok = ok,
                Detail = ok ? "" : "重登未成功（冷却期/需要短信验证/凭据缺失时会失败，详见日志）",
            });
        });

        MapPost<Api.IdReq>(app, "/api/ydpc/account/{id}/sync", async (ctx, req) =>
        {
            var rt = YdpcOf(ctx, req.Id);
            if (rt == null) return (1, null);
            var msg = await rt.SyncDesktopsAsync(ctx.RequestAborted);
            return (0, (IMessage?)new Api.BoolReply { Ok = true, Detail = msg });
        });

        MapGet(app, "/api/ydpc/account/{id}/desktops", async ctx =>
        {
            var rt = YdpcOf(ctx);
            if (rt == null) return (1, null);
            await rt.SyncDesktopsAsync(ctx.RequestAborted);
            var list = new Api.DesktopList();
            foreach (var d in Svc.Db.DesktopsOf(rt.Row.Id))
            {
                list.Items.Add(new Api.DesktopInfo
                {
                    DesktopId = d.DesktopId, Name = d.Name, UseStatus = d.UseStatus,
                    UseStatusText = d.UseStatusText, Spec = d.Spec,
                    KeepaliveEnabled = d.KeepaliveEnabled, TaskEnabled = d.TaskEnabled,
                    KeepaliveInterval = d.KeepaliveInterval ?? rt.Row.PulseIntervalSeconds,
                    LastPulseAt = d.LastPulseAt ?? "", RawJson = d.RawJson, ConnectUrl = "",
                });
            }
            return (0, (IMessage?)list);
        });

        MapPost<Api.PowerReq>(app, "/api/ydpc/account/{id}/power", async (ctx, req) =>
        {
            var rt = YdpcOf(ctx, req.Id);
            if (rt == null) return (1, null);
            var (ok, message) = await rt.PowerAsync(req.DesktopId, req.Action, ctx.RequestAborted);
            return (ok ? 0 : 1, (IMessage?)new Api.BoolReply { Ok = ok, Detail = message });
        });

        MapPost<Api.PrefsReq>(app, "/api/ydpc/account/{id}/prefs", (ctx, req) =>
        {
            var rt = YdpcOf(ctx, req.Id);
            if (rt == null) return Task.FromResult<(int, IMessage?)>(new(1, null));
            var d = Svc.Db.DesktopsOf(req.Id).FirstOrDefault(x => x.DesktopId == req.DesktopId);
            if (d == null) return Task.FromResult<(int, IMessage?)>(new(1, (IMessage?)new Api.BoolReply { Detail = "桌面不存在" }));
            d.KeepaliveEnabled = req.KeepaliveEnabled;
            d.TaskEnabled = req.TaskEnabled;
            d.KeepaliveInterval = req.KeepaliveInterval > 0 ? Math.Clamp(req.KeepaliveInterval, 60, 604800) : null;
            Svc.Db.UpdateDesktop(d);
            return Task.FromResult<(int, IMessage?)>(new(0, (IMessage?)new Api.BoolReply { Ok = true }));
        });

        MapPost<Api.PrefsBatchReq>(app, "/api/ydpc/account/{id}/prefs/batch", (ctx, req) =>
        {
            var rt = YdpcOf(ctx, req.Id);
            if (rt == null) return Task.FromResult<(int, IMessage?)>(new(1, null));
            var desks = Svc.Db.DesktopsOf(req.Id);
            var targets = req.DesktopIds.Count > 0
                ? desks.Where(d => req.DesktopIds.Contains(d.DesktopId)).ToList()
                : desks;
            var updated = 0;
            foreach (var d in targets)
            {
                if (req.SetKeepalive) d.KeepaliveEnabled = req.KeepaliveEnabled;
                if (req.SetTask) d.TaskEnabled = req.TaskEnabled;
                if (req.SetInterval) d.KeepaliveInterval = req.KeepaliveInterval > 0 ? Math.Clamp(req.KeepaliveInterval, 60, 604800) : null;
                Svc.Db.UpdateDesktop(d);
                updated++;
            }
            Svc.Logs.Write("info", "Ydpc", rt.Row.Name, $"批量配置已下发：{updated} 台" +
                (req.SetInterval ? $" · 间隔={Math.Clamp(req.KeepaliveInterval, 60, 604800)}s" : "") +
                (req.SetKeepalive ? $" · 保活={(req.KeepaliveEnabled ? "开" : "关")}" : "") +
                (req.SetTask ? $" · 任务={(req.TaskEnabled ? "开" : "关")}" : ""));
            return Task.FromResult<(int, IMessage?)>(new(0, (IMessage?)new Api.BoolReply { Ok = true, Detail = updated.ToString() }));
        });

        MapPost<Api.UpdateAccountReq>(app, "/api/ydpc/account/{id}/update", (ctx, req) =>
        {
            var row = Svc.Db.AccountById(req.Id);
            if (row == null || !YdpcCanAccess(ctx, row)) return Task.FromResult<(int, IMessage?)>(new(1, null));
            if (req.Name != "") row.Name = req.Name;
            row.KeepaliveEnabled = req.KeepaliveEnabled;
            if (req.PulseInterval > 0) row.PulseIntervalSeconds = Math.Clamp(req.PulseInterval, 60, 604800);
            if (req.Protocol != "") row.Protocol = NormalizeYdpcProtocol(req.Protocol);
            Svc.Db.UpdateAccount(row);
            Svc.Engine.EnsureYdpc(row);
            return Task.FromResult<(int, IMessage?)>(new(0, (IMessage?)new Api.BoolReply { Ok = true }));
        });

        // 桌面登出（logout.py desktop_logout）：桌面被占用时释放会话锁
        MapPost<Api.YdpcLogoutReq>(app, "/api/ydpc/account/{id}/logout", async (ctx, req) =>
        {
            var rt = YdpcOf(ctx, req.Id);
            if (rt == null) return (1, null);
            var res = await rt.LogoutDesktopAsync(req.UserServiceId, ctx.RequestAborted);
            string detail = "桌面会话锁已请求释放";
            if (res.ValueKind == JsonValueKind.Object)
            {
                if (res.TryGetProperty("code", out var c))
                    detail += $" (code={(c.ValueKind == JsonValueKind.Number ? c.GetRawText() : c.GetString() ?? "?")})";
                string? msg = res.TryGetProperty("msg", out var m) && m.ValueKind == JsonValueKind.String ? m.GetString() : null;
                if (msg != null) detail += " " + msg;
            }
            Svc.Logs.Write("info", "Ydpc", rt.Row.Name, $"桌面登出已下发: {detail}");
            return (0, (IMessage?)new Api.BoolReply { Ok = true, Detail = detail });
        });

        // 账号登出（logout.py account_logout）：/login/logout/v1 + 清本地会话
        MapPost<Api.IdReq>(app, "/api/ydpc/account/{id}/account-logout", async (ctx, req) =>
        {
            var rt = YdpcOf(ctx, req.Id);
            if (rt == null) return (1, null);
            await rt.AccountLogoutAsync(ctx.RequestAborted);
            Svc.Logs.Write("info", "Ydpc", rt.Row.Name, "账号已登出（sohoToken 已清除，下轮自动重登）");
            return (0, (IMessage?)new Api.BoolReply { Ok = true, Detail = "账号已登出" });
        });

        MapPost<Api.IdReq>(app, "/api/ydpc/account/{id}/open", (ctx, req) =>
        {
            var row = Svc.Db.AccountById(req.Id);
            if (row == null || !CanAccess(ctx, row)) return Task.FromResult<(int, IMessage?)>(new(1, null));
            // 移动云无 pc.ctyun.cn 式网页端可注入，免密直通暂不支持 —— 明确告知而非 500
            return Task.FromResult<(int, IMessage?)>(new(1, new Api.BoolReply
            {
                Ok = false,
                Detail = "移动云暂不支持网页免密直通：请使用「移动云电脑/和家亲」官方 App 进入桌面；如已安装官方客户端可直接打开",
            }));
        });

        MapPost<Api.IdReq>(app, "/api/ydpc/account/{id}/delete", (ctx, req) =>
        {
            var row = Svc.Db.AccountById(req.Id);
            if (row == null || !YdpcCanAccess(ctx, row)) return Task.FromResult<(int, IMessage?)>(new(1, null));
            Svc.Engine.RemoveYdpc(req.Id);
            Svc.Db.DeleteAccount(req.Id);
            return Task.FromResult<(int, IMessage?)>(new(0, (IMessage?)new Api.BoolReply { Ok = true }));
        });

        // ---- Web 远程桌面免密直通（DesktopView）：open 接口返回 JSON 供前端直接消费 ----
        // POST /api/account/{id}/open?desktopId=...（body=IdReq protobuf，desktopId 走 query）
        // 返回 { authData, authExpiredAt, targetUrl, directViewUrl, desktopUrl, desktopName, ... }
        app.MapPost("/api/account/{id}/open", async ctx =>
        {
            string? token = ctx.Request.Cookies["sid"];
            if (ctx.Request.Headers.TryGetValue("Authorization", out var authz) && authz.ToString().StartsWith("Bearer "))
                token = authz.ToString()[7..];
            if (CurrentUser(ctx) == null)
            {
                ctx.Response.StatusCode = 401;
                ctx.Response.ContentType = "application/json; charset=utf-8";
                await ctx.Response.WriteAsync("{\"error\":\"未授权：请登录后再操作\"}", ctx.RequestAborted);
                return;
            }
            var accId = ctx.Request.RouteValues["id"]?.ToString() ?? "";
            if (accId == "" && ctx.Request.ContentLength is > 0)
            {
                using var ms = new MemoryStream();
                await ctx.Request.Body.CopyToAsync(ms, ctx.RequestAborted);
                if (ms.Length > 0) accId = Api.IdReq.Parser.ParseFrom(ms.ToArray()).Id;
            }
            var row = accId != "" ? Svc.Db.AccountById(accId) : null;
            if (row == null)
            {
                ctx.Response.StatusCode = 404;
                ctx.Response.ContentType = "application/json; charset=utf-8";
                await ctx.Response.WriteAsync("{\"error\":\"账号不存在\"}", ctx.RequestAborted);
                return;
            }
            if (!CanAccess(ctx, row))
            {
                ctx.Response.StatusCode = 403;
                ctx.Response.ContentType = "application/json; charset=utf-8";
                await ctx.Response.WriteAsync("{\"error\":\"权限不足：无权访问该账号\"}", ctx.RequestAborted);
                return;
            }
            var desktopId = ctx.Request.Query["desktopId"].ToString();
            var (payload, err, status) = await DesktopViewPage.BuildOpenPayloadAsync(row, desktopId, token ?? "", ctx.RequestAborted);
            if (payload == null)
            {
                ctx.Response.StatusCode = status == 0 ? 500 : status;
                ctx.Response.ContentType = "application/json; charset=utf-8";
                await ctx.Response.WriteAsync("{\"error\":" + JsonEncodedText.Encode(err) + "}", ctx.RequestAborted);
                return;
            }
            ctx.Response.ContentType = "application/json; charset=utf-8";
            await ctx.Response.WriteAsync(JsonSerializer.Serialize(payload, AppJson.Default.JsonObject), ctx.RequestAborted);
        });

        // ---- 免密直通引导页 + pc.ctyun.cn 同源反代（必须最后注册：仅接管其余路径） ----
        DesktopViewPage.Map(app);
        PcProxy.Map(app);
    }

    // ---------- 辅助 ----------
    private static (int, IMessage?) UserReply(HttpContext ctx)
    {
        var u = CurrentUser(ctx);
        return u == null
            ? (1, null)
            : (0, (IMessage?)new Api.UserReply { Id = u.Id, Username = u.Username, Role = u.Role });
    }

    private static AccountRuntime? EngineOf(HttpContext ctx, string? id = null)
    {
        var key = id ?? ctx.Request.RouteValues["id"]?.ToString();
        var rt = key != null ? Svc.Engine.Get(key) : null;
        return rt != null && CanAccess(ctx, rt.Row) ? rt : null;
    }

    private static bool CanAccess(HttpContext ctx, SmAccount row) =>
        CurrentUser(ctx) is { } u && (u.Role == "admin" || row.Owner == u.Username);

    private static SmUser? CurrentUser(HttpContext ctx)
    {
        string? token = ctx.Request.Cookies["sid"];
        if (ctx.Request.Headers.TryGetValue("Authorization", out var auth) && auth.ToString().StartsWith("Bearer "))
            token = auth.ToString()[7..];
        if (token == null) return null;
        var s = Svc.Db.FindSession(token);
        if (s == null || string.Compare(s.ExpiresAt, Db.Now()) < 0) return null;
        return Svc.Db.UserById(s.UserId);
    }

    private static string MaskUser(string user)
    {
        if (user.Length <= 4) return user;
        if (user.Contains('@')) return user[..3] + "****" + user[user.IndexOf('@')..];
        return user.Length == 11 ? user[..3] + "****" + user[7..] : user[..3] + "****";
    }

    // ---------- 移动云 ydpc 辅助 ----------
    /// <summary>soho 图形验证码待重试表：user → (password, randomCode)。randomCode 与回显图片绑定。</summary>
    internal static readonly ConcurrentDictionary<string, (string Password, string RandomCode)> YdpcSohoCaptcha = new();

    private static bool YdpcCanAccess(HttpContext ctx, SmAccount row) => CanAccess(ctx, row);

    /// <summary>ydpc 运行时解析 + 权限检查（对齐 EngineOf）。</summary>
    private static YdpcAccountRuntime? YdpcOf(HttpContext ctx, string? id = null)
    {
        var key = id ?? ctx.Request.RouteValues["id"]?.ToString();
        if (key == null) return null;
        var rt = Svc.Engine.GetYdpc(key);
        return rt != null && YdpcCanAccess(ctx, rt.Row) ? rt : null;
    }

    /// <summary>ecloud 会话落盘 JSON（对齐 sidecar _persist_sessions：只存非敏感字段，绝不写密码）。</summary>
    private static string EcloudSessionJson(string username, string deviceUid, string mobile, string accessToken, string loginUid)
    {
        var obj = new JsonObject
        {
            ["username"] = username,
            ["deviceUid"] = deviceUid,
            ["mobile"] = mobile,
            ["accessToken"] = accessToken,
            ["loginUid"] = loginUid,
            ["lastTokenRefreshAt"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            ["savedAt"] = Db.Now(),
        };
        return JsonSerializer.Serialize(obj, AppJson.Default.JsonObject);
    }

    private static string MaskMobile(string m)
    {
        var s = (m ?? "").Trim();
        return s.Length >= 7 ? $"{s[..3]}****{s[^4..]}" : "***";
    }

    /// <summary>ydpc-soho 底层协议归一：SCG / ZTE（其余值一律 ZTE，空=ZTE）。</summary>
    private static string NormalizeYdpcProtocol(string? protocol) =>
        protocol != null && protocol.Trim().Equals("SCG", StringComparison.OrdinalIgnoreCase) ? "SCG" : "ZTE";

    private static Api.SettingsMsg ToSettingsMsg(AppSettings s)
    {
        var msg = new Api.SettingsMsg
        {
            PulseIntervalSeconds = s.PulseIntervalSeconds, KeepAliveSeconds = s.KeepAliveSeconds,
            SignCron = s.SignCron, AiCron = s.AiCron, HangCron = s.HangCron, RedeemCron = s.RedeemCron,
            RedeemMode = s.RedeemMode, RedeemModeDay = s.RedeemModeDay, RedeemModeStepDays = s.RedeemModeStepDays,
            NotifyOnErrorOnly = s.NotifyOnErrorOnly, Title = s.Title, Subtitle = s.Subtitle,
            HookUrl = s.HookUrl,
        };
        foreach (var t in s.ExecuteTime) msg.ExecuteTime.Add(t);
        foreach (var c in s.NotifyChannels)
            msg.NotifyChannels.Add(new Api.NotifyChannelMsg { Type = c.Type, Url = c.Url, Secret = c.Secret, AccScope = c.AccScope });
        return msg;
    }

    private static Api.RewardList ParseRewards(ApiResult raw)
    {
        var list = new Api.RewardList();
        if (raw.Data.ValueKind != JsonValueKind.Array) return list;
        foreach (var mall in raw.Data.EnumerateArray())
        {
            if (mall.ValueKind != JsonValueKind.Object || !mall.TryGetProperty("series", out var series)) continue;
            foreach (var sr in series.EnumerateArray())
            {
                if (!sr.TryGetProperty("sku", out var skus)) continue;
                var sdesc = sr.TryGetProperty("description", out var sd) ? sd.GetString() ?? "" : "";
                foreach (var sku in skus.EnumerateArray())
                {
                    list.Items.Add(new Api.RewardItem
                    {
                        ProdId = sku.TryGetProperty("prodId", out var pi) ? pi.ToString() : "",
                        ProdName = sku.TryGetProperty("prodName", out var pn) ? pn.GetString() ?? "" : "",
                        CostPoints = sku.TryGetProperty("costPoints", out var cp) && cp.TryGetInt32(out var cv) ? cv : 0,
                        ProdType = sku.TryGetProperty("prodType", out var pt) ? pt.ToString() : "",
                        Description = StripTags(sku.TryGetProperty("description", out var dd) ? dd.GetString() ?? sdesc : sdesc),
                    });
                }
            }
        }
        return list;
    }

    private static string StripTags(string s)
    {
        var sb = new System.Text.StringBuilder();
        var inTag = false;
        foreach (var ch in s) { if (ch == '<') inTag = true; else if (ch == '>') inTag = false; else if (!inTag) sb.Append(ch); }
        return sb.ToString();
    }

    // ---------- protobuf 基础设施 ----------
    private static void MapGet(WebApplication app, string pattern, Func<HttpContext, Task<(int, IMessage?)>> handler) =>
        app.MapGet(pattern, async ctx =>
        {
            if (RequiresAuth(pattern) && CurrentUser(ctx) == null) { ctx.Response.StatusCode = 401; return; }
            try
            {
                var (code, data) = await handler(ctx);
                await WriteEnvelope(ctx, code, code == 0 ? "ok" : "error", data);
            }
            catch (Exception ex)
            {
                Svc.Logs.Write("error", "Api", "", pattern + ": " + ex.Message);
                await WriteEnvelope(ctx, 1, ex.Message, null);
            }
        });

    private static void MapPost<T>(WebApplication app, string pattern, Func<HttpContext, T, Task<(int, IMessage?)>> handler)
        where T : IMessage<T>, new()
    {
        app.MapPost(pattern, async ctx =>
        {
            if (RequiresAuth(pattern) && CurrentUser(ctx) == null) { ctx.Response.StatusCode = 401; return; }
            try
            {
                using var ms = new MemoryStream();
                await ctx.Request.Body.CopyToAsync(ms, ctx.RequestAborted);
                var inst = new T();
                var req = ms.Length > 0 ? (T)inst.Descriptor.Parser.ParseFrom(ms.ToArray()) : inst;
                var (code, data) = await handler(ctx, req);
                await WriteEnvelope(ctx, code, code == 0 ? "ok" : "error", data);
            }
            catch (Exception ex)
            {
                Svc.Logs.Write("error", "Api", "", pattern + ": " + ex.Message);
                await WriteEnvelope(ctx, 1, ex.Message, null);
            }
        });
    }

    private static bool RequiresAuth(string pattern) =>
        !pattern.StartsWith("/api/auth/login") && !pattern.StartsWith("/api/account/captcha");

    private static async Task WriteEnvelope(HttpContext ctx, int code, string msg, IMessage? data)
    {
        var env = new Api.Envelope { Code = code, Msg = msg };
        if (data != null) env.Data = ByteString.CopyFrom(data.ToByteArray());
        ctx.Response.ContentType = "application/x-protobuf";
        await ctx.Response.Body.WriteAsync(env.ToByteArray(), ctx.RequestAborted);
    }
}
