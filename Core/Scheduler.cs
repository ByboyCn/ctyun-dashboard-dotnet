using System.Text.Json.Nodes;
using CtyunDashboard.CtYun;

namespace CtyunDashboard;

/// <summary>轻量 5 段 Cron（分 时 日 月 周），支持 * , - / 。</summary>
public static class CronLite
{
    public static bool Matches(string cron, DateTime t)
    {
        if (string.IsNullOrWhiteSpace(cron)) return false;
        var parts = cron.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 5) return false;
        return Field(parts[0], t.Minute) && Field(parts[1], t.Hour) && Field(parts[2], t.Day) &&
               Field(parts[3], t.Month) && Field(parts[4], t.Hour == 0 && t.Minute == 0 ? -1 : (int)t.DayOfWeek);
    }

    private static bool Field(string expr, int value)
    {
        if (expr == "*") return true;
        foreach (var term in expr.Split(','))
        {
            var step = 1;
            var range = term;
            var slash = term.IndexOf('/');
            if (slash >= 0)
            {
                range = term[..slash];
                if (!int.TryParse(term[(slash + 1)..], out step) || step <= 0) return false;
            }
            int lo, hi;
            if (range == "*")
            {
                lo = 0; hi = 59;
            }
            else if (range.Contains('-'))
            {
                var seg = range.Split('-');
                if (!int.TryParse(seg[0], out lo) || !int.TryParse(seg[1], out hi)) return false;
            }
            else
            {
                if (!int.TryParse(range, out lo)) return false;
                hi = slash >= 0 ? 59 : lo;
            }
            if (value == lo) return true;                 // 精确命中
            if (value > lo && value <= hi && (value - lo) % step == 0) return true;
        }
        return false;
    }

    /// <summary>每日准点时间点（"01:20" 或 "01:20,12:00"）。</summary>
    public static bool TimePointHit(string times, DateTime now) =>
        times.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
             .Any(s => s == now.ToString("HH:mm"));
}

/// <summary>
/// 调度器：30 秒滴答。全局准点时间点 + 分项 Cron（签到/AI/挂机/兑换）+ 兑换三策略，
/// 分钟级去重 + 打卡落账跨分钟复检。
/// </summary>
public sealed class Scheduler
{
    private readonly Db _db;
    private readonly LogHub _log;
    private Timer? _timer;

    public Scheduler(Db db, LogHub log) { _db = db; _log = log; }

    public void Start() => _timer ??= new Timer(_ => _ = TickAsync(), null, 15_000, 30_000);

    private async Task TickAsync()
    {
        try
        {
            var now = DateTime.Now;
            var minuteKey = now.ToString("yyyy-MM-dd HH:mm");
            var settings = _db.GetSettings();
            foreach (var rt in Svc.Engine.All())
            {
                var acc = rt.Row;
                await RunDueTaskAsync(rt, "sign", acc.AutoSign, settings.SignCron, settings.ExecuteTime, minuteKey, now);
                await RunDueTaskAsync(rt, "ai", acc.AutoAi, settings.AiCron, [], minuteKey, now);
                await RunDueTaskAsync(rt, "hang", acc.AutoHang, settings.HangCron, [], minuteKey, now);

                // 兑换：策略日 + cron/准点触发
                if (acc.AutoRedeem && !string.IsNullOrEmpty(acc.RedeemProdId))
                {
                    var dateDue = acc.RedeemStrategy switch
                    {
                        "daily" => true,
                        "interval" => (now.Date - DateTime.Parse(acc.AddedAt)).TotalDays % Math.Max(1, acc.RedeemStepDays) < 1,
                        _ => now.Day == acc.RedeemDay || now.Day == DateTime.DaysInMonth(now.Year, now.Month) && acc.RedeemDay > DateTime.DaysInMonth(now.Year, now.Month),
                    };
                    if (dateDue)
                        await RunDueTaskAsync(rt, "redeem", true, settings.RedeemCron, settings.ExecuteTime, minuteKey, now);
                }

                // 打卡落账复检：认领已下发但未确认，5 分钟后复检一次
                await RecheckPendingAsync(rt, "sign");
            }
        }
        catch { /* 调度永不致命 */ }
    }

    private async Task RunDueTaskAsync(AccountRuntime rt, string task, bool enabled, string cron, List<string> timePoints, string minuteKey, DateTime now)
    {
        if (!enabled) return;
        var cronDue = cron != "" && CronLite.Matches(cron, now);
        var pointDue = timePoints.Count > 0 && CronLite.TimePointHit(string.Join(',', timePoints), now) && task is "sign" or "redeem";
        if (!cronDue && !pointDue) return;
        var key = $"{rt.Id}:{task}:{minuteKey}";
        if (_db.GetRunState(key) != null) return;
        _db.SetRunState(key, "1");
        await ExecuteAsync(rt, task, $"定时触发({(cronDue ? "cron" : "准点")})");
    }

    private async Task RecheckPendingAsync(AccountRuntime rt, string task)
    {
        var flag = _db.GetRunState($"pending:{rt.Id}:{task}");
        if (flag == null) return;
        if (!DateTime.TryParse(flag, out var since)) { _db.SetRunState($"pending:{rt.Id}:{task}", ""); return; }
        if ((DateTime.Now - since).TotalMinutes < 5) return;
        _db.SetRunState($"pending:{rt.Id}:{task}", "");
        if (task == "sign" && !rt.IsTaskDoneToday("sign"))
        {
            _log.Write("info", "Task", rt.Name, "打卡落账复检中...");
            await rt.RefreshOfficialTasksAsync();
            if (rt.IsTaskDoneToday("sign")) _log.Write("success", "Task", rt.Name, "复检确认：今日打卡已达成 (+100积分)");
        }
    }

    /// <summary>立即执行一次任务（API 手动触发 / 调度共用）。</summary>
    public async Task<string> ExecuteAsync(AccountRuntime rt, string task, string source)
    {
        _log.Write("info", "Task", rt.Name, $"[{task}] 开始执行 ({source})");
        var result = task switch
        {
            "sign" => await rt.SignTaskAsync(),
            "ai" => await rt.AiChatTaskAsync(),
            "hang" => await rt.HangTaskAsync(),
            "redeem" => await rt.RedeemAsync(rt.Row.RedeemProdId, rt.Row.RedeemProdName, rt.Row.RedeemCostPoints, 1, ""),
            _ => "未知任务",
        };
        var done = result.StartsWith("打卡完成") || result.StartsWith("AI 对话完成") || result.StartsWith("挂机达成") || result == "";
        if (result.Contains("等待官方落账") || result.Contains("复检"))
            _db.SetRunState($"pending:{rt.Id}:{task}", Db.Now());
        _log.Write(done ? "success" : "warning", "Task", rt.Name, $"[{task}] {result}");
        if (!done && result != "今日打卡已达成" && result != "今日 AI 对话已达成" && result != "今日挂机任务已达成")
            await Svc.NotifyHubField.SendAsync(rt.Name, $"{task} 任务异常 - {rt.Name}", result);
        return result;
    }
}
