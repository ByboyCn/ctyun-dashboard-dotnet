using System.Collections.Concurrent;
using System.Text.Json.Nodes;

namespace CtyunDashboard;

/// <summary>
/// 日志枢纽：内存环形缓冲（最近日志）+ SQLite 落盘（后台批量）+ SSE 实时广播。
/// SSE 行格式：{"ts","level","scope","account","msg"}（JSON 行，前端 EventSource 直接渲染）。
/// </summary>
public sealed class LogHub
{
    public sealed record Entry(string Ts, string Level, string Scope, string Account, string Msg);

    private readonly ConcurrentQueue<Entry> _ring = new();
    private readonly ConcurrentQueue<SmLog> _pending = new();
    private readonly List<SseClient> _clients = [];
    private long _seq;
    private readonly Db _db;

    public LogHub(Db db) { _db = db; _ = Task.Run(FlushLoop); }

    public void Write(string level, string scope, string account, string msg)
    {
        var e = new Entry(Db.Now(), level, scope, account, msg);
        _ring.Enqueue(e);
        while (_ring.Count > 2000 && _ring.TryDequeue(out _)) { }

        _pending.Enqueue(new SmLog
        {
            Ts = e.Ts, Level = level, Scope = scope,
            Account = account, Msg = msg.Length > 4000 ? msg[..4000] : msg,
        });

        var line = ToJson(e) + "\n";
        List<SseClient> snapshot;
        lock (_clients) snapshot = [.. _clients];
        foreach (var c in snapshot)
        {
            if (!c.Match(e)) continue;
            try { c.Write(line); } catch { lock (_clients) _clients.Remove(c); }
        }
    }

    public void Info(string scope, string account, string msg) => Write("info", scope, account, msg);
    public void Success(string scope, string account, string msg) => Write("success", scope, account, msg);
    public void Warn(string scope, string account, string msg) => Write("warning", scope, account, msg);
    public void Error(string scope, string account, string msg) => Write("error", scope, account, msg);

    public List<Entry> Recent(int limit, string level = "", string scope = "", string account = "")
    {
        var list = new List<Entry>();
        foreach (var e in _ring)
        {
            if (level != "" && e.Level != level) continue;
            if (scope != "" && e.Scope != scope) continue;
            if (account != "" && e.Account != account) continue;
            list.Add(e);
        }
        list.Reverse();
        return list.Take(limit).ToList();
    }

    public IReadOnlyList<SmLog> RecentFromDb(int limit, string level = "", string scope = "", string account = "") =>
        _db.RecentLogs(limit, level, scope, account);

    public SseClient Subscribe(string level = "", string scope = "", string account = "")
    {
        var c = new SseClient(level, scope, account, ++_seq);
        lock (_clients) _clients.Add(c);
        return c;
    }

    public void Unsubscribe(SseClient c) { lock (_clients) _clients.Remove(c); }

    private static string Esc(string s) => s.Replace("\\", "\\\\").Replace("\"", "\\\"")
        .Replace("\n", "\\n").Replace("\r", "");

    internal static string ToJson(Entry e) =>
        "{\"ts\":\"" + Esc(e.Ts) + "\",\"level\":\"" + Esc(e.Level) + "\",\"scope\":\"" + Esc(e.Scope) +
        "\",\"account\":\"" + Esc(e.Account) + "\",\"msg\":\"" + Esc(e.Msg) + "\"}";

    private async Task FlushLoop()
    {
        while (true)
        {
            try
            {
                await Task.Delay(1000);
                if (_pending.IsEmpty) continue;
                var batch = new List<SmLog>();
                while (batch.Count < 200 && _pending.TryDequeue(out var l)) batch.Add(l);
                _db.InsertLogs(batch);
            }
            catch { /* 落盘失败不致命，下轮重试 */ }
        }
    }

    public sealed class SseClient(string level, string scope, string account, long seq)
    {
        public long Seq { get; } = seq;
        public string Level { get; } = level;
        public string Scope { get; } = scope;
        public string Account { get; } = account;
        private readonly BlockingCollection<string> _queue = new(500);

        public bool Match(Entry e) =>
            (Level == "" || e.Level == Level) &&
            (Scope == "" || e.Scope == Scope) &&
            (Account == "" || e.Account == Account);

        public void Write(string line)
        {
            if (!_queue.TryAdd(line)) { /* 订阅者过慢：丢行保进程 */ }
        }

        /// <summary>消费队列直到取消（由 SSE 路由调用）。</summary>
        public async Task PumpAsync(HttpContext ctx, CancellationToken ct)
        {
            var resp = ctx.Response;
            resp.StatusCode = 200;
            resp.ContentType = "text/event-stream";
            resp.Headers.CacheControl = "no-cache";
            resp.Headers.Connection = "keep-alive";
            await resp.StartAsync(ct);
            foreach (var line in _queue.GetConsumingEnumerable(ct))
            {
                await resp.WriteAsync("event: log\ndata: " + line.TrimEnd('\n') + "\n\n", ct);
                await resp.Body.FlushAsync(ct);
            }
        }
    }
}
