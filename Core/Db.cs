using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using CtyunDashboard.Persist;

namespace CtyunDashboard;

/// <summary>
/// 落盘层：SQLite（data/ctyun.db，Microsoft.Data.Sqlite 直连，显式列映射）。
/// 说明1：SqlSugar 的查询物化依赖反射 emit（DynamicMethod），NativeAOT 不支持。
/// 说明2：反射式属性映射会被 AOT 裁剪掉成员元数据，故全部采用显式列映射（AOT 零魔法）。
/// 敏感字段（云电脑账号密码、登录态）先经国密 SM4-CBC+HMAC-SM3 加密再存 TEXT。
/// </summary>
public sealed class Db
{
    private readonly SqliteConnection _conn;
    private readonly byte[] _masterKey;
    private readonly object _lock = new();
    public string DataDir { get; }

    public Db(string? dataDir = null)
    {
        var env = Environment.GetEnvironmentVariable("CTYUN_DATA_DIR");
        DataDir = dataDir ?? (string.IsNullOrEmpty(env) ? null : env)
                 ?? Path.Combine(AppContext.BaseDirectory, "data");
        Directory.CreateDirectory(DataDir);
        _masterKey = LoadOrCreateMasterKey();
        _conn = new SqliteConnection("Data Source=" + Path.Combine(DataDir, "ctyun.db") + ";Cache=Shared");
        _conn.Open();
        Exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000;");
    }

    /// <summary>建表 + 种子数据 + 国密算法自检。失败即抛（快速失败）。</summary>
    public void Init()
    {
        var selfTest = Gm.Sm3SelfTest() ?? Gm.Sm4SelfTest();
        if (selfTest != null) throw new InvalidOperationException(selfTest);

        Exec("""
            CREATE TABLE IF NOT EXISTS user (
                Id TEXT PRIMARY KEY, Username TEXT, Role TEXT, PwdHash TEXT, Salt TEXT, CreatedAt TEXT);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_user_name ON user(Username);
            """);
        Exec("""
            CREATE TABLE IF NOT EXISTS account (
                Id TEXT PRIMARY KEY, Platform TEXT, Owner TEXT, Name TEXT, User TEXT,
                EncPassword TEXT, EncSession TEXT,
                KeepaliveEnabled INTEGER, PulseIntervalSeconds INTEGER,
                AutoSign INTEGER, AutoAi INTEGER, AutoHang INTEGER, AutoRedeem INTEGER,
                RedeemStrategy TEXT, RedeemDay INTEGER, RedeemStepDays INTEGER,
                RedeemProdId TEXT, RedeemProdName TEXT, RedeemCostPoints INTEGER,
                LastSignTime TEXT, LastAiTime TEXT, LastHangTime TEXT,
                HangMinutesToday INTEGER, Points INTEGER, LastLoginAt TEXT, AddedAt TEXT, LastError TEXT);
            """);
        Exec("""
            CREATE TABLE IF NOT EXISTS desktop (
                AccountId TEXT, DesktopId TEXT, Name TEXT, UseStatus INTEGER, UseStatusText TEXT, Spec TEXT,
                KeepaliveEnabled INTEGER, TaskEnabled INTEGER, KeepaliveInterval INTEGER, LastPulseAt TEXT,
                RawJson TEXT,
                PRIMARY KEY (AccountId, DesktopId));
            """);
        Exec("CREATE TABLE IF NOT EXISTS session (Token TEXT PRIMARY KEY, UserId TEXT, ExpiresAt TEXT);");
        Exec("CREATE TABLE IF NOT EXISTS kv (Key TEXT PRIMARY KEY, Value TEXT);");
        Exec("CREATE TABLE IF NOT EXISTS log (Id INTEGER PRIMARY KEY AUTOINCREMENT, Ts TEXT, Level TEXT, Scope TEXT, Account TEXT, Msg TEXT);");

        if (FindUser("admin") == null)
        {
            var (hash, salt) = Auth.HashPassword("admin123");
            InsertUser(new SmUser
            {
                Id = NewId(), Username = "admin", Role = "admin",
                PwdHash = hash, Salt = salt, CreatedAt = Now(),
            });
        }
        if (GetKv("settings") == null) SaveSettings(new AppSettings());

        // 迁移（必须在全部建表与种子之后）
        try { Exec("ALTER TABLE desktop ADD COLUMN RawJson TEXT"); } catch { /* 列已存在 */ }
        try { Exec("ALTER TABLE account ADD COLUMN Protocol TEXT"); } catch { /* 列已存在 */ }   // ydpc：ZTE / SCG（用户可选，空=ZTE）
        // 保活周期默认迁移：600 秒以下的旧值（含旧默认 30 秒、用户误填的 5 秒）统一 → 6 小时；低于 10 秒的单机间隔回归继承账号值
        Exec("UPDATE account SET PulseIntervalSeconds=21600 WHERE PulseIntervalSeconds < 600");
        Exec("UPDATE desktop SET KeepaliveInterval=NULL WHERE KeepaliveInterval IS NOT NULL AND KeepaliveInterval<10");
        var settings = GetSettings();
        if (settings.PulseIntervalSeconds == 30) { settings.PulseIntervalSeconds = 21600; SaveSettings(settings); }
    }

    // ---------- 通用 ----------
    public static string NewId() => Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();
    public static string Now() => DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
    public static string Today() => DateTime.Now.ToString("yyyy-MM-dd");

    private byte[] LoadOrCreateMasterKey()
    {
        var p = Path.Combine(DataDir, "master.key");
        if (File.Exists(p))
            try { return Convert.FromBase64String(File.ReadAllText(p)); } catch { }
        var key = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        File.WriteAllText(p, Convert.ToBase64String(key));
        return key;
    }

    public string Protect(string plain) => Gm.Protect(_masterKey, Encoding.UTF8.GetBytes(plain));
    public string Unprotect(string payload) => Encoding.UTF8.GetString(Gm.Unprotect(_masterKey, payload));

    // ---------- ADO 原语 ----------
    private static SqliteCommand Cmd(SqliteConnection conn, string sql, object?[] args)
    {
        var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        for (var i = 0; i < args.Length; i++)
        {
            var p = cmd.CreateParameter();
            p.ParameterName = "@p" + i;
            p.Value = args[i] switch
            {
                null => DBNull.Value,
                bool b => b ? 1L : 0L,
                int n => (long)n,
                _ => args[i],
            };
            cmd.Parameters.Add(p);
        }
        return cmd;
    }

    private int Exec(string sql, params object?[] args)
    {
        lock (_lock)
        {
            using var cmd = Cmd(_conn, sql, args);
            return cmd.ExecuteNonQuery();
        }
    }

    private static string S(SqliteDataReader r, int ord) => r.IsDBNull(ord) ? "" : r.GetString(ord);
    private static string? SN(SqliteDataReader r, int ord) => r.IsDBNull(ord) ? null : r.GetString(ord);
    private static int I(SqliteDataReader r, int ord) => r.IsDBNull(ord) ? 0 : Convert.ToInt32(r.GetInt64(ord));
    private static bool B(SqliteDataReader r, int ord) => !r.IsDBNull(ord) && r.GetInt64(ord) != 0;
    private static int? INull(SqliteDataReader r, int ord) => r.IsDBNull(ord) ? null : Convert.ToInt32(r.GetInt64(ord));

    private static int Ord(SqliteDataReader r, string col) { try { return r.GetOrdinal(col); } catch { return -1; } }

    // ---------- 用户 ----------
    public SmUser? FindUser(string username)
    {
        lock (_lock)
        {
            using var cmd = Cmd(_conn, "SELECT * FROM user WHERE Username=@p0 LIMIT 1", [username]);
            using var r = cmd.ExecuteReader();
            if (!r.Read()) return null;
            return new SmUser
            {
                Id = S(r, Ord(r, "Id")), Username = S(r, Ord(r, "Username")), Role = S(r, Ord(r, "Role")),
                PwdHash = S(r, Ord(r, "PwdHash")), Salt = S(r, Ord(r, "Salt")), CreatedAt = S(r, Ord(r, "CreatedAt")),
            };
        }
    }

    public SmUser? UserById(string id)
    {
        lock (_lock)
        {
            using var cmd = Cmd(_conn, "SELECT * FROM user WHERE Id=@p0 LIMIT 1", [id]);
            using var r = cmd.ExecuteReader();
            if (!r.Read()) return null;
            return new SmUser { Id = S(r, 0), Username = S(r, 1), Role = S(r, 2), PwdHash = S(r, 3), Salt = S(r, 4), CreatedAt = S(r, 5) };
        }
    }

    public List<SmUser> Users()
    {
        var list = new List<SmUser>();
        lock (_lock)
        {
            using var cmd = Cmd(_conn, "SELECT Id,Username,Role,PwdHash,Salt,CreatedAt FROM user ORDER BY CreatedAt", []);
            using var r = cmd.ExecuteReader();
            while (r.Read())
                list.Add(new SmUser { Id = S(r, 0), Username = S(r, 1), Role = S(r, 2), PwdHash = S(r, 3), Salt = S(r, 4), CreatedAt = S(r, 5) });
        }
        return list;
    }

    public void InsertUser(SmUser u) =>
        Exec("INSERT INTO user (Id,Username,Role,PwdHash,Salt,CreatedAt) VALUES (@p0,@p1,@p2,@p3,@p4,@p5)",
            u.Id, u.Username, u.Role, u.PwdHash, u.Salt, u.CreatedAt);

    public void UpdateUser(SmUser u) =>
        Exec("UPDATE user SET Username=@p1, Role=@p2, PwdHash=@p3, Salt=@p4, CreatedAt=@p5 WHERE Id=@p0",
            u.Id, u.Username, u.Role, u.PwdHash, u.Salt, u.CreatedAt);

    public void DeleteUser(string id)
    {
        Exec("DELETE FROM user WHERE Id=@p0", id);
        Exec("DELETE FROM session WHERE UserId=@p0", id);
    }

    // ---------- 会话 ----------
    public void InsertSession(SmSession s) =>
        Exec("INSERT INTO session (Token,UserId,ExpiresAt) VALUES (@p0,@p1,@p2)", s.Token, s.UserId, s.ExpiresAt);

    public SmSession? FindSession(string token)
    {
        lock (_lock)
        {
            using var cmd = Cmd(_conn, "SELECT Token,UserId,ExpiresAt FROM session WHERE Token=@p0 LIMIT 1", [token]);
            using var r = cmd.ExecuteReader();
            return r.Read() ? new SmSession { Token = S(r, 0), UserId = S(r, 1), ExpiresAt = S(r, 2) } : null;
        }
    }

    public void DeleteSession(string token) => Exec("DELETE FROM session WHERE Token=@p0", token);
    public void PurgeExpiredSessions() => Exec("DELETE FROM session WHERE ExpiresAt < @p0", Now());

    // ---------- 账号 ----------
    private const string AccountCols =
        "Id,Platform,Owner,Name,User,EncPassword,EncSession,KeepaliveEnabled,PulseIntervalSeconds," +
        "AutoSign,AutoAi,AutoHang,AutoRedeem,RedeemStrategy,RedeemDay,RedeemStepDays," +
        "RedeemProdId,RedeemProdName,RedeemCostPoints,LastSignTime,LastAiTime,LastHangTime," +
        "HangMinutesToday,Points,LastLoginAt,AddedAt,LastError,Protocol";

    private static SmAccount ReadAccount(SqliteDataReader r)
    {
        var a = new SmAccount
        {
            Id = S(r, 0), Platform = S(r, 1), Owner = S(r, 2), Name = S(r, 3), User = S(r, 4),
            EncPassword = S(r, 5), EncSession = S(r, 6),
            KeepaliveEnabled = B(r, 7), PulseIntervalSeconds = I(r, 8),
            AutoSign = B(r, 9), AutoAi = B(r, 10), AutoHang = B(r, 11), AutoRedeem = B(r, 12),
            RedeemStrategy = S(r, 13), RedeemDay = I(r, 14), RedeemStepDays = I(r, 15),
            RedeemProdId = S(r, 16), RedeemProdName = S(r, 17), RedeemCostPoints = I(r, 18),
            LastSignTime = SN(r, 19), LastAiTime = SN(r, 20), LastHangTime = SN(r, 21),
            HangMinutesToday = I(r, 22), Points = I(r, 23), LastLoginAt = SN(r, 24),
            AddedAt = S(r, 25), LastError = SN(r, 26), Protocol = S(r, 27),
        };
        return a;
    }

    private static object?[] AccountArgs(SmAccount a) =>
    [
        a.Id, a.Platform, a.Owner, a.Name, a.User, a.EncPassword, a.EncSession,
        a.KeepaliveEnabled, a.PulseIntervalSeconds,
        a.AutoSign, a.AutoAi, a.AutoHang, a.AutoRedeem,
        a.RedeemStrategy, a.RedeemDay, a.RedeemStepDays,
        a.RedeemProdId, a.RedeemProdName, a.RedeemCostPoints,
        a.LastSignTime, a.LastAiTime, a.LastHangTime,
        a.HangMinutesToday, a.Points, a.LastLoginAt, a.AddedAt, a.LastError, a.Protocol,
    ];

    public List<SmAccount> Accounts()
    {
        var list = new List<SmAccount>();
        lock (_lock)
        {
            using var cmd = Cmd(_conn, $"SELECT {AccountCols} FROM account ORDER BY AddedAt", []);
            using var r = cmd.ExecuteReader();
            while (r.Read()) list.Add(ReadAccount(r));
        }
        return list;
    }

    public SmAccount? AccountById(string id)
    {
        lock (_lock)
        {
            using var cmd = Cmd(_conn, $"SELECT {AccountCols} FROM account WHERE Id=@p0 LIMIT 1", [id]);
            using var r = cmd.ExecuteReader();
            return r.Read() ? ReadAccount(r) : null;
        }
    }

    public void InsertAccount(SmAccount a)
    {
        var holders = string.Join(",", Enumerable.Range(0, 28).Select(i => "@p" + i));
        Exec($"INSERT INTO account ({AccountCols}) VALUES ({holders})", AccountArgs(a));
    }

    public void UpdateAccount(SmAccount a)
    {
        var sets = "Platform=@p1,Owner=@p2,Name=@p3,User=@p4,EncPassword=@p5,EncSession=@p6," +
            "KeepaliveEnabled=@p7,PulseIntervalSeconds=@p8,AutoSign=@p9,AutoAi=@p10,AutoHang=@p11,AutoRedeem=@p12," +
            "RedeemStrategy=@p13,RedeemDay=@p14,RedeemStepDays=@p15,RedeemProdId=@p16,RedeemProdName=@p17," +
            "RedeemCostPoints=@p18,LastSignTime=@p19,LastAiTime=@p20,LastHangTime=@p21,HangMinutesToday=@p22," +
            "Points=@p23,LastLoginAt=@p24,AddedAt=@p25,LastError=@p26,Protocol=@p27";
        Exec($"UPDATE account SET {sets} WHERE Id=@p0", AccountArgs(a));
    }

    public void DeleteAccount(string id)
    {
        Exec("DELETE FROM account WHERE Id=@p0", id);
        Exec("DELETE FROM desktop WHERE AccountId=@p0", id);
    }

    // ---------- 桌面 ----------
    private const string DeskCols =
        "AccountId,DesktopId,Name,UseStatus,UseStatusText,Spec,KeepaliveEnabled,TaskEnabled,KeepaliveInterval,LastPulseAt,RawJson";

    private static SmDesktop ReadDesktop(SqliteDataReader r) => new()
    {
        AccountId = S(r, 0), DesktopId = S(r, 1), Name = S(r, 2), UseStatus = I(r, 3),
        UseStatusText = S(r, 4), Spec = S(r, 5), KeepaliveEnabled = B(r, 6), TaskEnabled = B(r, 7),
        KeepaliveInterval = INull(r, 8), LastPulseAt = SN(r, 9), RawJson = S(r, 10),
    };

    public void SyncDesktops(SmAccount account, List<(string id, string name, int useStatus, string useStatusText, string spec, string raw)>? list = null)
    {
        var old = DesktopsOf(account.Id);
        if (list == null) return;
        foreach (var (id, name, useStatus, useStatusText, spec, raw) in list)
        {
            var exist = old.FirstOrDefault(d => d.DesktopId == id);
            if (exist == null)
            {
                Exec("INSERT INTO desktop (" + DeskCols + ") VALUES (@p0,@p1,@p2,@p3,@p4,@p5,@p6,@p7,@p8,@p9,@p10)",
                    account.Id, id, name, useStatus, useStatusText, spec, true, true, null, null, raw);
            }
            else
            {
                exist.Name = string.IsNullOrEmpty(name) ? exist.Name : name;
                exist.UseStatus = useStatus;
                exist.UseStatusText = useStatusText;
                exist.Spec = spec;
                exist.RawJson = raw;
                UpdateDesktop(exist);
            }
        }
    }

    public List<SmDesktop> DesktopsOf(string accountId)
    {
        var list = new List<SmDesktop>();
        lock (_lock)
        {
            using var cmd = Cmd(_conn, $"SELECT {DeskCols} FROM desktop WHERE AccountId=@p0 ORDER BY DesktopId", [accountId]);
            using var r = cmd.ExecuteReader();
            while (r.Read()) list.Add(ReadDesktop(r));
        }
        return list;
    }

    public void UpdateDesktop(SmDesktop d) =>
        Exec("UPDATE desktop SET Name=@p2, UseStatus=@p3, UseStatusText=@p4, Spec=@p5, KeepaliveEnabled=@p6, " +
             "TaskEnabled=@p7, KeepaliveInterval=@p8, LastPulseAt=@p9, RawJson=@p10 WHERE AccountId=@p0 AND DesktopId=@p1",
            d.AccountId, d.DesktopId, d.Name, d.UseStatus, d.UseStatusText, d.Spec,
            d.KeepaliveEnabled, d.TaskEnabled, d.KeepaliveInterval, d.LastPulseAt, d.RawJson);

    public void TouchPulse(string accountId, string desktopId) =>
        Exec("UPDATE desktop SET LastPulseAt=@p0 WHERE AccountId=@p1 AND DesktopId=@p2", Now(), accountId, desktopId);

    // ---------- kv / 设置 ----------
    public string? GetKv(string key)
    {
        lock (_lock)
        {
            using var cmd = Cmd(_conn, "SELECT Value FROM kv WHERE Key=@p0 LIMIT 1", [key]);
            using var r = cmd.ExecuteReader();
            return r.Read() ? S(r, 0) : null;
        }
    }

    public void SetKv(string key, string value) =>
        Exec("INSERT INTO kv (Key,Value) VALUES (@p0,@p1) ON CONFLICT(Key) DO UPDATE SET Value=@p1", key, value);

    public AppSettings GetSettings()
    {
        var raw = GetKv("settings");
        if (raw == null) return new AppSettings();
        try { return JsonSerializer.Deserialize(raw, AppJson.Default.AppSettings) ?? new AppSettings(); }
        catch { return new AppSettings(); }
    }

    public void SaveSettings(AppSettings s) => SetKv("settings", JsonSerializer.Serialize(s, AppJson.Default.AppSettings));

    // ---------- 运行状态（任务去重等） ----------
    public string? GetRunState(string key) => GetKv("run:" + key);
    public void SetRunState(string key, string value) => SetKv("run:" + key, value);

    // ---------- 日志 ----------
    public void InsertLogs(List<SmLog> logs)
    {
        if (logs.Count == 0) return;
        lock (_lock)
        {
            using var tx = _conn.BeginTransaction();
            foreach (var l in logs)
            {
                using var cmd = Cmd(_conn, "INSERT INTO log (Ts,Level,Scope,Account,Msg) VALUES (@p0,@p1,@p2,@p3,@p4)",
                    [l.Ts, l.Level, l.Scope, l.Account, l.Msg]);
                cmd.Transaction = tx;
                cmd.ExecuteNonQuery();
            }
            tx.Commit();
        }
    }

    public List<SmLog> RecentLogs(int limit, string level = "", string scope = "", string account = "")
    {
        var sql = "SELECT Ts,Level,Scope,Account,Msg FROM log";
        var conds = new List<string>();
        var args = new List<object?>();
        if (level != "") { conds.Add("Level=@p" + args.Count); args.Add(level); }
        if (scope != "") { conds.Add("Scope=@p" + args.Count); args.Add(scope); }
        if (account != "") { conds.Add("Account=@p" + args.Count); args.Add(account); }
        if (conds.Count > 0) sql += " WHERE " + string.Join(" AND ", conds);
        sql += $" ORDER BY Id DESC LIMIT {Math.Clamp(limit, 1, 1000)}";

        var list = new List<SmLog>();
        lock (_lock)
        {
            using var cmd = Cmd(_conn, sql, [.. args]);
            using var r = cmd.ExecuteReader();
            while (r.Read())
                list.Add(new SmLog { Ts = S(r, 0), Level = S(r, 1), Scope = S(r, 2), Account = S(r, 3), Msg = S(r, 4) });
        }
        list.Reverse();   // 统一为旧→新升序（与 SSE 追加顺序一致）
        return list;
    }
}

// ================= 实体 =================

public class SmUser
{
    public string Id { get; set; } = "";
    public string Username { get; set; } = "";
    public string Role { get; set; } = "user";
    public string PwdHash { get; set; } = "";
    public string Salt { get; set; } = "";
    public string CreatedAt { get; set; } = "";
}

public class SmAccount
{
    public string Id { get; set; } = "";
    public string Platform { get; set; } = "ctyun";
    public string Owner { get; set; } = "";
    public string Name { get; set; } = "";
    public string User { get; set; } = "";
    public string EncPassword { get; set; } = "";
    public string EncSession { get; set; } = "";

    public bool KeepaliveEnabled { get; set; } = true;
    public int PulseIntervalSeconds { get; set; } = 21600;   // 默认 6 小时一轮
    public bool AutoSign { get; set; } = true;
    public bool AutoAi { get; set; } = true;
    public bool AutoHang { get; set; } = true;
    public bool AutoRedeem { get; set; } = false;
    public string RedeemStrategy { get; set; } = "monthly";
    public int RedeemDay { get; set; } = 28;
    public int RedeemStepDays { get; set; } = 7;
    public string RedeemProdId { get; set; } = "";
    public string RedeemProdName { get; set; } = "";
    public int RedeemCostPoints { get; set; } = 100;

    public string? LastSignTime { get; set; }
    public string? LastAiTime { get; set; }
    public string? LastHangTime { get; set; }
    public int HangMinutesToday { get; set; }
    public int Points { get; set; }
    public string? LastLoginAt { get; set; }
    public string AddedAt { get; set; } = "";
    public string? LastError { get; set; }
    /// <summary>移动爱家底层协议：ZTE（默认）/ SCG（深信服）；仅 ydpc-soho 平台消费。</summary>
    public string Protocol { get; set; } = "";
}

public class SmDesktop
{
    public string AccountId { get; set; } = "";
    public string DesktopId { get; set; } = "";
    public string Name { get; set; } = "";
    public int UseStatus { get; set; }
    public string UseStatusText { get; set; } = "";
    public string Spec { get; set; } = "";
    public bool KeepaliveEnabled { get; set; } = true;
    public bool TaskEnabled { get; set; } = true;
    public int? KeepaliveInterval { get; set; }
    public string? LastPulseAt { get; set; }
    public string RawJson { get; set; } = "";
}

public class SmSession
{
    public string Token { get; set; } = "";
    public string UserId { get; set; } = "";
    public string ExpiresAt { get; set; } = "";
}

public class SmKv
{
    public string Key { get; set; } = "";
    public string Value { get; set; } = "";
}

public class SmLog
{
    public long Id { get; set; }
    public string Ts { get; set; } = "";
    public string Level { get; set; } = "info";
    public string Scope { get; set; } = "";
    public string Account { get; set; } = "";
    public string Msg { get; set; } = "";
}
