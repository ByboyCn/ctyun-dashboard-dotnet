// =============================================================================
// CtyunDashboard.Ecloud / EcloudConfig.cs
// =============================================================================
// 对齐参考实现（Python，只读）：app/ecloud_engine/config.py
//   BASE_URL / API_PATH / BACKUP_DOMAINS     → BaseUrl / ApiPath / BackupDomains
//   SIGN_METHOD / SIGN_VERSION / HMAC_KEY_PREFIX / API_TIMEOUT / LOGIN_TIMEOUT
//   USER_AGENT / COMPANY_CODE / CLIENT_VERSION / CHANNEL_VERSION
//   RSA_ENCRYPT_CHUNK=117 / RSA_DECRYPT_CHUNK=128
//   class Endpoint（全部端点常量）             → class Endpoints
//   class LoginError（30002009/30002060/30002063/10002039/30002026）
//   class LoginType（PASSWORD=0…MULTI_ACCT=7）
//   _load_credentials()                       → EcloudCredentials.LoadAsync 同源三级解析：
//     ① 环境变量 ECLOUD_ACCESS_KEY / ECLOUD_SECRET_KEY /
//        ECLOUD_RSA_PUBLIC_PEM(_FILE) / ECLOUD_RSA_PRIVATE_PEM(_FILE)
//     ② 覆盖文件 ECLOUD_CRED_FILE，缺省 <AppContext.BaseDirectory>/ecloud_credentials.json
//        （JSON: accessKey / secretKey / rsaPublicPem / rsaPrivatePem）
//     ③ 内置公开常量（public_credentials.json 的官方公众线固定材料，随仓库分发，
//        不含任何账号信息；平台轮换 Key 时用覆盖文件或环境变量替换即可）
//
// AOT：纯常量与文件/环境变量读取，零反射。
// =============================================================================

using System.Text.Json;

namespace CtyunDashboard.Ecloud;

public static class EcloudConfig
{
    // ---------- 服务端地址（config.py 120-125） ----------
    public const string BaseUrl = "https://cloudpc.ecloud.10086.cn";
    public const string ApiPath = "/api/cem/gateway/outer/cem-webapi";
    public static readonly string[] BackupDomains =
    {
        "https://cloudpc1.ecloud.10086.cn",
        "https://cloudpc2.ecloud.10086.cn",
    };

    // ---------- 签名常量（config.py 146-148） ----------
    public const string SignMethod = "HmacSHA1";
    public const string SignVersion = "V2.0";
    public const string HmacKeyPrefix = "BC_SIGNATURE&";

    // ---------- HTTP 常量（config.py 153-158） ----------
    public const int ApiTimeoutSec = 30;
    public const int LoginTimeoutSec = 10;
    public const string UserAgent =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) EcloudCloudComputer/3.8.2";

    // ---------- 业务常量（config.py 219-221） ----------
    public const string CompanyCode = "ECloud";
    public const string ClientVersion = "3.8.2";
    public const string ChannelVersion = "23";

    // ---------- RSA 分块（RSA-1024 PKCS1，config.py 140-141） ----------
    public const int RsaEncryptChunk = 117; // modulusLength/8 - 11
    public const int RsaDecryptChunk = 128; // modulusLength/8

    /// <summary>登录类端点：10s 超时 + 备用域名重试（config.py LOGIN_PATHS）。</summary>
    public static bool IsLoginPath(string endpoint) => endpoint is
        Endpoints.LoginCheckUserPassword or
        Endpoints.LoginQrCode or
        Endpoints.LoginCheckMobile or
        Endpoints.LoginAdLogin;

    /// <summary>API 端点表（config.py class Endpoint 逐字对齐）。</summary>
    public static class Endpoints
    {
        // 登录
        public const string LoginCheckUserPassword = "/login/verify";
        public const string LoginGetToken = "/login/verifyAccessTicket";
        public const string LoginCheckMobile = "/login/checkMobile";
        public const string LoginSendSms = "/login/sendVerifySms";
        public const string LoginVerifySms = "/login/verifySms";
        public const string LoginQrCode = "/login/getQRCode";
        public const string LoginQrLoginResult = "/login/getQRLoginResult";
        public const string LoginTrustDevice = "/login/trustDevice";
        public const string LoginTemporaryDevice = "/login/trustOrTemporaryDevice";
        public const string LoginAuthTwoFactorGet = "/login/special/getSecondauthSms";
        public const string LoginAuthTwoFactor = "/login/verifyTwoFactorAuthSms";
        public const string LoginAuth4ASms = "/user/getUserNameBySmsAuth";
        public const string LoginAuth4A = "/login/special/secondauthBy4a";
        public const string LoginEnhanceSms = "/login/verifyLoginEnhanceSms";
        public const string LoginAdLogin = "/login/adUserLogin";
        public const string LoginAdResult = "/login/getAdLoginResult";
        public const string LoginSimCode = "/login/simVerify";
        public const string LoginSimLoginResult = "/login/getSimLoginResult";
        public const string LoginNewByCode = "/login/loginByCode";
        public const string Logout = "/login/logout";

        // 用户/设备
        public const string UserGetInfo = "/user/getLoginUserInfo";
        public const string GetSysConfig = "/client/getSysConfig";
        public const string UserGetDeviceInfo = "/user/getDeviceInfo";
        public const string GetSysTime = "/user/getSysTime";
        public const string SetNewPwd = "/user/setNewPwd";

        // 探针上报（登录态保活）
        public const string ProbeQkkBatchPush = "/login/batchPushLoginQkk";

        // 桌面会话保活（desktop_session.py）
        public const string DesktopUptime = "/resource/desktopUptime";
        public const string SessionMachineConnect = "/session/machineConnect";
        public const string PushConnectEvent = "/machine/pushConnectEventData";
        public const string GetDesktopList = "/resource/getDesktopList";

        // 桌面列表与操作
        public const string GetDeviceInfo = "/user/getDeviceInfo";
        public const string GetDesktopStatus = "/user/getDesktopStatus";
        public const string ResourceOperate = "/resource/operate";
        public const string UpdateSessionStatus = "/session/updateSessionStatus";
    }

    /// <summary>登录错误码（config.py class LoginError）。</summary>
    public static class LoginError
    {
        public const string UntrustedDevice = "30002009";  // 未授信设备 → 需短信信任
        public const string TwoFactorAuth = "30002060";    // 二次验证
        public const string EnhancedStrategy = "30002063"; // 增强策略短信
        public const string FeishuBind = "10002039";
        public const string RefreshFsQrCode = "30002026";
    }

    /// <summary>登录方式（config.py class LoginType）。</summary>
    public static class LoginType
    {
        public const int Password = 0;
        public const int Sms = 1;
        public const int QrCode = 2;
        public const int Sim = 3;
        public const int ForgetPwd = 4;
        public const int AdConnector = 5;
        public const int FeishuQr = 6;
        public const int MultiAcct = 7;
    }
}

/// <summary>凭据缺失异常（config.py CredentialMissing：绝不静默降级）。</summary>
public sealed class EcloudCredentialMissingException : Exception
{
    public EcloudCredentialMissingException(string message) : base(message) { }
}

/// <summary>协议签名四件套（AccessKey/SecretKey/RSA 公私钥）。</summary>
public sealed class EcloudCredentials
{
    public string AccessKey { get; init; } = "";
    public string SecretKey { get; init; } = "";
    public string RsaPublicPem { get; init; } = "";
    public string RsaPrivatePem { get; init; } = "";

    // ---------------------------------------------------------------------------
    // 内置公开常量（app/ecloud_engine/public_credentials.json 逐字对齐）：
    // 官方公众线客户端内置的固定签名材料，属公开信息，不含任何账号信息。
    // ---------------------------------------------------------------------------
    public const string BundledAccessKey = "53bb79015a3f47c4be166d9371f68f14";
    public const string BundledSecretKey = "6b0d3b93f3aa4c7ea076c841bead1ddd";
    public const string BundledRsaPublicPem =
        "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqisJL7YvdPC/gJA7fLrr1G+t6\nJ0arJr0sVfieVJTXTclm/2afP/fjNYY/CFcg1MUx8KPmPC2CqsUHRMZq6Ev1/UNX\nE74I1TfJC/2b8aexcdZ+Lokj7AwzrM9yPy2qfV6vXtxyRrTs+JcFHVXtV6phNkor\nNyIahyfy46+iNB+FSQIDAQAB\n-----END PUBLIC KEY-----\n";
    public const string BundledRsaPrivatePem =
        "-----BEGIN PRIVATE KEY-----\nMIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKqKwkvti908L+Ak\nDt8uuvUb63onRqsmvSxV+J5UlNdNyWb/Zp8/9+M1hj8IVyDUxTHwo+Y8LYKqxQdE\nxmroS/X9Q1cTvgjVN8kL/Zvxp7Fx1n4uiSPsDDOsz3I/Lap9Xq9e3HJGtOz4lwUd\nVe1XqmE2Sis3IhqHJ/Ljr6I0H4VJAgMBAAECgYBD6lx0BlajtRtPxKxTfvWfNQ4y\nqD+BWz0M0fPfgcmAcI7bQKyqkLv0NNWQdo7UGUeqmq16u85X8g/i1CW8X2QYHOSY\nNBUWsK3k5gFT1wdk+bwuIMZqgjEc48TXzM4pidcplJLyD1tnNiubzcXIsZCIIuQ/\nGmWcuxn7ULHnXDsQMQJBANMl4V97be6fkd1beGqYZWIx3XNnL96AQsapBrEbbORT\nu/JnwTCRbsRWRBHU11FZuK85dBDXrH8reoAsgepmsF0CQQDOxL99OFjozj8g1weF\nGwI/otMKcPhkaslU2tj3QF44zT1TZiOZ710I8GQLPlKeu1yGWvVUwgH4bCY0M8M1\n/gndAkB9sU4RTeOqKjllwT7UjbXEl5SRTzrSxB18L0B5i67t2N7INXVumRSMMiJB\nTyeCGNv1C0mJgSoBZft9c4E+7TRNAkB+7Azza7Q/6+KaYQRPs32U3HkZbrE6ysYd\nXV1ToOJ1kZ60Y/00j9cXFqECudXzc+Ve39S6m4CkIpbs8l1A9ljNAkBy6Rp19R5w\nWMr/3feIMZ18akWXT5mgRvZpkT5MgmrjVu1lRv8bHsEsAzRYvdPSjzp0nCkUbOWU\nITxWp7d//Fwc\n-----END PRIVATE KEY-----\n";

    private static EcloudCredentials? _loaded;

    /// <summary>
    /// 三级解析（对齐 config.py _load_credentials）：环境变量 → 覆盖文件 → 内置公开常量。
    /// 进程内只解析一次；文件缺失/损坏只跳过该级（覆盖文件不存在是常态），四级皆缺才抛
    /// EcloudCredentialMissing（内置常量兜底后实际不会发生，保留契约以防内置值被清空）。
    /// </summary>
    public static EcloudCredentials Load()
    {
        if (_loaded != null) return _loaded;
        lock (typeof(EcloudCredentials))
        {
            if (_loaded != null) return _loaded;

            string ak = Environment.GetEnvironmentVariable("ECLOUD_ACCESS_KEY") ?? "";
            string sk = Environment.GetEnvironmentVariable("ECLOUD_SECRET_KEY") ?? "";
            string pub = ReadPemSource("ECLOUD_RSA_PUBLIC_PEM", "ECLOUD_RSA_PUBLIC_PEM_FILE");
            string priv = ReadPemSource("ECLOUD_RSA_PRIVATE_PEM", "ECLOUD_RSA_PRIVATE_PEM_FILE");

            string credFile = Environment.GetEnvironmentVariable("ECLOUD_CRED_FILE") ?? "";
            if (credFile == "")
                credFile = Path.Combine(AppContext.BaseDirectory, "ecloud_credentials.json");

            // 覆盖文件 → 内置常量（对齐 config.py 的 for label, path 循环）
            foreach ((string label, string path) in new[] { ("覆盖文件", credFile), ("内置公开常量", "") })
            {
                if (ak != "" && sk != "" && pub != "" && priv != "") break;
                if (label == "内置公开常量")
                {
                    ak = Or(ak, BundledAccessKey);
                    sk = Or(sk, BundledSecretKey);
                    pub = Or(pub, BundledRsaPublicPem);
                    priv = Or(priv, BundledRsaPrivatePem);
                    break;
                }
                if (!File.Exists(path)) continue; // 覆盖文件不存在是常态，交给下一级兜底
                try
                {
                    using var doc = JsonDocument.Parse(File.ReadAllText(path));
                    var d = doc.RootElement;
                    ak = Or(ak, GetStr(d, "accessKey"));
                    sk = Or(sk, GetStr(d, "secretKey"));
                    pub = Or(pub, GetStr(d, "rsaPublicPem"));
                    priv = Or(priv, GetStr(d, "rsaPrivatePem"));
                }
                catch (Exception e)
                {
                    throw new EcloudCredentialMissingException($"凭据文件解析失败（{label}）: {path} ({e.GetType().Name}: {e.Message})");
                }
            }

            var missing = new List<string>();
            if (ak == "") missing.Add("AccessKey");
            if (sk == "") missing.Add("SecretKey");
            if (pub == "") missing.Add("RSA 公钥");
            if (priv == "") missing.Add("RSA 私钥");
            if (missing.Count > 0)
                throw new EcloudCredentialMissingException(
                    "移动公众协议凭据缺失: " + string.Join(" / ", missing) +
                    " —— 请通过环境变量提供，或检查覆盖文件是否完整");

            _loaded = new EcloudCredentials { AccessKey = ak, SecretKey = sk, RsaPublicPem = pub, RsaPrivatePem = priv };
            return _loaded;
        }
    }

    private static string Or(string cur, string fallback) => cur != "" ? cur : fallback;

    private static string GetStr(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString() ?? ""
            : "";

    /// <summary>按 内容 → 文件 的顺序取 PEM（config.py _read_pem）。</summary>
    private static string ReadPemSource(string envContent, string envFile)
    {
        var content = Environment.GetEnvironmentVariable(envContent);
        if (!string.IsNullOrWhiteSpace(content)) return content;
        var path = Environment.GetEnvironmentVariable(envFile);
        if (!string.IsNullOrEmpty(path) && File.Exists(path))
            return File.ReadAllText(path);
        return "";
    }
}
