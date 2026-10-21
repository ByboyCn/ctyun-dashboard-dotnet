using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using CtyunDashboard.Persist;

namespace CtyunDashboard;

/// <summary>8 渠道 Webhook 推送（企业微信/钉钉加签/飞书/Bark/Server酱/PushPlus/TG/自定义），内置 SSRF 防御。</summary>
public sealed class NotifyHub
{
    private readonly Db _db;
    private readonly LogHub _log;
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(10) };

    public NotifyHub(Db db, LogHub log) { _db = db; _log = log; }

    public async Task SendAsync(string account, string title, string body)
    {
        var settings = _db.GetSettings();
        if (settings.NotifyOnErrorOnly && !IsErrorTitle(title)) return;
        foreach (var ch in settings.NotifyChannels)
        {
            if (ch.AccScope != "*" && ch.AccScope != account) continue;
            try { await SendChannelAsync(ch, account, title, body); }
            catch (Exception ex) { _log.Write("warning", "Notify", account, "推送失败[" + ch.Type + "]: " + ex.Message); }
        }
    }

    private static bool IsErrorTitle(string title) =>
        title.Contains("失败") || title.Contains("异常") || title.Contains("错误");

    private async Task SendChannelAsync(NotifyChannel ch, string account, string title, string body)
    {
        if (!IsSafeUrl(ch.Url)) throw new Exception("目标地址被 SSRF 防御拦截");
        var text = "**" + title + "**\n" + body;
        static StringContent Json(string s) => new(s, Encoding.UTF8, "application/json");
        switch (ch.Type)
        {
            case "wecom":
                await Http.PostAsync(ch.Url, Json("{\"msgtype\":\"markdown\",\"markdown\":{\"content\":" + Quote(text) + "}}"));
                break;
            case "dingtalk":
            {
                var url = ch.Url;
                if (ch.Secret != "")
                {
                    var ts = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                    var sign = Convert.ToBase64String(new HMACSHA256(Encoding.UTF8.GetBytes(ch.Secret))
                        .ComputeHash(Encoding.UTF8.GetBytes(ts + "\n" + ch.Secret)));
                    url += (url.Contains('?') ? "&" : "?") + "timestamp=" + ts + "&sign=" + Uri.EscapeDataString(sign);
                }
                await Http.PostAsync(url, Json("{\"msgtype\":\"markdown\",\"markdown\":{\"title\":" + Quote(title) + ",\"text\":" + Quote(text) + "}}"));
                break;
            }
            case "feishu":
                await Http.PostAsync(ch.Url, Json("{\"msg_type\":\"text\",\"content\":{\"text\":" + Quote(title + "\n" + body) + "}}"));
                break;
            case "bark":
                await Http.GetAsync(ch.Url.TrimEnd('/') + "/" + Uri.EscapeDataString(title) + "/" + Uri.EscapeDataString(body));
                break;
            case "serverchan":
                await Http.PostAsync(ch.Url, new FormUrlEncodedContent(new Dictionary<string, string> { ["title"] = title, ["desp"] = body }));
                break;
            case "pushplus":
                await Http.PostAsync(ch.Url, Json("{\"title\":" + Quote(title) + ",\"content\":" + Quote(body) + ",\"template\":\"txt\"}"));
                break;
            case "telegram":
                await Http.PostAsync(ch.Url, Json("{\"text\":" + Quote(title + "\n" + body) + "}"));
                break;
            default:
                await Http.PostAsync(ch.Url, Json("{\"title\":" + Quote(title) + ",\"account\":" + Quote(account) + ",\"body\":" + Quote(body) + "}"));
                break;
        }
    }

    private static string Quote(string s) => "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "") + "\"";

    /// <summary>SSRF 防御：仅允许 http(s)，解析 DNS 后拒绝回环/私有/链路本地地址。</summary>
    internal static bool IsSafeUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https")) return false;
        try
        {
            var host = uri.Host;
            if (IPAddress.TryParse(host, out var ip)) return IsPublic(ip);
            var entries = Dns.GetHostAddresses(host);
            return entries.Length > 0 && entries.All(IsPublic);
        }
        catch { return false; }
    }

    private static bool IsPublic(IPAddress ip)
    {
        if (ip.IsIPv6LinkLocal || IPAddress.IsLoopback(ip)) return false;
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            if (b[0] is 10 or 127 or 0) return false;
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return false;
            if (b[0] == 192 && b[1] == 168) return false;
            if (b[0] == 169 && b[1] == 254) return false;
        }
        else if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv6SiteLocal) return false;
            var b = ip.GetAddressBytes();
            if (b[0] == 0xfd || (b[0] == 0xfe && b[1] == 0x80)) return false;
        }
        return true;
    }
}
