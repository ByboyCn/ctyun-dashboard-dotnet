using System.Text;
using System.Text.Json.Nodes;

namespace CtyunDashboard;

/// <summary>
/// 保活完成回调 Hook：每次脉冲执行结束后，向系统设置里配置的 URL 主动发一次请求。
/// 携带方式：query 参数 + JSON body 双通道，均含 desktopCode（官方原始字段，缺省回退 desktopId）。
/// 失败静默（记日志），绝不影响保活主流程；URL 为空 = 禁用。
/// </summary>
public static class PulseHook
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(5) };

    public static async Task FireAsync(Db db, string account, string desktopId, string desktopCode,
        string desktopName, bool ok, string error, int heldSec, string reason)
    {
        try
        {
            var url = db.GetSettings().HookUrl;
            if (string.IsNullOrWhiteSpace(url)) return;
            url = url.Trim();
            if (!url.StartsWith("http://") && !url.StartsWith("https://")) return;

            var ts = Db.Now();
            var status = ok ? "success" : "failed";
            var qs = "desktopCode=" + Uri.EscapeDataString(desktopCode) +
                     "&desktopId=" + Uri.EscapeDataString(desktopId) +
                     "&desktopName=" + Uri.EscapeDataString(desktopName) +
                     "&account=" + Uri.EscapeDataString(account) +
                     "&status=" + status +
                     "&heldSeconds=" + heldSec +
                     "&reason=" + Uri.EscapeDataString(reason) +
                     "&error=" + Uri.EscapeDataString(error) +
                     "&ts=" + Uri.EscapeDataString(ts);
            var sep = url.Contains('?') ? "&" : "?";

            var body = new JsonObject
            {
                ["event"] = "keepalive.completed",
                ["account"] = account,
                ["desktopId"] = desktopId,
                ["desktopCode"] = desktopCode,
                ["desktopName"] = desktopName,
                ["status"] = status,
                ["error"] = error,
                ["heldSeconds"] = heldSec,
                ["reason"] = reason,
                ["ts"] = ts,
            };
            var json = System.Text.Json.JsonSerializer.Serialize(body, AppJson.Default.JsonObject);
            using var content = new StringContent(json, Encoding.UTF8, "application/json");
            await Http.PostAsync(url + sep + qs, content);
        }
        catch { /* Hook 失败不影响保活主流程 */ }
    }
}
