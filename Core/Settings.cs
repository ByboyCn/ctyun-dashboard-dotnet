namespace CtyunDashboard.Persist;

public class AppSettings
{
    public int PulseIntervalSeconds { get; set; } = 21600;   // 默认 6 小时一轮
    public int KeepAliveSeconds { get; set; } = 20;
    public List<string> ExecuteTime { get; set; } = ["01:20"];
    public string SignCron { get; set; } = "";
    public string AiCron { get; set; } = "";
    public string HangCron { get; set; } = "";
    public string RedeemCron { get; set; } = "";
    public string RedeemMode { get; set; } = "monthly";
    public int RedeemModeDay { get; set; } = 28;
    public int RedeemModeStepDays { get; set; } = 7;
    public bool NotifyOnErrorOnly { get; set; } = false;
    public List<NotifyChannel> NotifyChannels { get; set; } = [];
    public string Title { get; set; } = "云电脑可视化控制台";
    public string Subtitle { get; set; } = "天翼云 / 移动云 · NativeAOT 版";
    public string HookUrl { get; set; } = "";   // 保活完成回调 Hook（空=禁用）
}

public class NotifyChannel
{
    public string Type { get; set; } = "generic";
    public string Url { get; set; } = "";
    public string Secret { get; set; } = "";
    public string AccScope { get; set; } = "*";
}
