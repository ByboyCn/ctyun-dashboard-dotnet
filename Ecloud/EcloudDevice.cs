// =============================================================================
// CtyunDashboard.Ecloud / EcloudDevice.cs
// =============================================================================
// 对齐参考实现（Python，只读）：app/ecloud_engine/device.py + desktop_list.py(operate_desktop)
//   ──────────────────────────────────────────────────────────────────────────
//   device.py detect()/DeviceInfo.to_common_params()
//     —— 设备指纹：只有 deviceUid 是关键（跨运行稳定，变化触发"未授信设备"）；
//        其余字段服务端不校验（逐字段删除测试实证），给合理默认值。
//     clientType：Windows → pc_windows_64_yt（对齐 deviceUtil.js 的 Windows 分支）
//                                             → EcloudDevice.BuildCommonParams
//   desktop_list.operate_desktop()（POST /resource/operate
//     {machineId, machineName, operate, deviceUid, resourcePoolUid, sdkType}
//     operate: "available"(开机，后端不认识 startup/powerOn) | "shutdown" | "restart"
//     sdkType: Darwin=5 否则 4）
//                                             → PowerAsync
//   sidecar.py op_desktop_power（白名单 + 平台受理口径：
//     "已下发{中文}指令，平台已受理（状态落地需数秒到数十秒）"）→ PowerAsync 返回消息
//
// deviceUid 稳定性策略：Python 从配置/machine-id 派生；C# 侧由账号运行时持久化在
// EncSession（首见生成 GUID，此后跨重启复用）——语义一致：稳定即可，来源不限。
//
// AOT：纯字符串/常量组装 + JsonObject，零反射。
// =============================================================================

using System.Text.Json.Nodes;

namespace CtyunDashboard.Ecloud;

public static class EcloudDevice
{
    /// <summary>电源操作白名单（侧车 _POWER_OPERATE_CN；协议取值来自官方 asar 逆向）。</summary>
    public static bool IsSupportedOperate(string operate) => operate is "available" or "shutdown" or "restart";

    public static string OperateCn(string operate) => operate switch
    {
        "available" => "开机",
        "shutdown" => "关机",
        "restart" => "重启",
        _ => operate,
    };

    /// <summary>
    /// 生成每个请求 body 合并的公共参数（device.py to_common_params 逐字段对齐）。
    /// deviceUid 必须跨运行稳定；其余字段服务端不校验。
    /// </summary>
    public static JsonObject BuildCommonParams(string deviceUid, string hostName)
    {
        return new JsonObject
        {
            ["companyCode"] = EcloudConfig.CompanyCode,
            ["clientType"] = "pc_windows_64_yt",          // clientUtil.js Windows 分支
            ["clientVersion"] = EcloudConfig.ClientVersion,
            ["deviceUid"] = deviceUid,
            ["deviceName"] = hostName != "" ? hostName : "keepalive",
            ["deviceType"] = "pc",
            ["operatingSystem"] = "Windows",
            ["cores"] = 4,
            ["ram"] = 8,
            ["systemArchitecture"] = "x86_64",
            // 以下字段服务端不校验，给默认值即可
            ["deviceCompany"] = "Unknown",
            ["deviceModel"] = "Server",
            ["deviceSystem"] = "Unknown",
            ["operatingVersion"] = "unknown",
            ["processor"] = "Unknown",
            ["diskTotal"] = 500.0,
            ["diskUsed"] = 250.0,
            ["ipAddress"] = "127.0.0.1",
            ["macAddress"] = "00:00:00:00:00:00",
        };
    }

    /// <summary>
    /// 桌面电源操作（operate_desktop + op_desktop_power）：开机 / 关机 / 重启。
    /// 用户显式触发的动作；成功只报"平台已受理"——受理 ≠ 已生效，最终状态以刷新为准。
    /// </summary>
    public static async Task<(bool Ok, string Message)> PowerAsync(
        EcloudHttpUtil http, string machineId, string machineName, string operate,
        string resourcePoolUid = "", CancellationToken ct = default)
    {
        operate = operate.Trim();
        if (!IsSupportedOperate(operate))
            throw new InvalidOperationException($"不支持的电源操作: {(operate == "" ? "(空)" : operate)}（仅 available/shutdown/restart）");
        if (machineId == "")
            throw new InvalidOperationException("desktop.power 需要 machineId（桌面列表里获取）");

        await http.PostAsync(EcloudConfig.Endpoints.ResourceOperate, new JsonObject
        {
            ["machineId"] = machineId,
            ["machineName"] = machineName,
            ["operate"] = operate,
            ["deviceUid"] = http.CommonParams["deviceUid"] is JsonValue dv && dv.TryGetValue<string>(out var du) ? du : "",
            ["resourcePoolUid"] = resourcePoolUid,
            ["sdkType"] = 4, // Darwin=5；Windows/Linux 客户端=4（operate_desktop 的 platform 分支）
        }, ct: ct).ConfigureAwait(false);

        string cn = OperateCn(operate);
        return (true, $"已下发{cn}指令，平台已受理（状态落地需数秒到数十秒，稍后自动刷新）");
    }
}
