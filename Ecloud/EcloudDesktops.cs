// =============================================================================
// CtyunDashboard.Ecloud / EcloudDesktops.cs
// =============================================================================
// 对齐参考实现（Python，只读）：app/ecloud_engine/desktop_list.py
//   Desktop dataclass                         → EcloudDesktop record
//   POWER_ON_TOKENS / POWER_OFF_TOKENS /
//   _POWER_OFF_SUBSTR / _POWER_ON_SUBSTR /
//   normalize_power_state()（on/off/unknown 三态，先判 off，unknown 绝不当 off）
//                                             → EcloudDesktops.NormalizePowerState
//   get_desktop_list()（POST /user/getDeviceInfo
//                        {companyCode:ECloud, allCompany:true, version:1.0.0}
//                        → machineList[]：instanceId/machineId/machineName/
//                          originCompanyCode/resourcePoolUid/machineOperateMap）
//                                             → GetDesktopListAsync
//   get_desktop_status()（POST /user/getDesktopStatus {instanceIdList}
//                        → machineStatusList[]：instanceId/resourceStatus）
//                                             → GetDesktopStatusAsync
//   select_running_desktop()（只有明确 on 才可保活；状态不可用回落第一台）
//                                             → SelectRunningDesktopAsync
//   （operate_desktop 的电源操作在 EcloudDevice.cs —— 侧车按职责拆分）
//
// AOT：JsonElement/JsonObject 手工解包，零反射。
// =============================================================================

using System.Text.Json.Nodes;

namespace CtyunDashboard.Ecloud;

/// <summary>一个云电脑桌面（desktop_list.Desktop + 侧车 op_desktop_list 的输出字段）。</summary>
public sealed record EcloudDesktop(
    string InstanceId,          // CCA-xxx，desktopUptime 必需
    string MachineId,           // UUID，machineConnect / resource/operate 用
    string MachineName = "",
    string OriginCompanyCode = "",
    string ResourcePoolUid = "",
    string ResourceStatus = "", // 服务端原始枚举（会滞后/失真，仅展示与排查）
    string PowerState = "unknown", // 归一三态：on / off / unknown
    bool? PowerOnEnable = null, // machineOperateMap.powerOn.operateEnable（平台操作层现算）
    string PowerOnHint = "")
{
    public JsonObject ToRawJson() => new()
    {
        ["instanceId"] = InstanceId,
        ["machineId"] = MachineId,
        ["machineName"] = MachineName,
        ["originCompanyCode"] = OriginCompanyCode,
        ["resourcePoolUid"] = ResourcePoolUid,
        ["resourceStatus"] = ResourceStatus,
        ["powerState"] = PowerState,
        ["powerOnEnable"] = PowerOnEnable == null ? null : JsonValue.Create(PowerOnEnable.Value),
        ["powerOnHint"] = PowerOnHint,
    };
}

public static class EcloudDesktops
{
    // 运行状态归一化词表（desktop_list.py 38-47 逐字对齐）
    private static readonly string[] PowerOnTokens =
        { "running", "active", "available", "on", "up", "1", "normal" };
    private static readonly string[] PowerOffTokens =
        { "shutdown", "shut", "stopped", "stop", "off", "down", "0", "closed", "close", "hibernat", "suspend", "deleted" };
    // 子串兜底：刻意不放裸 "on"/"off"（"shutdown" 会被片段误判）；先判 off（"未开机"含"开机"）
    private static readonly string[] PowerOffSubstr =
        { "shutdown", "stopped", "stopping", "closed", "hibernat", "suspend", "关机", "未开机", "未运行", "停止" };
    private static readonly string[] PowerOnSubstr =
        { "running", "active", "available", "normal", "运行中", "已开机", "开机" };

    /// <summary>
    /// 把服务端 resourceStatus 归一到 on / off / unknown（desktop_list.normalize_power_state）。
    /// 诚实性红线：无法确定时一律 unknown，绝不猜成 off。
    /// </summary>
    public static string NormalizePowerState(string? resourceStatus)
    {
        string s = (resourceStatus ?? "").Trim().ToLowerInvariant();
        if (s == "") return "unknown";
        if (Array.IndexOf(PowerOnTokens, s) >= 0) return "on";
        if (Array.IndexOf(PowerOffTokens, s) >= 0) return "off";
        foreach (var t in PowerOffSubstr) if (s.Contains(t, StringComparison.Ordinal)) return "off";
        foreach (var t in PowerOnSubstr) if (s.Contains(t, StringComparison.Ordinal)) return "on";
        return "unknown";
    }

    /// <summary>拉取桌面列表（get_desktop_list；复刻渲染层 St 函数）。</summary>
    public static async Task<List<EcloudDesktop>> GetDesktopListAsync(EcloudHttpUtil http, CancellationToken ct = default)
    {
        var resp = await http.PostAsync(EcloudConfig.Endpoints.GetDeviceInfo, new JsonObject
        {
            ["companyCode"] = EcloudConfig.CompanyCode,
            ["allCompany"] = true,
            ["version"] = "1.0.0",
        }, ct: ct).ConfigureAwait(false);

        var machineList = resp["machineList"] as JsonArray ?? new JsonArray();
        var desktops = new List<EcloudDesktop>();
        foreach (var node in machineList)
        {
            if (node is not JsonObject m) continue;
            string instanceId = GetStr(m, "instanceId");
            string machineId = GetStr(m, "machineId");
            if (instanceId == "" && machineId == "") continue;

            // 平台操作能力表（machineOperateMap.powerOn）：operateEnable=true ⇒ 平台认为现在可开机，
            // 比 resourceStatus 更贴近真实电源态（状态字段会滞后）。
            bool? powerOnEnable = null;
            string powerOnHint = "";
            if (m["machineOperateMap"] is JsonObject opMap && opMap["powerOn"] is JsonObject pom)
            {
                if (pom["operateEnable"] is JsonValue oe) powerOnEnable = oe.TryGetValue<bool>(out var b) && b;
                if (pom["operateFailReason"] is JsonValue ofr && ofr.TryGetValue<string>(out var h)) powerOnHint = h;
            }

            desktops.Add(new EcloudDesktop(
                InstanceId: instanceId,
                MachineId: machineId,
                MachineName: GetStr(m, "machineName"),
                OriginCompanyCode: GetStr(m, "originCompanyCode"),
                ResourcePoolUid: GetStr(m, "resourcePoolUid"),
                PowerOnEnable: powerOnEnable,
                PowerOnHint: powerOnHint));
        }
        return desktops;
    }

    /// <summary>查询桌面运行状态（get_desktop_status）：{instanceId: resourceStatus}。</summary>
    public static async Task<Dictionary<string, string>> GetDesktopStatusAsync(
        EcloudHttpUtil http, List<EcloudDesktop> desktops, CancellationToken ct = default)
    {
        var result = new Dictionary<string, string>();
        var instanceIds = desktops.Where(d => d.InstanceId != "").Select(d => d.InstanceId).ToList();
        if (instanceIds.Count == 0) return result;

        var arr = new JsonArray();
        foreach (var id in instanceIds) arr.Add(id);
        var resp = await http.PostAsync(EcloudConfig.Endpoints.GetDesktopStatus, new JsonObject
        {
            ["instanceIdList"] = arr,
        }, ct: ct).ConfigureAwait(false);

        var statusList = resp["machineStatusList"] as JsonArray ?? new JsonArray();
        foreach (var node in statusList)
        {
            if (node is not JsonObject s) continue;
            var iid = s["instanceId"] is JsonValue iv && iv.TryGetValue<string>(out var i) ? i : "";
            var st = s["resourceStatus"] is JsonValue sv && sv.TryGetValue<string>(out var v) ? v : "";
            result[iid] = st;
        }
        return result;
    }

    /// <summary>列表 + 状态合并（侧车 op_desktop_list 的输出形态；状态查询失败整批回落 unknown 不抛错）。</summary>
    public static async Task<List<EcloudDesktop>> GetDesktopsWithStatusAsync(EcloudHttpUtil http, CancellationToken ct = default)
    {
        var desktops = await GetDesktopListAsync(http, ct).ConfigureAwait(false);
        Dictionary<string, string> statuses;
        try
        {
            statuses = await GetDesktopStatusAsync(http, desktops, ct).ConfigureAwait(false);
        }
        catch (Exception)
        {
            statuses = new Dictionary<string, string>(); // 状态是增量信息，失败只降级、不抛出
        }
        for (int i = 0; i < desktops.Count; i++)
        {
            var d = desktops[i];
            var raw = statuses.GetValueOrDefault(d.InstanceId, "");
            desktops[i] = d with { ResourceStatus = raw, PowerState = NormalizePowerState(raw) };
        }
        return desktops;
    }

    /// <summary>自动选一个正在运行的桌面（select_running_desktop）：只有明确 on 才选中；状态接口失败回落第一台。</summary>
    public static async Task<EcloudDesktop?> SelectRunningDesktopAsync(EcloudHttpUtil http, CancellationToken ct = default)
    {
        var desktops = await GetDesktopListAsync(http, ct).ConfigureAwait(false);
        if (desktops.Count == 0) return null;
        Dictionary<string, string> statuses;
        try
        {
            statuses = await GetDesktopStatusAsync(http, desktops, ct).ConfigureAwait(false);
        }
        catch (EcloudException)
        {
            return desktops[0]; // 状态接口不可用时保持兼容：返回第一个
        }
        foreach (var d in desktops)
        {
            if (statuses.TryGetValue(d.InstanceId, out var st) && NormalizePowerState(st) == "on")
                return d with { ResourceStatus = st, PowerState = "on" };
        }
        if (statuses.Count > 0) return null; // 没有正在运行的桌面
        return desktops[0];
    }

    private static string GetStr(JsonObject o, string name) =>
        o[name] is JsonValue v && v.TryGetValue<string>(out var s) ? s : "";
}
