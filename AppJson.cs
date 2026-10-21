using System.Text.Json.Serialization;

namespace CtyunDashboard;

/// <summary>
/// NativeAOT 的 JSON 元数据入口（source-gen）。
/// 落盘主存储 = SqlSugar + SQLite；这里只保留 DOM 序列化（API 响应）与设置 JSON 列。
/// </summary>
[JsonSourceGenerationOptions(WriteIndented = false)]
[JsonSerializable(typeof(System.Text.Json.Nodes.JsonObject))]
[JsonSerializable(typeof(System.Text.Json.JsonElement))]
[JsonSerializable(typeof(Persist.AppSettings))]
[JsonSerializable(typeof(Persist.NotifyChannel))]
internal partial class AppJson : JsonSerializerContext;
