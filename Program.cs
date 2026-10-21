using CtyunDashboard;
using CtyunDashboard.CtYun;

var builder = WebApplication.CreateSlimBuilder(args);

var port = int.TryParse(Environment.GetEnvironmentVariable("PORT"), out var p) ? p : 8571;
builder.WebHost.UseUrls($"http://0.0.0.0:{port}");

// ---- 服务装配（静态定位，规避 AOT 反射 DI） ----
var db = new Db();
db.Init();
Svc.Db = db;
Svc.Logs = new LogHub(db);
Svc.NotifyHubField = new NotifyHub(db, Svc.Logs);
Svc.Engine = new Engine(db, Svc.Logs);
Svc.Scheduler = new Scheduler(db, Svc.Logs);
Svc.StartedAt = DateTime.Now;

var app = builder.Build();

// 可选：托管 Vue 构建产物（单体部署；分离部署由 nginx 提供 web/dist）
var dist = Path.Combine(AppContext.BaseDirectory, "web", "dist");
if (!Directory.Exists(dist)) dist = Path.Combine(Directory.GetCurrentDirectory(), "web", "dist");
if (Directory.Exists(dist))
{
    var fp = new Microsoft.Extensions.FileProviders.PhysicalFileProvider(dist);
    app.UseDefaultFiles(new DefaultFilesOptions { FileProvider = fp });
    app.UseStaticFiles(new StaticFileOptions { FileProvider = fp });
}

Routes.Map(app);

app.Start();
Svc.Logs.Write("info", "System", "", $"服务已启动 http://0.0.0.0:{port} · NativeAOT · 数据目录 {db.DataDir}");
Svc.Engine.Start();
Svc.Scheduler.Start();
app.WaitForShutdown();
