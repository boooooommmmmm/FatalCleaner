using System.Diagnostics;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text.Json;
using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Elevation;
using CleanSweep.Core.Environment;
using CleanSweep.Core.Rules;
using CleanSweep.Core.Safety;
using CleanSweep.Core.Settings;
using CleanSweep.Core.Storage;

namespace CleanSweep.Service;

/// <summary>写在数据目录里的服务配置：允许连接的用户 SID 与客户端可执行文件路径，安装时由安装者写入。</summary>
public sealed class ElevationConfig
{
    public List<string> AllowedSids { get; set; } = new();
    public List<string> AllowedClientExePaths { get; set; } = new();
    public bool RequireSignedClient { get; set; } = true;

    public static string Path => System.IO.Path.Combine(AppPaths.DataDir, "elevation.json");

    public static ElevationConfig Load()
    {
        try
        {
            if (File.Exists(Path)) return JsonSerializer.Deserialize<ElevationConfig>(File.ReadAllText(Path)) ?? new ElevationConfig();
        }
        catch { }
        return new ElevationConfig();
    }

    public void Save()
    {
        AppPaths.EnsureCreated();
        File.WriteAllText(Path, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
    }
}

/// <summary>
/// 提权服务宿主（设计文档 7.4）。以 LocalSystem 运行，只做一件事：在受 ACL 保护的命名管道上接收枚举型指令并交给 Core 执行。
/// 命令行：--install / --uninstall（需要管理员）、--console（前台运行，调试用）、无参数由 SCM 启动。
/// </summary>
public static class Program
{
    public const string ServiceName = "CleanSweepElevation";

    public static int Main(string[] args)
    {
        if (args.Length > 0)
        {
            switch (args[0].ToLowerInvariant())
            {
                case "--install": return Install();
                case "--uninstall": return Uninstall();
                case "--console":
                    using (var host = ElevationHost.Create(Console.WriteLine))
                    {
                        Console.WriteLine($"提权服务前台运行，管道 {host.Server.PipeName}。按回车退出。");
                        Console.ReadLine();
                    }
                    return 0;
                default:
                    Console.Error.WriteLine("用法：CleanSweep.Service [--install | --uninstall | --console]");
                    return 2;
            }
        }

        ServiceBase.Run(new ElevationWindowsService());
        return 0;
    }

    /// <summary>用 sc.exe 注册服务（按需启动，LocalSystem），并把安装者的 SID 与 CleanSweep.exe 路径写入配置。</summary>
    private static int Install()
    {
        if (!ProtectedDirectory.IsElevated())
        {
            Console.Error.WriteLine("需要管理员权限。");
            return 5;
        }
        var exe = System.Environment.ProcessPath!;
        var client = Path.Combine(Path.GetDirectoryName(exe)!, "CleanSweep.exe");
        var config = ElevationConfig.Load();
        var sid = WindowsIdentity.GetCurrent().User?.Value;
        if (sid is not null && !config.AllowedSids.Contains(sid)) config.AllowedSids.Add(sid);
        if (!config.AllowedClientExePaths.Contains(client, StringComparer.OrdinalIgnoreCase)) config.AllowedClientExePaths.Add(client);
        // 未签名的开发构建：签名要求关闭，发布构建（EV 签名）安装器应把它改回 true
        config.RequireSignedClient = Core.Startup.FileSignature.Inspect(client).State is Core.Startup.SignatureState.Signed or Core.Startup.SignatureState.SignedMicrosoft;
        config.Save();

        // 延迟自动启动：装完就能用，重启后也在；普通权限的界面自己启动不了服务
        var rc = Sc($"create {ServiceName} binPath= \"{exe}\" start= delayed-auto obj= LocalSystem DisplayName= \"FatalCleaner 提权服务\"");
        if (rc != 0)
        {
            Console.WriteLine($"sc.exe create 返回 {rc}");
            return rc;
        }
        Sc($"description {ServiceName} \"FatalCleaner 的提权服务：在受保护的命名管道上执行枚举型清理指令。\"");
        var start = Sc($"start {ServiceName}");
        var online = false;
        for (int i = 0; i < 20 && !online; i++)
        {
            Thread.Sleep(500);
            online = ElevationClient.IsAvailableAsync().GetAwaiter().GetResult();
        }
        Console.WriteLine(online ? "已安装并启动，管道在线。" : $"已安装，但服务未能在 10 秒内上线（sc start 返回 {start}）；请查看事件日志或用 --console 前台运行排查。");
        return online ? 0 : 3;
    }

    private static int Uninstall()
    {
        if (!ProtectedDirectory.IsElevated())
        {
            Console.Error.WriteLine("需要管理员权限。");
            return 5;
        }
        Sc($"stop {ServiceName}");
        var rc = Sc($"delete {ServiceName}");
        Console.WriteLine(rc == 0 ? "已卸载。" : $"sc.exe 返回 {rc}");
        return rc;
    }

    private static int Sc(string args)
    {
        var sc = Path.Combine(System.Environment.SystemDirectory, "sc.exe");
        using var p = Process.Start(new ProcessStartInfo(sc, args) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true })!;
        p.WaitForExit(30_000);
        return p.ExitCode;
    }
}

/// <summary>把 Core 服务装配起来并启动管道服务端。</summary>
public sealed class ElevationHost : IDisposable
{
    public required ElevationServer Server { get; init; }
    public required CleanSweepDb Db { get; init; }

    public static ElevationHost Create(Action<string>? console = null)
    {
        AppPaths.EnsureCreated();
        var db = new CleanSweepDb(AppPaths.DbPath);
        var log = new OperationLog(db);
        var env = new CurrentUserEnvironmentResolver();
        var guard = new PathGuard(env);
        var whitelist = new Whitelist(AppPaths.WhitelistPath);
        var quarantine = new Quarantine(db, null, null, guard);
        // 与界面相同的规则来源：每次请求都重新定位（内置或在线更新目录）、重新校验签名、按连接方护栏加载；校验失败一条规则都不加载
        RuleLoadResult LoadRules(PathGuard g)
        {
            var location = Core.Integrity.DataSets.LocateInstalled(Core.Integrity.DataKind.Rules, AppPaths.UpdateDir(Core.Integrity.DataKind.Rules));
            if (!location.Verdict.Ok) log.Write(null, "rules", "signature", location.Directory, 0, false, location.Verdict.Reason);
            return new RuleLoader(g).LoadContents(location.Contents);
        }
        var config = ElevationConfig.Load();

        // 白名单每次请求重新读（界面新加的排除项立即生效）；预动作用真实执行器（规则要求先停服务的照停，恢复失败记日志）
        var preActions = new ServicePreActionRunner
        {
            OnRestoreFailure = msg => log.Write(null, "engine", "restore-service", null, 0, false, msg),
        };
        var ops = new ElevatedOperations(quarantine, log, LoadRules, () => new Whitelist(AppPaths.WhitelistPath), preActions: preActions);
        var server = new ElevationServer(ops, new ElevationServerOptions
        {
            AllowedClientSids = new HashSet<string>(config.AllowedSids),
            AllowedClientExePaths = new HashSet<string>(config.AllowedClientExePaths, StringComparer.OrdinalIgnoreCase),
            RequireSignedClient = config.RequireSignedClient,
            Log = (msg, ok) =>
            {
                console?.Invoke((ok ? "[ok] " : "[!!] ") + msg);
                try { log.Write(null, "elevation", "pipe", null, 0, ok, msg); } catch { }
            },
        });
        server.Start();
        return new ElevationHost { Server = server, Db = db };
    }

    public void Dispose()
    {
        Server.Dispose();
        Db.Dispose();
    }
}

public sealed class ElevationWindowsService : ServiceBase
{
    private ElevationHost? _host;

    public ElevationWindowsService()
    {
        ServiceName = Program.ServiceName;
        CanStop = true;
        CanPauseAndContinue = false;
        AutoLog = true;
    }

    protected override void OnStart(string[] args)
    {
        _host = ElevationHost.Create();
    }

    protected override void OnStop()
    {
        _host?.Dispose();
        _host = null;
    }
}
