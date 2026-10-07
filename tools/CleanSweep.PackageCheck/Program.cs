using System.Diagnostics;
using System.IO.Compression;
using System.Reflection;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text.Json;
using CleanSweep.Core.Integrity;

// 用实际旧版 Core 验证新版包。只在指定的新目录中造测试安装，不启动主界面或真实服务。
if (args.Length != 3)
{
    Console.Error.WriteLine("用法：PackageCheck <新版兼容包目录> <旧版 CleanSweep.Core.dll> <新的验收输出目录>");
    return 2;
}
var package = Path.GetFullPath(args[0]);
var legacyDll = Path.GetFullPath(args[1]);
var work = Path.GetFullPath(args[2]);
if (Directory.Exists(work) || File.Exists(work)) throw new IOException("验收输出目录必须不存在，保留历史证据");
Directory.CreateDirectory(work);
var legacyContext = new AssemblyLoadContext("LegacyUpdater", isCollectible: true);
var legacy = legacyContext.LoadFromAssemblyPath(legacyDll);
var oldKeys = (IReadOnlyDictionary<string, byte[]>)legacy.GetType("CleanSweep.Core.Integrity.TrustedKeys")!
    .GetProperty("Current")!.GetValue(null)!;
using var testKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var keys = new Dictionary<string, byte[]>(oldKeys) { ["package-check-only"] = testKey.ExportSubjectPublicKeyInfo() };
var zip = Path.Combine(work, "compatibility.zip");
ZipFile.CreateFromDirectory(package, zip);
var oldExe = Path.Combine(Path.GetDirectoryName(legacyDll)!, "CleanSweep.exe");
var versionText = FileVersionInfo.GetVersionInfo(oldExe).ProductVersion!.Split('+')[0];
var current = Version.Parse(versionText);
var next = new Version(current.Major, current.Minor, current.Build + 1).ToString(3);
var dto = ReleaseManifest.Sign(next, zip, "https://example.invalid/compatibility.zip", "本地兼容验收，临时测试密钥", testKey, "package-check-only");
File.WriteAllText(zip + AppUpdater.ReleaseInfoSuffix, ReleaseManifest.ToJson(dto));
var oldType = legacy.GetType("CleanSweep.Core.Integrity.AppUpdater")!;
var oldUpdater = Activator.CreateInstance(oldType, new object?[] { null, keys })!;
var stageArgs = new object?[] { zip, Path.Combine(work, "legacy-stage"), current, null };
var staged = (string?)oldType.GetMethod("VerifyAndExtract")!.Invoke(oldUpdater, stageArgs);
if (staged is null) throw new InvalidDataException("旧版更新器拒绝新版包：" + stageArgs[3]);

var install = Path.Combine(work, "legacy-install");
Directory.CreateDirectory(install);
File.Copy(oldExe, Path.Combine(install, "CleanSweep.exe"));
File.WriteAllText(Path.Combine(install, "obsolete.dll"), "old owned file");
File.WriteAllText(Path.Combine(install, "personal.txt"), "用户文件必须保留");
AppUpdater.WriteInstallManifest(Path.Combine(install, AppUpdater.InstallManifestName), new[] { "CleanSweep.exe", "obsolete.dll" });
var service = new TestService();
var error = AppUpdater.ApplyStaged(staged, install, service);
if (error is not null) throw new IOException(error);
if (File.Exists(Path.Combine(install, "obsolete.dll"))) throw new IOException("旧清单拥有的废弃文件未清除");
if (File.ReadAllText(Path.Combine(install, "personal.txt")) != "用户文件必须保留") throw new IOException("用户文件被改动");
if (!service.Calls.SequenceEqual(new[] { "stop", "start" })) throw new IOException("服务协调流程不完整");
var legacyProbe = Probe(Path.Combine(install, "CleanSweep.exe"));

var portable = Path.Combine(work, "portable-install");
Directory.CreateDirectory(portable);
File.Copy(Path.Combine(package, "CleanSweep.exe"), Path.Combine(portable, "FatalCleaner.exe"));
File.WriteAllText(Path.Combine(portable, "personal.txt"), "下载目录文件");
error = AppUpdater.ApplyStaged(staged, portable, null, executableName: AppUpdater.PortableExeName);
if (error is not null) throw new IOException(error);
if (!Directory.GetFiles(portable).Select(Path.GetFileName).Order().SequenceEqual(new[] { "FatalCleaner.exe", "personal.txt" }))
    throw new IOException("单文件更新向下载目录写入了额外文件");
if (File.ReadAllText(Path.Combine(portable, "personal.txt")) != "下载目录文件") throw new IOException("下载目录文件被改动");
var portableProbe = Probe(Path.Combine(portable, "FatalCleaner.exe"));
var result = JsonSerializer.Serialize(new
{
    Passed = true,
    LegacyVersion = versionText,
    LegacyCoreSha256 = SignedManifest.HashFile(legacyDll),
    LegacyVerifierAccepted = true,
    LegacyProbe = legacyProbe,
    PortableProbe = portableProbe,
    ServiceCalls = service.Calls,
    Limitation = "临时发布签名仅用于本地验收；服务为测试桩；未执行真实 UAC、SYSTEM 服务或断电恢复",
}, new JsonSerializerOptions { WriteIndented = true });
File.WriteAllText(Path.Combine(work, "result.json"), result);
Console.WriteLine(result);
legacyContext.Unload();
return 0;

static JsonElement Probe(string exe)
{
    using var process = Process.Start(new ProcessStartInfo(exe, "--verify-portable")
    {
        UseShellExecute = false, CreateNoWindow = true,
        RedirectStandardOutput = true, RedirectStandardError = true,
        WorkingDirectory = Path.GetDirectoryName(exe)!,
    })!;
    var stdout = process.StandardOutput.ReadToEndAsync();
    var stderr = process.StandardError.ReadToEndAsync();
    if (!process.WaitForExit(60_000)) { process.Kill(); throw new TimeoutException("产物自检超时"); }
    if (process.ExitCode != 0) throw new IOException(stderr.GetAwaiter().GetResult());
    var result = JsonSerializer.Deserialize<JsonElement>(stdout.GetAwaiter().GetResult());
    if (!result.GetProperty("Ok").GetBoolean()) throw new IOException("产物自检失败");
    return result;
}

sealed class TestService : IUpdateServiceControl
{
    public bool IsInstalled => true;
    public bool IsRunning => true;
    public List<string> Calls { get; } = new();
    public void Stop(TimeSpan timeout) => Calls.Add("stop");
    public void Start(TimeSpan timeout) => Calls.Add("start");
}
