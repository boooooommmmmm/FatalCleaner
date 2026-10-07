using System.Text.Json;
using System.Windows.Media.Imaging;
using CleanSweep.Core.Integrity;
using Microsoft.Data.Sqlite;

namespace CleanSweep.App.Services;

/// <summary>发布包自检入口：不装配 AppServices，不访问用户设置、隔离区、服务或联网。</summary>
internal static class PortableDiagnostics
{
    public static int Run()
    {
        try
        {
            var sets = Enum.GetValues<DataKind>().Select(EmbeddedDataSets.Verify).ToArray();
            if (sets.Any(s => !s.Ok)) throw new InvalidDataException(string.Join("; ", sets.Where(s => !s.Ok).Select(s => s.Reason)));
            using var db = new SqliteConnection("Data Source=:memory:");
            db.Open();
            using var cmd = db.CreateCommand();
            cmd.CommandText = "SELECT sqlite_version()";
            var sqlite = cmd.ExecuteScalar();
            var icon = new BitmapImage(new Uri("pack://application:,,,/CleanSweep;component/Assets/FatalCleaner.png"));
            if (icon.PixelWidth == 0) throw new InvalidDataException("图标资源不可用");
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                Ok = true,
                Version = typeof(App).Assembly.GetName().Version?.ToString(),
                BaseDirectory = AppContext.BaseDirectory,
                Executable = System.Environment.ProcessPath,
                Sqlite = sqlite,
                DataSets = sets.Select(s => new { s.Kind, s.Version, Count = s.Contents.Count }),
                IconWidth = icon.PixelWidth,
            }));
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.ToString());
            return 1;
        }
    }
}
