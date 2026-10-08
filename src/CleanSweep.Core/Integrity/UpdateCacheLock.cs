using CleanSweep.Core.Cleaning;
using CleanSweep.Core.Safety;

namespace CleanSweep.Core.Integrity;

/// <summary>更新包下载、索引访问与缓存维护共用的跨进程文件锁；失败时不继续操作。</summary>
public static class UpdateCacheLock
{
    public static IDisposable Acquire(string directory)
    {
        var root = PathGuard.Normalize(directory);
        if (PathGuard.AnyAncestorIsReparsePoint(root, Path.GetPathRoot(root)!))
            throw new IOException("更新缓存路径包含目录链接，已保留原文件");
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, ".cache-maintenance.lock");
        if (PathGuard.IsReparsePoint(path)) throw new IOException("更新缓存锁路径异常");
        var stream = new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        if (!PathGuard.IsSamePhysicalPath(path, HandleMove.FinalPath(stream.SafeFileHandle)))
        {
            stream.Dispose();
            throw new IOException("更新缓存真实路径与预期不一致");
        }
        return stream;
    }
}
