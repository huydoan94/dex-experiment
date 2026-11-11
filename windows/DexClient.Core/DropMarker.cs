namespace DexClient.Core;

// Phone files dragged out of the DeX window: Windows gets a real 1-byte placeholder
// file at once (nothing waits for the phone), and after the drop a short-lived watcher
// finds where the placeholder was copied. The phone's files are then written into
// that folder and the placeholder is removed. A drop that is not a folder (an editor,
// for example) is never found, and the transfer is cancelled.
public sealed class DropMarker : IDisposable
{
    public const string Prefix = "phoneFileCopy-";
    public string Name { get; }
    public string Source { get; }
    private readonly List<FileSystemWatcher> watchers = [];
    private readonly TaskCompletionSource<string> found = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public DropMarker(string folder)
    {
        Name = Prefix + Guid.NewGuid().ToString("N")[..12];
        Directory.CreateDirectory(folder);
        Source = Path.Combine(folder, Name);
        File.WriteAllBytes(Source, [0]);
    }

    // Starts watching the given roots (by default every ready fixed or removable drive).
    public void Watch(IEnumerable<string>? roots = null)
    {
        roots ??= DriveInfo.GetDrives().Where(d => d.IsReady && d.DriveType is DriveType.Fixed or DriveType.Removable).Select(d => d.RootDirectory.FullName);
        foreach (string root in roots)
        {
            try
            {
                var watcher = new FileSystemWatcher(root, Name)
                {
                    IncludeSubdirectories = true, NotifyFilter = NotifyFilters.FileName, InternalBufferSize = 65536,
                };
                watcher.Created += Seen; watcher.Renamed += Seen;
                watcher.EnableRaisingEvents = true;
                watchers.Add(watcher);
            }
            catch (Exception) { } // A drive that cannot be watched cannot be the drop target.
        }
    }

    private void Seen(object sender, FileSystemEventArgs args)
    {
        if (!string.Equals(Path.GetFullPath(args.FullPath), Path.GetFullPath(Source), StringComparison.OrdinalIgnoreCase)
            && string.Equals(Path.GetFileName(args.FullPath), Name, StringComparison.OrdinalIgnoreCase))
            found.TrySetResult(args.FullPath);
    }

    // The copied placeholder's path, or null when none appears in time.
    public async Task<string?> WaitAsync(TimeSpan timeout)
    {
        var done = await Task.WhenAny(found.Task, Task.Delay(timeout));
        return done == found.Task ? found.Task.Result : null;
    }

    // Removes a copied placeholder once the copying program has finished with it: the
    // watcher sees the file when the copy starts, and a delete during the copy does not
    // stick. Only a file of at most 1 byte is removed; true when it is gone.
    public static async Task<bool> RemoveAsync(string path, int tries = 40)
    {
        for (int i = 0; i < tries; i++)
        {
            try
            {
                if (!File.Exists(path)) { await Task.Delay(250); if (!File.Exists(path)) return true; continue; }
                using (var held = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None))
                    if (held.Length > 1) return false; // Not ours any more.
                File.Delete(path);
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
            await Task.Delay(250);
        }
        return !File.Exists(path);
    }

    public void Dispose()
    {
        foreach (var watcher in watchers) { watcher.EnableRaisingEvents = false; watcher.Dispose(); }
        watchers.Clear();
        try { File.Delete(Source); } catch (Exception) { }
    }
}
