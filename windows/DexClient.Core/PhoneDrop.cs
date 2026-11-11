using System.Text;

namespace DexClient.Core;

// Files dragged out of the DeX window (backend phone_files): the backend streams
// them as "FN <i> <size> <base64 name>", "FB <base64>"..., "FE" per file, then "FA"
// when all are in, or "FX <reason>". They are written to Folder, the folder the
// user dropped on (see DropMarker). Call Line() from one thread only.
public sealed class PhoneDrop : IDisposable
{
    public string Folder { get; }
    public int Expected { get; }
    public List<string> Files { get; } = [];
    public bool Done { get; private set; }
    public string? Error { get; private set; }
    private FileStream? current;
    private string currentName = "", currentPath = "";
    private long currentSize, written;

    public PhoneDrop(string folder, int expected)
    {
        Folder = folder; Expected = Math.Max(expected, 1);
        Directory.CreateDirectory(folder);
    }

    // Progress for the panel after one line: (text, percent or null, final), or null when nothing changed.
    public (string Text, double? Percent, bool Final)? Line(string line)
    {
        if (Done || Error != null) return null;
        try
        {
            if (line.StartsWith("FB ", StringComparison.Ordinal))
            {
                if (current == null) return Fail("data before a file");
                var data = Convert.FromBase64String(line[3..]);
                if (currentSize >= 0 && written + data.Length > currentSize) return Fail("more data than the file's size");
                current.Write(data);
                written += data.Length;
                return (Receiving(), currentSize > 0 ? Math.Min(100, 100d * written / currentSize) : null, false);
            }
            if (line.StartsWith("FN ", StringComparison.Ordinal))
            {
                var parts = line.Split(' ');
                if (parts.Length != 4 || !long.TryParse(parts[2], out currentSize)) return Fail("bad file header");
                if (Files.Count >= Expected) return Fail("more files than the phone offered");
                currentName = SafeName(Encoding.UTF8.GetString(Convert.FromBase64String(parts[3])));
                string path = Unique(Path.Combine(Folder, currentName));
                current?.Dispose();
                current = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
                Files.Add(path); currentPath = path; written = 0;
                return (Receiving(), currentSize > 0 ? 0 : null, false);
            }
            if (line == "FE") { current?.Dispose(); current = null; currentPath = ""; return null; }
            if (line == "FA")
            {
                current?.Dispose(); current = null; Done = true;
                return (Files.Count == 1 ? $"Received {Path.GetFileName(Files[0])} from the phone" : $"Received {Files.Count} files from the phone", 100, true);
            }
            if (line.StartsWith("FX", StringComparison.Ordinal)) return Fail(line.Length > 3 ? line[3..].Replace('_', ' ') : "transfer failed");
        }
        catch (FormatException) { return Fail("bad data"); }
        catch (IOException error) { return Fail(error.Message); }
        return null;
    }

    private string Receiving() => $"Receiving {currentName}" + (Expected > 1 ? $" ({Math.Min(Files.Count, Expected)} of {Expected})" : "");

    private (string, double?, bool) Fail(string reason)
    {
        current?.Dispose(); current = null; Error = reason;
        // Files go straight into the drop folder: a half-written one is removed.
        if (currentPath.Length > 0) { try { File.Delete(currentPath); } catch (IOException) { } catch (UnauthorizedAccessException) { } Files.Remove(currentPath); currentPath = ""; }
        return ($"Couldn't receive files from the phone: {reason}", null, true);
    }

    public static string SafeName(string name)
    {
        name = name.Replace('\\', '/');
        name = name[(name.LastIndexOf('/') + 1)..];
        foreach (char c in Path.GetInvalidFileNameChars()) name = name.Replace(c, '_');
        name = name.Trim(' ', '.');
        name = name.Length == 0 ? "file" : name.Length > 200 ? name[..200] : name;
        // Windows device names (CON, NUL, COM1, ...) are not files, with or without an extension.
        string stem = name.Split('.')[0].TrimEnd(' ');
        return Reserved.Contains(stem) ? "_" + name : name;
    }

    private static readonly HashSet<string> Reserved = new(
        ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
         .. Enumerable.Range(0, 10).SelectMany(i => new[] { $"COM{i}", $"LPT{i}" }),
         "COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³"], StringComparer.OrdinalIgnoreCase);

    private static string Unique(string path)
    {
        if (!File.Exists(path)) return path;
        string dir = Path.GetDirectoryName(path)!, stem = Path.GetFileNameWithoutExtension(path), ext = Path.GetExtension(path);
        for (int i = 2; ; i++) { string next = Path.Combine(dir, $"{stem} ({i}){ext}"); if (!File.Exists(next)) return next; }
    }

    public void Dispose() { current?.Dispose(); current = null; }
}
