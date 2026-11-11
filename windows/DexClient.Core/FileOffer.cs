using System.Text;
using System.Text.Json;

namespace DexClient.Core;

// Files from this PC to the phone (backend file_bridge): "FO <0|1> <base64 JSON
// [[name,size],..]>" offers copied (0) or dropped (1) files; the phone pulls them
// when the user pastes or drops, and each "G <file> <chunk>" request is answered
// with "B <base64 of at most ChunkBytes>" or "BX" when the file cannot be read.
public sealed class FileOffer
{
    public const int Copy = 0, Drag = 1;
    public const int ChunkBytes = 49152;
    public const int MaxFiles = 1000;
    public const string ReadFailed = "BX";
    public const string CancelDrag = "FC";
    public static readonly int MaxChunkLine = 2 + 4 * ((ChunkBytes + 2) / 3);
    private string? lastCopyKey;
    public IReadOnlyList<(string Path, string Name, long Size)> Files { get; private set; } = [];

    // The offer line for these files, or null when there is nothing new to offer.
    // Only plain files are offered (no folders); names never carry a PC path.
    // copyKey identifies one copy action (the clipboard's change counter): copying the
    // same files again is a new copy; clicking in and out without copying is not.
    public string? Offer(int operation, IEnumerable<(string Path, string Name, long Size)> files, string? copyKey = null)
    {
        var list = files.Where(f => IsPlainName(f.Name) && f.Size >= 0).Take(MaxFiles + 1).ToList();
        if (list.Count == 0 || list.Count > MaxFiles) return null;
        string key = copyKey ?? string.Join("\n", list.Select(f => f.Path + "\t" + f.Size));
        if (operation == Copy && key == lastCopyKey) return null;
        if (operation == Copy) lastCopyKey = key;
        Files = list;
        var json = JsonSerializer.Serialize(list.Select(f => new object[] { f.Name, f.Size }));
        return $"FO {operation} " + Convert.ToBase64String(Encoding.UTF8.GetBytes(json));
    }

    public static bool IsPlainName(string name) =>
        name.Length is > 0 and <= 255 && name.IndexOfAny(['/', '\\', '\n', '\r']) < 0 && name is not "." and not "..";

    // Parses "G <file> <chunk>"; false for any other line.
    public static bool TryParseRequest(string line, out int file, out long chunk)
    {
        file = 0; chunk = 0;
        var parts = line.Split(' ');
        return parts.Length == 3 && parts[0] == "G" && int.TryParse(parts[1], out file) && long.TryParse(parts[2], out chunk)
            && file >= 0 && chunk >= 0;
    }

    public static string ChunkLine(ReadOnlySpan<byte> data) => "B " + Convert.ToBase64String(data);

    // Progress from an "S <file> <bytes> <done>" line (bytes the phone accepted):
    // (delivered, total, finished) or null for anything else.
    public (long Delivered, long Total, bool Finished, int File)? Delivered(string line)
    {
        var parts = line.Split(' ');
        if (parts.Length != 4 || parts[0] != "S" || !int.TryParse(parts[1], out int file) || !long.TryParse(parts[2], out long bytes)
            || parts[3] is not ("0" or "1") || file < 0 || file >= Files.Count || bytes < 0 || bytes > Files[file].Size) return null;
        long total = 0, delivered = bytes;
        for (int i = 0; i < Files.Count; i++) { total += Files[i].Size; if (i < file) delivered += Files[i].Size; }
        return (delivered, total, parts[3] == "1" && file == Files.Count - 1, file);
    }
}
