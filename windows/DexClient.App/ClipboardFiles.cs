using System.Runtime.InteropServices;
using System.Text;

namespace DexClient.App;

// Files copied in Explorer, read from the Win32 clipboard (CF_HDROP): the WinRT
// clipboard did not hand them to this unpackaged app.
internal static class ClipboardFiles
{
    private const uint HDrop = 15;
    [DllImport("user32.dll")] private static extern bool IsClipboardFormatAvailable(uint format);
    [DllImport("user32.dll", SetLastError = true)] private static extern bool OpenClipboard(nint owner);
    [DllImport("user32.dll")] private static extern bool CloseClipboard();
    [DllImport("user32.dll")] private static extern nint GetClipboardData(uint format);
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)] private static extern uint DragQueryFileW(nint drop, uint index, StringBuilder? file, uint size);
    [DllImport("user32.dll")] private static extern uint GetClipboardSequenceNumber();
    // Changes with every copy, even of the same files again.
    public static uint Sequence => GetClipboardSequenceNumber();

    // Plain files on the clipboard, or null when it holds no file list.
    public static List<(string Path, string Name, long Size)>? Files(nint owner)
    {
        if (!IsClipboardFormatAvailable(HDrop) || !OpenClipboard(owner)) return null;
        var paths = new List<string>();
        try
        {
            nint drop = GetClipboardData(HDrop);
            if (drop == 0) return null;
            uint count = DragQueryFileW(drop, 0xFFFFFFFF, null, 0);
            for (uint i = 0; i < count; i++)
            {
                var name = new StringBuilder((int)DragQueryFileW(drop, i, null, 0) + 1);
                if (DragQueryFileW(drop, i, name, (uint)name.Capacity) > 0) paths.Add(name.ToString());
            }
        }
        finally { CloseClipboard(); }
        var files = new List<(string Path, string Name, long Size)>();
        foreach (string path in paths)
            if (File.Exists(path)) files.Add((path, System.IO.Path.GetFileName(path), new FileInfo(path).Length));
        return files;
    }
}
