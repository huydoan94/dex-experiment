using System.Diagnostics;

namespace DexClient.Core;

// Win32 set-1 scan codes -> the same Linux evdev/KMS line grammar used by
// Python's dex_input.InputState. This class has no UI, transport or phone I/O.
public sealed class DesktopInput
{
    private readonly HashSet<int> keys = [];
    private readonly HashSet<int> buttons = [];
    private readonly Dictionary<int, (int Press, int Release)> codes = new()
    { [1] = (2, 1), [2] = (6, 5), [3] = (4, 3), [4] = (15, 14), [5] = (17, 16) };
    public bool Enabled { get; set; }
    public bool HasButtons => buttons.Count != 0;
    private int x, y;
    private readonly Func<long> clock;
    private long? lastMove;
    private string? pendingMove;
    public DesktopInput(Func<long>? clock = null) { this.clock = clock ?? Stopwatch.GetTimestamp; }
    public string[] FlushMove(bool force = false)
    {
        long now = clock();
        if (pendingMove == null || (!force && lastMove.HasValue && Stopwatch.GetElapsedTime(lastMove.Value, now).TotalSeconds < 1d / 60)) return [];
        string line = pendingMove; pendingMove = null; lastMove = now;
        return [line];
    }
    public static int ScanCode(int scan, bool extended) => extended ? scan switch
    { 0x1c => 96, 0x1d => 97, 0x35 => 98, 0x37 => 99, 0x38 => 100,
      0x47 => 102, 0x48 => 103, 0x49 => 104, 0x4b => 105, 0x4d => 106,
      0x4f => 107, 0x50 => 108, 0x51 => 109, 0x52 => 110, 0x53 => 111,
      0x5b => 125, 0x5c => 126, 0x5d => 127, 0x5e => 116, _ => 0 }
        : scan switch { >= 1 and <= 0x58 => scan, 0x59 => 117, 0x70 => 93, 0x73 => 89,
            0x79 => 92, 0x7b => 94, 0x7d => 124, 0x7e => 121, _ => 0 };
    public string[] Key(int scan, bool extended, bool down, int virtualKey = 0)
    {
        int key = virtualKey switch
        {
            0x13 or 0x03 => 119, // Pause has a special multi-byte set-1 sequence.
            0x90 => 69, 0x2c => 99, // Legacy extended Num Lock / Alt-PrintScreen.
            >= 0x7c and <= 0x87 => 183 + virtualKey - 0x7c, // F13..F24.
            0xad => 113, 0xae => 114, 0xaf => 115, // Volume keys.
            0x15 when scan is 0 or 0x72 or 0xf2 => 122, 0x19 when scan is 0 or 0x71 or 0xf1 => 123, // Korean Hangul/Hanja virtual keys.
            _ => ScanCode(scan, extended)
        };
        if (!Enabled || key == 0 || key is 125 or 126 || (down && key == 62 && (keys.Contains(56) || keys.Contains(100)))) return [];
        // Windows emits some Korean language keys only as a release. Forward
        // one complete tap rather than discarding it as an unmatched key-up.
        if (!down && (key is 122 or 123) && !keys.Contains(key)) return [$"K d {key}", $"K u {key}"];
        if (down ? !keys.Add(key) : !keys.Remove(key)) return [];
        return [$"K {(down ? "d" : "u")} {key}"];
    }
    public string[] Move(double px, double py, double width, double height)
    {
        if (!Enabled || !double.IsFinite(px) || !double.IsFinite(py) || !double.IsFinite(width) || !double.IsFinite(height) || width <= 0 || height <= 0) return [];
        x = Math.Clamp((int)(px * 1920 / width), 0, 1919);
        y = Math.Clamp((int)(py * 1080 / height), 0, 1079);
        pendingMove = $"M 0 {x} {y}";
        return FlushMove();
    }
    public string[] Button(int button, bool down)
    {
        if (!Enabled || !codes.TryGetValue(button, out var pair)) return [];
        if (down ? !buttons.Add(button) : !buttons.Remove(button)) return [];
        pendingMove = null;
        return [$"M {(down ? pair.Press : pair.Release)} {x} {y}"];
    }
    public string[] Wheel(int delta, bool horizontal)
    {
        if (!Enabled) return [];
        return FlushMove(true).Concat(Enumerable.Repeat(
            $"M {(horizontal ? delta > 0 ? 11 : 12 : delta > 0 ? 7 : 8)} {x} {y}", Math.Min(Math.Abs(delta / 120), 5))).ToArray();
    }
    public string[] ReleaseButtons()
    {
        var lines = buttons.Order().Select(button => $"M {codes[button].Release} {x} {y}").ToArray();
        pendingMove = null; buttons.Clear(); return lines;
    }
    public string[] ReleaseAll()
    {
        var lines = keys.Order().Select(key => $"K u {key}").ToList();
        lines.AddRange(ReleaseButtons());
        keys.Clear();
        return lines.ToArray();
    }
}
