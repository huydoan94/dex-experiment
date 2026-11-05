namespace DexClient.Media;

// The phone reports each pointer-shape change as an Android PointerIcon type
// (DeXonPC MouseIconChangedListener -> MOUSE_CURSOR_CHANGE; Samsung resize types
// are already folded onto 1014-1017 there). The gateway forwards them on the input
// connection as "C <type> <night 0|1>" lines after the client's opt-in.
public enum CursorKind { Arrow, Hand, Help, Wait, Cross, IBeam, No, SizeAll, SizeWestEast, SizeNorthSouth, SizeNortheastSouthwest, SizeNorthwestSoutheast }

public static class CursorShapes
{
    public const string OptIn = "X cursor";
    public static CursorKind FromAndroid(int type) => type switch
    {
        1002 or 1020 or 1021 => CursorKind.Hand,      // hand, grab, grabbing
        1003 => CursorKind.Help,
        1004 => CursorKind.Wait,
        1006 or 1007 => CursorKind.Cross,             // cell, crosshair
        1008 or 1009 => CursorKind.IBeam,             // text, vertical text
        1012 => CursorKind.No,                        // no drop
        1013 => CursorKind.SizeAll,                   // all scroll
        1014 => CursorKind.SizeWestEast,              // horizontal double arrow
        1015 => CursorKind.SizeNorthSouth,            // vertical double arrow
        1016 => CursorKind.SizeNortheastSouthwest,    // top-right diagonal double arrow
        1017 => CursorKind.SizeNorthwestSoutheast,    // top-left diagonal double arrow
        _ => CursorKind.Arrow,                        // arrow, context menu, copy, alias, zoom, null
    };
    public static bool TryParse(string line, out int type)
    {
        type = 0;
        string[] parts = line.Split(' ');
        return parts.Length == 3 && parts[0] == "C" && parts[1].Length is > 0 and <= 5 && parts[1].All(char.IsAsciiDigit)
            && parts[2] is "0" or "1" && int.TryParse(parts[1], out type);
    }
}
