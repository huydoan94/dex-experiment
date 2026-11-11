namespace DexClient.Media;

// Wire limit for the clipboard lines ("P"/"V" + base64 of at most 131072 UTF-8
// characters); DexClient.Core.ClipboardSync builds and parses them.
public static class ClipboardLines
{
    public const int MaxLength = 2 + 4 * ((4 * 131072 + 2) / 3);
    // "B <base64>" file chunk lines (DexClient.Core.FileOffer.ChunkBytes = 49152 bytes).
    public const int MaxChunkLength = 2 + 4 * ((49152 + 2) / 3);
    public static int LimitFor(string line) =>
        line.StartsWith("P ", StringComparison.Ordinal) || line.StartsWith("FO ", StringComparison.Ordinal) ? MaxLength
        : line.StartsWith("B ", StringComparison.Ordinal) ? MaxChunkLength : 64;
}
