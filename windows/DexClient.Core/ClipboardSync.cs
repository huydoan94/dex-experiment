using System.Text;

namespace DexClient.Core;

// Clipboard text between this PC and the phone, as SamsungDeX.exe does it: when
// the window becomes active the PC text goes to the phone ("P <base64>"); when it
// loses focus the phone is asked for its text ("R") and its answer arrives as
// "V <base64>". Text only; the phone keeps at most 131072 characters.
public sealed class ClipboardSync
{
    public const int MaxCharacters = 131072;
    public const string Request = "R";
    // Longest "P"/"V" line: the prefix plus base64 of MaxCharacters UTF-8 characters.
    public static readonly int MaxLineLength = 2 + 4 * ((4 * MaxCharacters + 2) / 3);
    private string? lastShared;
    public long Sent { get; private set; }
    public long Received { get; private set; }

    // The line to send when the window is activated, or null when the PC text is
    // empty or already shared (including text that came from the phone).
    public string? Activated(string? pcText)
    {
        if (string.IsNullOrEmpty(pcText)) return null;
        if (pcText.Length > MaxCharacters) pcText = pcText[..MaxCharacters];
        if (pcText == lastShared) return null;
        lastShared = pcText; Sent++;
        return "P " + Convert.ToBase64String(Encoding.UTF8.GetBytes(pcText));
    }

    // The phone's text from a "V <base64>" line, or null for anything else.
    public string? PhoneLine(string line)
    {
        if (!line.StartsWith("V ", StringComparison.Ordinal) || line.Length > MaxLineLength) return null;
        string text;
        try { text = new UTF8Encoding(false, true).GetString(Convert.FromBase64String(line[2..])); }
        catch (FormatException) { return null; }
        catch (ArgumentException) { return null; }
        if (text.Length == 0 || text.Length > MaxCharacters) return null;
        lastShared = text; Received++;
        return text;
    }
}
