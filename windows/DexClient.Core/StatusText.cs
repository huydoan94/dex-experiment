namespace DexClient.Core;

// What the bottom-left status line shows, and how the app's version is written.
public static class StatusText
{
    // A working session shows nothing there; only a missing audio device is worth a line.
    public static string? Connected(bool audioAvailable) => audioAvailable ? null : "No audio output device";

    // The backend's version as its gateway reported it: printable ASCII, at most 40
    // characters, else "unknown" (also before connecting and with older backends).
    public static string Backend(string? reported) =>
        reported is { Length: > 0 and <= 40 } text && text.All(c => c >= ' ' && c <= '~') ? text : "unknown";

    // Major.minor.patch from the assembly version (the fourth part is always 0).
    public static string Version(Version? version) =>
        version is null ? "unknown" : $"{version.Major}.{version.Minor}.{Math.Max(version.Build, 0)}";
}
