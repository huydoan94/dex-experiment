using System.Text.Json;

namespace DexClient.Core;

// How the picture is decoded: Hardware decodes and converts on the GPU (falling back
// to the CPU when the GPU cannot); Software decodes and converts on the CPU. Either
// way the picture is shown through the GPU when one is available.
public enum VideoRendering { Hardware, Software }

// Per-user client choices, kept in %LOCALAPPDATA%\DexClient\settings.json. A missing
// or unreadable file gives the defaults; a failed save keeps the current session's choice.
public static class ClientSettings
{
    public static string DefaultPath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DexClient", "settings.json");

    public static VideoRendering LoadRendering(string path)
    {
        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(path));
            if (document.RootElement.TryGetProperty("rendering", out var value) && value.ValueKind == JsonValueKind.String
                && string.Equals(value.GetString(), "software", StringComparison.OrdinalIgnoreCase))
                return VideoRendering.Software;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException) { }
        return VideoRendering.Hardware;
    }

    public static bool SaveRendering(string path, VideoRendering rendering)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            string temporary = path + ".new";
            File.WriteAllText(temporary, JsonSerializer.Serialize(new { rendering = rendering == VideoRendering.Software ? "software" : "hardware" }));
            File.Move(temporary, path, overwrite: true);
            return true;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return false; }
    }
}
