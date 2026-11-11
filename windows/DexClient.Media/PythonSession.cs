using System.Text.Json;

namespace DexClient.Media;

public sealed record BackendSettings(string Host, int Port, string TokenFile,
                                     string CertificateSha256, string NativeDirectory)
{
    public static BackendSettings Load(string path)
    {
        var settings = JsonSerializer.Deserialize<BackendSettings>(File.ReadAllText(path)) ?? throw new InvalidDataException("Missing connection settings.");
        string folder = Path.GetDirectoryName(Path.GetFullPath(path))!;
        // Relative paths are beside backend.json, so a packaged copy works from any folder.
        static string Beside(string? path, string folder) => string.IsNullOrWhiteSpace(path) ? "" : Path.GetFullPath(path, folder);
        settings = settings with { TokenFile = Beside(settings.TokenFile, folder), NativeDirectory = Beside(settings.NativeDirectory, folder) };
        if (Uri.CheckHostName(settings.Host) != UriHostNameType.Dns || settings.Port is < 1 or > 65535 ||
            !File.Exists(settings.TokenFile) || !Directory.Exists(settings.NativeDirectory) || settings.Pin().Length != 32)
            throw new InvalidDataException("Choose a DNS backend name, gateway token and native media directory.");
        return settings;
    }
    public byte[] Pin() => Convert.FromBase64String(CertificateSha256);
}

// The existing Python/USB lifecycle is reached through paired, independent TLS
// relays. The client performs no SSH, remote commands, ADB or phone startup.
public sealed class PythonSession : IAsyncDisposable
{
    private DirectChannel? media, input;
    private Task? inputWatch;
    private readonly CancellationTokenSource stopped = new();
    private int disposing;
    public InputWriter Writer { get; private set; } = null!;
    public Stream MediaStream => media?.Stream ?? throw new InvalidOperationException("Not connected.");
    public TcpCounters? MediaCounters => media?.Counters();
    public TcpCounters? InputCounters => input?.Counters();
    public async Task ConnectAsync(BackendSettings settings, CancellationToken cancellation)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(stopped.Token, cancellation);
        string session = Guid.NewGuid().ToString("N");
        try
        {
            // Both are authenticated before the paired gateway claims viewer.lock.
            input = await DirectChannel.OpenAsync(settings, "input", session, linked.Token).ConfigureAwait(false);
            media = await DirectChannel.OpenAsync(settings, "media", session, linked.Token).ConfigureAwait(false);
            await input.ReadyAsync("ready", linked.Token).ConfigureAwait(false);
            await media.ReadyAsync("ready", linked.Token).ConfigureAwait(false);
            linked.Token.ThrowIfCancellationRequested();
            Writer = new InputWriter(input.Stream);
            inputWatch = WatchInputAsync(input.Stream, stopped.Token);
        }
        catch { await DisposeAsync().ConfigureAwait(false); throw; }
    }
    // Ask the gateway for the phone's pointer shapes. Call once, at the first
    // picture and before any other input: only then is the daemon reading its input
    // FIFO (an older gateway ends a session whose input cannot drain within 0.5 s)
    // and relays this line, which the daemon counts as one invalid line.
    public bool RequestCursorShapes() => Writer.Send(new[] { CursorShapes.OptIn });
    // Raised on the input reader's thread with each Android pointer type the phone reports.
    public event Action<int>? CursorChanged;
    // Raised on the input reader's thread with each "V <base64>" phone clipboard line.
    public event Action<string>? PhoneClipboardLine;
    // Raised on the input reader's thread with each "G <file> <chunk>" file request line.
    public event Action<string>? FileRequestLine;
    // Raised with each "S <file> <bytes> <done>" line: bytes of a file the phone accepted.
    public event Action<string>? FileProgressLine;
    public long CursorLines { get; private set; }
    private async Task WatchInputAsync(Stream stream, CancellationToken token)
    {
        // Input is full-duplex TLS: this read also detects peer EOF while the
        // independent background writer sends events. After the opt-in the gateway
        // sends only cursor-shape lines; anything else is ignored.
        var buffer = new byte[16384];
        var line = new System.Text.StringBuilder();
        bool discarding = false;
        while (true)
        {
            int count = await stream.ReadAsync(buffer, token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            if (count == 0) throw new IOException("Input connection ended.");
            for (int i = 0; i < count; i++)
            {
                char c = (char)buffer[i];
                if (c == '\n')
                {
                    if (!discarding && CursorShapes.TryParse(line.ToString(), out int type)) { CursorLines++; CursorChanged?.Invoke(type); }
                    else if (!discarding && line.Length > 2 && line[0] == 'V' && line[1] == ' ') PhoneClipboardLine?.Invoke(line.ToString());
                    else if (!discarding && line.Length > 2 && line[0] == 'G' && line[1] == ' ') FileRequestLine?.Invoke(line.ToString());
                    else if (!discarding && line.Length > 2 && line[0] == 'S' && line[1] == ' ') FileProgressLine?.Invoke(line.ToString());
                    line.Clear(); discarding = false;
                }
                // Cursor lines are short; only a phone clipboard line ("V ...") may be long.
                else if (line.Length < 32 || (line.Length < ClipboardLines.MaxLength && line[0] == 'V' && line[1] == ' ')) line.Append(c);
                else discarding = true;
            }
        }
    }
    public async Task MonitorAsync(CancellationToken cancellation)
    {
        while (!cancellation.IsCancellationRequested)
        {
            if (Writer.Failed) throw new IOException("Input transport failed.");
            if (inputWatch?.IsCompleted == true) await inputWatch.ConfigureAwait(false);
            await Task.Delay(20, cancellation).ConfigureAwait(false);
        }
    }
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposing, 1) != 0) return;
        Exception? failure = null;
        try { if (Writer != null) await Writer.CompleteAsync([]).ConfigureAwait(false); }
        catch (Exception error) { failure = error; }
        stopped.Cancel();
        // EOF closes both gateway relays and the FIFO writer, retaining dexd's
        // held-input release and viewer-left cleanup. Attempt both on any error.
        try { input?.Dispose(); } catch (Exception error) { failure ??= error; }
        try { media?.Dispose(); } catch (Exception error) { failure ??= error; }
        try { if (Writer != null) await Writer.DisposeAsync().ConfigureAwait(false); }
        catch (Exception error) { failure ??= error; }
        if (inputWatch != null)
        {
            try { await inputWatch.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false); }
            catch (Exception error) { if (!inputWatch.IsCompleted) failure ??= error; }
        }
        input = media = null;
        stopped.Dispose();
        if (failure != null) throw new IOException("Backend cleanup did not complete.", failure);
    }
}
