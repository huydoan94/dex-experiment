using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using DexClient.Media;

// Configuration acceptance only: authenticate the direct TLS gateway,
// then dispose it without opening a command, FIFO, ADB or phone channel.
if (args.Length == 3 && args[0] == "--backend-auth-check")
{
    object outcome;
    try
    {
        var settings = BackendSettings.Load(args[1]);
        using var authenticated = await DirectChannel.OpenAsync(settings, "probe", "", CancellationToken.None);
        await authenticated.ReadyAsync("authenticated", CancellationToken.None);
        outcome = new { passed = true, authenticationOnly = true, commandsOpened = 0, phoneAccess = false };
        Environment.ExitCode = 0;
    }
    catch (Exception error)
    {
        outcome = new { passed = false, errorType = error.GetType().Name, authenticationOnly = true, phoneAccess = false };
        Environment.ExitCode = 1;
    }
    File.WriteAllText(args[2], JsonSerializer.Serialize(outcome));
    return;
}

if (args.Length is not (3 or 4)) throw new ArgumentException("native-dir fixture-ts report-json");
int checks = 0;
void Assert(bool condition, string label)
{
    if (!condition) throw new InvalidOperationException(label);
    checks++;
}
void Reject<T>(Action action, string label) where T : Exception
{
    try { action(); }
    catch (T) { checks++; return; }
    throw new InvalidOperationException(label);
}
var native = NativeRuntime.Initialize(args[0]);
Reject<NotSupportedException>(() => NativeRuntime.CheckMajor(1u << 16, 2, "fixture"), "ABI mismatch accepted");
var decoded = SyntheticDecoder.Decode(args[1], CancellationToken.None);
Assert(decoded.Frames == 30, "EOF drain lost delayed frames");
Assert(decoded.Width == 320 && decoded.Height == 180, "Wrong geometry");
Assert(decoded.LastFrame.Bgra.Length == 320 * 180 * 4, "Wrong output length");
Assert(decoded.LastFrame.Bgra.Distinct().Count() > 8, "No test pattern pixels");
using var canceled = new CancellationTokenSource();
canceled.Cancel();
Reject<OperationCanceledException>(() => SyntheticDecoder.Decode(args[1], canceled.Token), "Canceled decode ran");
Reject<FileNotFoundException>(() => SyntheticDecoder.Decode(args[1] + ".absent", CancellationToken.None), "Missing fixture accepted");
string malformed = Path.Combine(Path.GetDirectoryName(args[2])!, "invalid.ts");
File.WriteAllBytes(malformed, new byte[188]);
Reject<InvalidDataException>(() => SyntheticDecoder.Decode(malformed, CancellationToken.None), "Malformed fixture accepted");
Reject<InvalidDataException>(() => SyntheticDecoder.Decode(Path.Combine(Path.GetDirectoryName(args[1])!, "oversized.ts"), CancellationToken.None), "Oversized native frame accepted");
var queue = AudioProbe.CreateQueue();
Assert(queue.BufferLength == 96000, "PCM bound differs from 250 ms");
queue.AddSamples(new byte[queue.BufferLength], 0, queue.BufferLength);
Reject<InvalidOperationException>(() => queue.AddSamples(new byte[8], 0, 8), "PCM overflow accepted");
queue.ClearBuffer();
Assert(queue.BufferedBytes == 0, "PCM clear failed");
byte[] certificateBytes = [1, 2, 3, 4];
Assert(DirectChannel.MatchesCertificate(certificateBytes, SHA256.HashData(certificateBytes)), "Matching certificate pin refused");
Assert(!DirectChannel.MatchesCertificate(certificateBytes, new byte[32]), "Wrong certificate pin accepted");
Assert(!DirectChannel.MatchesCertificate(certificateBytes, []), "Missing certificate pin accepted");
// A bounded finite byte stream follows exactly the same decoder/pixel path.
byte[] fixtureBytes = File.ReadAllBytes(args[1]);
var memoryDecoded = SyntheticDecoder.DecodeMemory(fixtureBytes, fixtureBytes.Length, CancellationToken.None);
Assert(memoryDecoded.Frames == decoded.Frames && memoryDecoded.Width == decoded.Width && memoryDecoded.Height == decoded.Height,
       "Memory AVIO lost frames or geometry");
Assert(memoryDecoded.LastFrame.Bgra.SequenceEqual(decoded.LastFrame.Bgra), "File/memory AVIO pixels differ");
Reject<InvalidDataException>(() => SyntheticDecoder.DecodeMemory([], 0, CancellationToken.None), "Empty memory input accepted");
Reject<InvalidDataException>(() => SyntheticDecoder.DecodeMemory(fixtureBytes, fixtureBytes.Length + 1, CancellationToken.None), "Bad memory length accepted");
Reject<InvalidDataException>(() => SyntheticDecoder.DecodeMemory(new byte[188], 188, CancellationToken.None), "Malformed memory input accepted");
Reject<InvalidDataException>(() => SyntheticDecoder.DecodeMemory(new byte[SyntheticDecoder.MaximumInputBytes + 1], SyntheticDecoder.MaximumInputBytes + 1, CancellationToken.None), "Oversized memory input accepted");
var fragmented = await BoundedTsInput.DecodeAsync(new FragmentedInput(fixtureBytes), CancellationToken.None);
Assert(fragmented.Frames == 30 && fragmented.LastFrame.Bgra.SequenceEqual(decoded.LastFrame.Bgra), "Fragmented input altered decoded pixels");
try
{
    await BoundedTsInput.DecodeAsync(new MemoryStream(new byte[SyntheticDecoder.MaximumInputBytes + 1]), CancellationToken.None);
    throw new InvalidOperationException("Stream byte cap ignored");
}
catch (InvalidDataException) { checks++; }
using (var stopped = new CancellationTokenSource())
{
    stopped.Cancel();
    try
    {
        await BoundedTsInput.DecodeAsync(new MemoryStream(fixtureBytes), stopped.Token);
        throw new InvalidOperationException("Canceled stream decoded");
    }
    catch (OperationCanceledException) { checks++; }
}
// Actual stalled loopback input, not a synchronous fake read hiding cancellation.
using (var streamListener = new TcpListener(IPAddress.Loopback, 0))
{
    streamListener.Start(1);
    using var streamClient = new TcpClient();
    Task<TcpClient> incoming = streamListener.AcceptTcpClientAsync();
    await streamClient.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)streamListener.LocalEndpoint).Port);
    using var streamPeer = await incoming;
    try
    {
        await BoundedTsInput.DecodeAsync(streamClient.GetStream(), CancellationToken.None);
        throw new InvalidOperationException("Stalled input ignored deadline");
    }
    catch (TimeoutException) { checks++; }
}
long continuousVideo = 0, continuousAudio = 0;
bool continuousCancellationObserved = false;
if (args.Length == 4)
{
    long pictures = 0, sound = 0;
    using (var liveDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(10)))
    {
        var live = await Task.Run(() => LiveDecoder.Decode(File.OpenRead(args[3]),
            frame => { if (frame.Bgra.Length != frame.Width * frame.Height * 4) throw new InvalidDataException("Live frame geometry"); pictures++; },
            pcm => { if (pcm.Length % 8 != 0) throw new InvalidDataException("PCM alignment"); sound++; }, liveDeadline.Token));
        continuousVideo = live.VideoFrames; continuousAudio = live.AudioFrames;
        Assert(live.VideoFrames == 150 && pictures == 150, "Continuous decoder retained old 120-frame limit");
        Assert(live.AudioFrames > 0 && sound > 0, "AAC not decoded to PCM");
    }
    VideoFrame? lastLive = null;
    var bFrames = LiveDecoder.Decode(new MemoryStream(fixtureBytes), frame => lastLive = frame, _ => { }, CancellationToken.None);
    Assert(bFrames.VideoFrames == 30 && lastLive!.Bgra.SequenceEqual(decoded.LastFrame.Bgra), $"Live EOF/B-frame drain differs from finite reference: frames={bFrames.VideoFrames}, samePixels={lastLive?.Bgra.SequenceEqual(decoded.LastFrame.Bgra)}");
    Reject<InvalidDataException>(() => LiveDecoder.Decode(new MemoryStream(new byte[188]), _ => { }, _ => { }, CancellationToken.None), "Live malformed TS accepted");
    Reject<InvalidDataException>(() => LiveDecoder.Decode(File.OpenRead(Path.Combine(Path.GetDirectoryName(args[1])!, "oversized.ts")), _ => { }, _ => { }, CancellationToken.None), "Live oversized video accepted");
    byte[] avFixture = File.ReadAllBytes(args[3]);
    using (var fragmentedDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(10)))
    {
        var fragmentedLive = await Task.Run(() => LiveDecoder.Decode(new FragmentedInput(avFixture), _ => { }, _ => { }, fragmentedDeadline.Token));
        Assert(fragmentedLive.VideoFrames == 150 && fragmentedLive.AudioFrames > 0, "Fragmented continuous input failed");
    }
    using (var noData = new TcpListener(IPAddress.Loopback, 0))
    {
        noData.Start(1);
        using var sending = new TcpClient();
        Task<TcpClient> incoming = noData.AcceptTcpClientAsync();
        await sending.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)noData.LocalEndpoint).Port);
        using var acceptedPeer = await incoming;
        using var cancelLive = new CancellationTokenSource();
        var enteredRead = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var decoding = Task.Run(() => LiveDecoder.Decode(new ObservedInput(sending.GetStream(), () => enteredRead.TrySetResult()), _ => { }, _ => { }, cancelLive.Token));
        await enteredRead.Task.WaitAsync(TimeSpan.FromSeconds(3));
        cancelLive.Cancel();
        try { await decoding.WaitAsync(TimeSpan.FromSeconds(3)); throw new InvalidOperationException("Live stalled read ignored cancellation"); }
        catch (OperationCanceledException) { checks++; continuousCancellationObserved = true; }
    }
    using var inputBytes = new MemoryStream();
    await using (var writer = new InputWriter(inputBytes))
    {
        writer.Send(["K d 42", "M 2 10 20", "M 1 10 20"]);
        await writer.CompleteAsync(["K u 42"]);
        Assert(!writer.Failed && writer.LinesWritten == 4, "Input worker did not drain releases");
        Assert(System.Text.Encoding.ASCII.GetString(inputBytes.ToArray()) == "K d 42\nM 2 10 20\nM 1 10 20\nK u 42\n", "Input ordering differs");
    }
}
// A packaged backend.json names its token and media folder relative to itself.
{
    string folder = Directory.CreateTempSubdirectory("dex-settings-").FullName;
    try
    {
        Directory.CreateDirectory(Path.Combine(folder, "media"));
        File.WriteAllText(Path.Combine(folder, "gateway-token"), new string('t', 40));
        File.WriteAllText(Path.Combine(folder, "backend.json"), JsonSerializer.Serialize(new { Host = "backend.example", Port = 7443, TokenFile = "gateway-token",
            CertificateSha256 = Convert.ToBase64String(new byte[32]), NativeDirectory = "media" }));
        string previous = Environment.CurrentDirectory;
        Environment.CurrentDirectory = Path.GetTempPath();
        try
        {
            var relative = BackendSettings.Load(Path.Combine(folder, "backend.json"));
            Assert(relative.TokenFile == Path.Combine(folder, "gateway-token") && relative.NativeDirectory == Path.Combine(folder, "media"), "Relative settings did not resolve beside backend.json");
        }
        finally { Environment.CurrentDirectory = previous; }
    }
    finally { Directory.Delete(folder, true); }
}
// The media clock follows rendered device position, not decode/read-ahead.
var timeline = new PlaybackTimeline();
timeline.Record(100, 2000);
Assert(timeline.At(99) == null && timeline.At(100) == 2000, "Audio clock starts before first PCM");
timeline.Record(300, 5000);
Assert(timeline.At(250) == 2150 && timeline.At(300) == 5000, "Future audio anchor applied early");
var timedPcm = new TimestampedPcmQueue();
timedPcm.Push(new byte[3840], 1000000);
Assert(timedPcm.Read(new byte[1920], 0, 1920) == 1920 && timedPcm.BufferedBytes == 3840 && timedPcm.PrimingBytes == 1920 && timedPcm.PlayedPcmBytes == 0, "Audio started before the jitter buffer filled");
timedPcm.Push(new byte[TimestampedPcmQueue.TargetBytes - 3840], 1010000);
Assert(timedPcm.Read(new byte[1920], 0, 1920) == 1920 && timedPcm.BufferedBytes == TimestampedPcmQueue.TargetBytes - 1920, "Partial timestamped PCM read");
Assert(timedPcm.Timeline.At(5000) == 1000000 && timedPcm.PlayedPcmBytes == 1920, "PCM/device timeline mapping");
timedPcm.Read(new byte[TimestampedPcmQueue.TargetBytes], 0, TimestampedPcmQueue.TargetBytes);
Assert(timedPcm.UnderrunBytes == 1920 && timedPcm.Rebuffers == 1 && timedPcm.BufferedBytes == 0, "Audio underrun must supply silence and rebuffer");
timedPcm.Push(new byte[3840], 2000000);
timedPcm.Read(new byte[1920], 0, 1920);
Assert(timedPcm.PlayedPcmBytes == 1920 + TimestampedPcmQueue.TargetBytes - 1920 && timedPcm.BufferedBytes == 3840, "Rebuffering played a trickle instead of refilling");
for (int i = 0; i < 48000 * 8 * 3 / 10 / 1920; i++) timedPcm.Push(new byte[1920], 2100000 + i * 20000);
Assert(timedPcm.DroppedBytes == 0, "A 300 ms burst after a gap was discarded");
var trimmed = new TimestampedPcmQueue();
for (int i = 0; i < 48000 * 8 * 45 / 100 / 8192 + 1; i++) trimmed.Push(new byte[8192], i * 21333);
Assert(trimmed.TrimmedBytes > 0 && trimmed.BufferedBytes >= TimestampedPcmQueue.TargetBytes && trimmed.BufferedBytes <= TimestampedPcmQueue.HighWaterBytes && trimmed.DroppedBytes == 0, "A start-up burst left audio latency above the high-water mark");
timedPcm.Push(new byte[TimestampedPcmQueue.LimitBytes], 3000000);
timedPcm.Push(new byte[3840], 3600000);
Assert(timedPcm.DroppedBytes > 0 && timedPcm.BufferedBytes <= TimestampedPcmQueue.LimitBytes && timedPcm.BufferedBytes == 3840, "Audio overflow retained stale PCM");
Reject<InvalidDataException>(() => timedPcm.Push(new byte[9], 0), "Unaligned PCM accepted");
Assert(CursorShapes.TryParse("C 1002 0", out int handType) && handType == 1002 && CursorShapes.FromAndroid(handType) == CursorKind.Hand, "Cursor line/hand mapping");
Assert(CursorShapes.FromAndroid(1008) == CursorKind.IBeam && CursorShapes.FromAndroid(1000) == CursorKind.Arrow && CursorShapes.FromAndroid(1014) == CursorKind.SizeWestEast
    && CursorShapes.FromAndroid(1017) == CursorKind.SizeNorthwestSoutheast && CursorShapes.FromAndroid(424242) == CursorKind.Arrow, "Android pointer types map to Windows cursors");
foreach (string bad in new[] { "C 1002", "C 1002 2", "C -1 0", "C 1002 0 x", "X cursor", "C 123456 0", "M 0 1 2" })
    Assert(!CursorShapes.TryParse(bad, out _), "Malformed cursor line accepted: " + bad);
var adaptive = new TimestampedPcmQueue();
const int OneMs = 48000 * 8 / 1000;
void Starve(TimestampedPcmQueue q) { q.Push(new byte[q.CurrentTargetBytes], 0); int all = q.BufferedBytes + 1920; q.Read(new byte[all], 0, all); }
Starve(adaptive);
Assert(adaptive.Rebuffers == 1 && adaptive.CurrentTargetMilliseconds == Playout.TargetMilliseconds + Playout.AudioGrowMilliseconds, "Audio underrun did not enlarge the jitter target");
adaptive.Push(new byte[TimestampedPcmQueue.TargetBytes], 0);
Assert(adaptive.Read(new byte[1920], 0, 1920) == 1920 && adaptive.PlayedPcmBytes == TimestampedPcmQueue.TargetBytes, "Rebuffer used the old, smaller target");
for (int i = 0; i < 20; i++) Starve(adaptive);
Assert(adaptive.CurrentTargetMilliseconds == Playout.AudioMaxTargetMilliseconds && adaptive.PeakTargetMilliseconds == Playout.AudioMaxTargetMilliseconds, "Adaptive audio target is not capped");
var steady = new TimestampedPcmQueue(); Starve(steady);
int grown = steady.CurrentTargetMilliseconds;
var block = new byte[OneMs * 20]; var played = new byte[block.Length];
steady.Push(new byte[steady.CurrentTargetBytes], 0); steady.Read(new byte[OneMs], 0, OneMs);
for (int i = 0; i < Playout.AudioStableSeconds * 50 + 2; i++) { steady.Push(block, null); steady.Read(played, 0, played.Length); }
Assert(steady.Rebuffers == 1 && steady.CurrentTargetMilliseconds == grown - Playout.AudioShrinkMilliseconds, "Quiet audio did not shrink the jitter target");
for (int i = 0; i < 3 * Playout.AudioStableSeconds * 50; i++) { steady.Push(block, null); steady.Read(played, 0, played.Length); }
Assert(steady.CurrentTargetMilliseconds == Playout.TargetMilliseconds, "Adaptive audio target fell below its minimum");
long tick = System.Diagnostics.Stopwatch.GetTimestamp();
VideoFrame Picture(long pts) => new(2, 2, new byte[16], pts) { PresentationMicroseconds = pts };
using (var schedule = new VideoSchedule(7, true))
{
    schedule.Push(Picture(0), tick);
    Assert(schedule.Take(tick, null) == null, "Video did not wait for its fallback clock");
    Assert(schedule.Take(tick + System.Diagnostics.Stopwatch.Frequency * (Playout.TargetMilliseconds / 2) / 1000, null) == null, "Video fallback ignored the playout delay");
    using var firstTimed = schedule.Take(tick + System.Diagnostics.Stopwatch.Frequency * (Playout.TargetMilliseconds + 20) / 1000, null);
    Assert(firstTimed?.PresentationMicroseconds == 0, "Video fallback deadline");
    schedule.Push(Picture(100000), tick);
    Assert(schedule.Take(tick, 30000) == null, "Video shown ahead of audio");
    using var nextTimed = schedule.Take(tick, 100000);
    Assert(nextTimed?.PresentationMicroseconds == 100000 && schedule.UsedAudioClock, "Video ignored rendered audio clock");
    foreach (long pts in new long[] { 133333,166666,200000,233333 }) schedule.Push(Picture(pts), tick);
    using var latestTimed = schedule.Take(tick, 233333);
    Assert(latestTimed?.PresentationMicroseconds == 233333 && schedule.Dropped == 3, "Decoded frame queue/lateness is not bounded");
    for (int i = 0; i < Playout.VideoQueueFrames - 1; i++) schedule.Push(Picture(300000 + i * 33333), tick);
    Assert(schedule.Dropped == 3, "A keyframe-sized video burst was dropped before it was due");
    for (int i = 0; i < Playout.VideoQueueFrames; i++) schedule.Push(Picture(1000000 + i * 33333), tick);
    using var caughtUp = schedule.Take(tick, 0);
    Assert(caughtUp != null && schedule.Resynchronizations == 1, "Late audio/startup burst starves the bounded video queue forever");
}
using (var fast = new VideoSchedule(8, true) { LowLatency = true })
{
    fast.Push(Picture(0), tick); fast.Push(Picture(33333), tick);
    using var newest = fast.Take(tick, null);
    Assert(newest?.PresentationMicroseconds == 33333 && fast.Dropped == 1 && fast.Take(tick, null) == null, "Low-latency video waited or showed a stale picture");
    fast.Push(Picture(66666), tick);
    using var ahead = fast.Take(tick, -100000);
    Assert(ahead?.PresentationMicroseconds == 66666, "Low-latency video waited for the audio clock");
    fast.LowLatency = false; fast.Push(Picture(5000000), tick);
    Assert(fast.Take(tick, 66666) == null, "Switching back to synchronized video ignored the audio clock");
}
if (args.Length == 4)
{
    var buffers = new HashSet<byte[]>(ReferenceEqualityComparer.Instance);
    long? pts = null;
    LiveDecoder.Decode(File.OpenRead(args[3]), frame => { buffers.Add(frame.Bgra); pts = frame.PresentationMicroseconds; frame.Dispose(); }, _ => { }, CancellationToken.None, reuseVideoBuffers: true);
    Assert(buffers.Count == 1 && pts > 1000000, "Live decoder failed exact-size buffer reuse or timestamp rescaling");
}
var hardware = SyntheticDecoder.ProbeHardware();
var report = new { passed = true, checks, continuousVideo, continuousAudio, continuousCancellationObserved, native, decoded.Frames, decoded.Width, decoded.Height,
    lastFrameSha256 = Convert.ToHexString(SHA256.HashData(decoded.LastFrame.Bgra)), hardware,
    note = "Synthetic file/memory/fragmented TS, capped/stalled/canceled input, bounded PCM and certificate-pin checks; no phone pipeline." };
File.WriteAllText(args[2], JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
Console.WriteLine($"PASS: {checks} media/TLS checks");

sealed class FragmentedInput(byte[] bytes) : MemoryStream(bytes, writable: false)
{
    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default) =>
        base.ReadAsync(buffer[..Math.Min(7, buffer.Length)], token);
}

sealed class ObservedInput(Stream inner, Action entered) : Stream
{
    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override int Read(byte[] bytes, int offset, int count) => inner.Read(bytes, offset, count);
    public override ValueTask<int> ReadAsync(Memory<byte> bytes, CancellationToken token = default) { entered(); return inner.ReadAsync(bytes, token); }
    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long length) => throw new NotSupportedException();
    public override void Write(byte[] bytes, int offset, int count) => throw new NotSupportedException();
    protected override void Dispose(bool disposing) { if (disposing) inner.Dispose(); base.Dispose(disposing); }
}
