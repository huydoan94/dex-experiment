using NAudio.Wave;

namespace DexClient.Media;

// Adaptive audio jitter buffer. Playback (re)starts only once the current target
// is queued, so a burst gap is absorbed instead of producing clicks; an empty
// queue rebuffers to the target rather than trickling single chunks. Each
// underrun raises the target (up to Playout.AudioMaxTargetMilliseconds); a
// stretch of Playout.AudioStableSeconds without one lowers it again.
public sealed class TimestampedPcmQueue : IWaveProvider
{
    private sealed class Chunk(byte[] data, long? pts)
    { public readonly byte[] Data = data; public readonly long? Pts = pts; public int Offset; }
    private const int BytesPerSecond = 48000 * 8;
    private readonly object gate = new();
    private readonly Queue<Chunk> chunks = new();
    private long readBytes;
    private int buffered;
    private bool priming = true;
    private int targetBytes = TargetBytes;
    private long stableBytes;
    private const int StepBytes = BytesPerSecond / 1000;
    public WaveFormat WaveFormat { get; } = WaveFormat.CreateIeeeFloatWaveFormat(48000, 2);
    public PlaybackTimeline Timeline { get; } = new();
    public const int TargetBytes = BytesPerSecond / 1000 * Playout.TargetMilliseconds;
    public const int LimitBytes = BytesPerSecond / 1000 * Playout.AudioLimitMilliseconds;
    public const int HighWaterBytes = BytesPerSecond / 1000 * Playout.AudioHighWaterMilliseconds;
    public const int MaxTargetBytes = BytesPerSecond / 1000 * Playout.AudioMaxTargetMilliseconds;
    public int CurrentTargetBytes { get { lock (gate) return targetBytes; } }
    public int CurrentTargetMilliseconds => CurrentTargetBytes / StepBytes;
    public int PeakTargetMilliseconds { get; private set; } = Playout.TargetMilliseconds;
    public long TrimmedBytes { get; private set; }
    public long DroppedBytes { get; private set; }
    public long UnderrunBytes { get; private set; }
    public long PrimingBytes { get; private set; }
    public long Rebuffers { get; private set; }
    public long PlayedPcmBytes { get; private set; }
    public int BufferedBytes { get { lock (gate) return buffered; } }
    public void Push(byte[] data, long? pts)
    {
        if (data.Length % 8 != 0 || data.Length > LimitBytes) throw new InvalidDataException("PCM frame outside bounds.");
        lock (gate)
        {
            while (buffered + data.Length > LimitBytes && chunks.TryDequeue(out var old))
            { int bytes = old.Data.Length - old.Offset; buffered -= bytes; DroppedBytes += bytes; }
            if (data.Length != 0) { chunks.Enqueue(new(data, pts)); buffered += data.Length; }
            if (buffered > targetBytes + Playout.AudioHighWaterMarginMilliseconds * StepBytes)
                while (buffered - (chunks.Peek().Data.Length - chunks.Peek().Offset) >= targetBytes && chunks.Count > 1)
                { var stale = chunks.Dequeue(); int bytes = stale.Data.Length - stale.Offset; buffered -= bytes; TrimmedBytes += bytes; }
        }
    }
    public int Read(byte[] buffer, int offset, int count)
    {
        if (count % 8 != 0) throw new ArgumentException("Unaligned PCM read.");
        lock (gate)
        {
            int copied = 0;
            if (priming && buffered >= targetBytes) priming = false;
            while (!priming && copied < count && chunks.TryPeek(out var chunk))
            {
                if (chunk.Pts is { } pts) Timeline.Record((readBytes + copied) * 1000000 / BytesPerSecond, pts + chunk.Offset * 1000000L / BytesPerSecond);
                int bytes = Math.Min(count - copied, chunk.Data.Length - chunk.Offset);
                Buffer.BlockCopy(chunk.Data, chunk.Offset, buffer, offset + copied, bytes);
                copied += bytes; chunk.Offset += bytes; buffered -= bytes;
                if (chunk.Offset == chunk.Data.Length) chunks.Dequeue();
            }
            Array.Clear(buffer, offset + copied, count - copied);
            if (priming) PrimingBytes += count - copied;
            else if (copied < count)
            {
                UnderrunBytes += count - copied; priming = true; Rebuffers++; stableBytes = 0;
                targetBytes = Math.Min(MaxTargetBytes, targetBytes + Playout.AudioGrowMilliseconds * StepBytes);
                PeakTargetMilliseconds = Math.Max(PeakTargetMilliseconds, targetBytes / StepBytes);
            }
            else if ((stableBytes += copied) >= (long)BytesPerSecond * Playout.AudioStableSeconds)
            {
                stableBytes = 0;
                targetBytes = Math.Max(TargetBytes, targetBytes - Playout.AudioShrinkMilliseconds * StepBytes);
            }
            readBytes += count; PlayedPcmBytes += copied;
            return count; // Keep the shared-mode device alive across network gaps.
        }
    }
    public void Clear() { lock (gate) { chunks.Clear(); buffered = 0; priming = true; } }
}
