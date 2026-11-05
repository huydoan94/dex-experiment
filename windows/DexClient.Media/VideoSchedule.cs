using System.Diagnostics;
namespace DexClient.Media;

// Owns every queued frame. A bounded decoded queue (Playout.VideoQueueFrames)
// absorbs network bursts; overdue pictures are skipped, future pictures wait for
// media time, which runs Playout.TargetMilliseconds behind arrival.
// LowLatency presents the newest decoded picture at the next render tick instead
// of waiting for the audio clock (audio keeps its own jitter buffer and trails).
public sealed class VideoSchedule(long generation, bool synchronize) : IDisposable
{
    private readonly object gate = new();
    private readonly Queue<VideoFrame> frames = new();
    private long? originPts;
    private long originTicks;
    private long? previousPts;
    private bool disposed;
    public long Generation { get; } = generation;
    public long Dropped { get; private set; }
    public long? LastOffsetMicroseconds { get; private set; }
    public long Resynchronizations { get; private set; }
    public bool UsedAudioClock { get; private set; }
    private bool lowLatency;
    public bool LowLatency { get { lock (gate) return lowLatency; } set { lock (gate) lowLatency = value; } }
    public void Push(VideoFrame frame, long now)
    {
        lock (gate)
        {
            if (disposed) { frame.Dispose(); return; }
            if (frame.PresentationMicroseconds is { } pts)
            {
                if (originPts == null || previousPts is { } old && (pts < old - 500000 || pts > old + 2000000))
                { Clear(); originPts = pts; originTicks = now; }
                previousPts = pts;
            }
            while (frames.Count >= (synchronize ? Playout.VideoQueueFrames : 1)) { frames.Dequeue().Dispose(); Dropped++; }
            frames.Enqueue(frame);
        }
    }
    public VideoFrame? Take(long now, long? audioMicroseconds)
    {
        lock (gate)
        {
            if (disposed || frames.Count == 0) return null;
            if (lowLatency || !synchronize || originPts == null)
            {
                var newest = frames.Dequeue();
                while (frames.TryDequeue(out var next)) { newest.Dispose(); Dropped++; newest = next; }
                if (newest.PresentationMicroseconds is { } shown && audioMicroseconds is { } heard) LastOffsetMicroseconds = shown - heard;
                return newest;
            }
            long fallback = originPts.Value + (long)(Stopwatch.GetElapsedTime(originTicks, now).TotalMilliseconds * 1000) - Playout.TargetMilliseconds * 1000L;
            bool validAudio = audioMicroseconds is { } a && Math.Abs(a - fallback) < 2000000;
            long clock = validAudio ? audioMicroseconds!.Value : fallback;
            long reportedClock = clock;
            // A bounded queue must not discard every picture before it becomes
            // due when audio is late or the demux probe releases a startup burst.
            // Catch up visibly instead of freezing forever behind an old clock.
            if (frames.Count == Playout.VideoQueueFrames && frames.Peek().PresentationMicroseconds is { } oldest && oldest > clock + Playout.VideoResyncMilliseconds * 1000L)
            {
                clock = oldest; originPts = oldest + Playout.TargetMilliseconds * 1000L; originTicks = now;
                validAudio = false; Resynchronizations++;
            }
            UsedAudioClock |= validAudio;
            VideoFrame? selected = null;
            while (frames.TryPeek(out var next) && (next.PresentationMicroseconds == null || next.PresentationMicroseconds <= clock + 15000))
            {
                if (selected != null) { selected.Dispose(); Dropped++; }
                selected = frames.Dequeue();
            }
            if (selected?.PresentationMicroseconds is { } pts) LastOffsetMicroseconds = pts - reportedClock;
            return selected;
        }
    }
    private void Clear() { while (frames.TryDequeue(out var frame)) frame.Dispose(); }
    public void Dispose() { lock (gate) { disposed = true; Clear(); } }
}
