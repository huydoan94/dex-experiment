namespace DexClient.Media;

// Maps source-provider read positions to media PTS. Device positions use elapsed
// microseconds, so shared-mode output resampling does not change the time unit.
public sealed class PlaybackTimeline
{
    private readonly object gate = new();
    private readonly Queue<(long Device, long Media)> anchors = new();
    private (long Device, long Media)? current;
    public void Record(long deviceMicroseconds, long mediaMicroseconds)
    {
        lock (gate)
        {
            anchors.Enqueue((deviceMicroseconds, mediaMicroseconds));
            // More than a second of anchors means the device is stalled; do not
            // claim synchronization against a clock that cannot catch up.
            if (anchors.Count > 128) { anchors.Clear(); current = null; }
        }
    }
    public long? At(long deviceMicroseconds)
    {
        lock (gate)
        {
            while (anchors.TryPeek(out var next) && next.Device <= deviceMicroseconds)
                current = anchors.Dequeue();
            return current is { } point ? point.Media + deviceMicroseconds - point.Device : null;
        }
    }
}
