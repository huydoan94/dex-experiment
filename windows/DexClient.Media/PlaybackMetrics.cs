using System.Diagnostics;
namespace DexClient.Media;

// Fixed-memory, local-monotonic metadata only. No PTS, media or input payloads
// are retained; arrival gaps describe this client, never optical roundtrip.
public sealed class PlaybackMetrics
{
    private sealed class Metric
    {
        public readonly long[] Bins = new long[2002];
        public long Count;
        public double Sum, Max;
        public void Add(double ms) { if (ms < 0 || !double.IsFinite(ms)) return; Bins[Math.Min((int)Math.Ceiling(Math.Min(ms, 2001)), 2001)]++; Count++; Sum += ms; Max = Math.Max(Max, ms); }
        public object Summary()
        {
            int? Percentile(double p) { long n = 0; for (int i = 0; i < Bins.Length; i++) { n += Bins[i]; if (Count > 0 && n >= Math.Ceiling(Count * p)) return i == 2001 ? null : i; } return null; }
            return new { count = Count, meanMs = Count == 0 ? (double?)null : Sum / Count, maxMs = Max,
                p50UpperMs = Percentile(.5), p95UpperMs = Percentile(.95), p99UpperMs = Percentile(.99), over100Ms = Bins.Skip(101).Sum(), over500Ms = Bins.Skip(501).Sum() };
        }
    }
    private readonly object gate = new();
    private readonly Queue<object> events = new();
    private readonly long started = Stopwatch.GetTimestamp();
    private int previousGc2 = GC.CollectionCount(2);
    private int omittedEvents;
    private void Event(string stage, double gapMs, long now)
    {
        if (events.Count == 128) { events.Dequeue(); omittedEvents++; }
        events.Enqueue(new { stage, atMs = Stopwatch.GetElapsedTime(started, now).TotalMilliseconds, gapMs, gc2 = GC.CollectionCount(2) });
    }
    private readonly Dictionary<string, Metric> values = new();
    private readonly Dictionary<string, long> last = new();
    public void Mark(string name)
    {
        long now = Stopwatch.GetTimestamp();
        lock (gate)
        {
            if (last.TryGetValue(name, out long previous))
            {
                double ms = Stopwatch.GetElapsedTime(previous, now).TotalMilliseconds;
                Add(name + "Gap", ms);
                if (ms > 100) Event(name, ms, now);
            }
            int gc2 = GC.CollectionCount(2);
            if (gc2 != previousGc2) { Event("gen2", 0, now); previousGc2 = gc2; }
            last[name] = now;
        }
    }
    public void Add(string name, double ms)
    {
        lock (gate) { if (!values.TryGetValue(name, out var value)) values.Add(name, value = new()); value.Add(ms); }
    }
    public object Summary() { lock (gate) return new { metrics = values.ToDictionary(p => p.Key, p => p.Value.Summary()), events = events.ToArray(), omittedEvents }; }
}

public sealed class MeasuredMediaStream(Stream source, PlaybackMetrics metrics) : Stream
{
    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override int Read(byte[] buffer, int offset, int count) { int bytes = source.Read(buffer, offset, count); if (bytes > 0) metrics.Mark("encoded"); return bytes; }
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default)
    { int bytes = await source.ReadAsync(buffer, token).ConfigureAwait(false); if (bytes > 0) metrics.Mark("encoded"); return bytes; }
    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    protected override void Dispose(bool disposing) { if (disposing) source.Dispose(); base.Dispose(disposing); }
}
