using System.Runtime.InteropServices;
using FFmpeg.AutoGen;

namespace DexClient.Media;

// A fixed byte ring also bounds fragmented inputs: seven-byte reads must not
// exhaust a chunk-count queue intended for 32 KiB reads. Encoded bytes never drop.
public sealed class StreamingTsInput : IDisposable
{
    private readonly object gate = new();
    private readonly byte[] ring = new byte[2 * 1024 * 1024];
    private readonly CancellationTokenSource stopped;
    private readonly Stream stream;
    private readonly Task reader;
    private int head, count;
    private Exception? error;
    private bool ended, disposed;
    private int readTimeout = 120000;
    public Exception? Error => error;
    public void Streaming() => Volatile.Write(ref readTimeout, 10000);
    public StreamingTsInput(Stream stream, CancellationToken cancellation)
    {
        this.stream = stream;
        stopped = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        reader = Task.Run(Read);
    }
    private async Task Read()
    {
        using var close = stopped.Token.Register(() => { lock (gate) Monitor.PulseAll(gate); stream.Dispose(); });
        var buffer = new byte[32768];
        try
        {
            while (true)
            {
                int received = await stream.ReadAsync(buffer, stopped.Token).ConfigureAwait(false);
                if (received == 0) break;
                lock (gate)
                {
                    if (received > ring.Length - count) throw new IOException("Encoded media queue exceeded 2 MiB.");
                    int tail = (head + count) % ring.Length;
                    int first = Math.Min(received, ring.Length - tail);
                    Buffer.BlockCopy(buffer, 0, ring, tail, first);
                    Buffer.BlockCopy(buffer, first, ring, 0, received - first);
                    count += received; Monitor.PulseAll(gate);
                }
            }
        }
        catch (Exception e) { error = e; }
        finally { lock (gate) { ended = true; Monitor.PulseAll(gate); } }
    }
    public unsafe int ReadNative(byte* target, int size)
    {
        if (target == null || size <= 0) return ffmpeg.AVERROR_INVALIDDATA;
        try
        {
            lock (gate)
            {
                while (count == 0 && !ended)
                {
                    stopped.Token.ThrowIfCancellationRequested();
                    if (!Monitor.Wait(gate, Volatile.Read(ref readTimeout))) throw new TimeoutException("Media read deadline exceeded.");
                }
                stopped.Token.ThrowIfCancellationRequested();
                if (error != null) throw new IOException("Media transport failed.", error);
                if (count == 0) return ffmpeg.AVERROR_EOF;
                int take = Math.Min(size, count);
                int first = Math.Min(take, ring.Length - head);
                Marshal.Copy(ring, head, (nint)target, first);
                Marshal.Copy(ring, 0, (nint)(target + first), take - first);
                head = (head + take) % ring.Length; count -= take;
                return take;
            }
        }
        catch (Exception e) { error = e; return ffmpeg.AVERROR_EXIT; }
    }
    public void Dispose()
    {
        if (disposed) return;
        disposed = true; stopped.Cancel(); stream.Dispose();
        try { reader.Wait(TimeSpan.FromSeconds(2)); } catch (AggregateException) { }
        if (!reader.IsCompleted) throw new TimeoutException("Media reader did not stop.");
        stopped.Dispose(); Array.Clear(ring);
    }
}
