using NAudio.CoreAudioApi;
using NAudio.Wave;

namespace DexClient.Media;

public sealed class LiveAudio : IDisposable
{
    private readonly object gate = new();
    private readonly TimestampedPcmQueue queue = new();
    private WasapiOut? output;
    private MMDevice? endpoint;
    private MMDeviceEnumerator? enumerator;
    private bool disposed;
    private Exception? outputFailure;
    public bool Available => output != null;
    public long DroppedBytes => queue.DroppedBytes;
    public long UnderrunBytes => queue.UnderrunBytes;
    public long PrimingBytes => queue.PrimingBytes;
    public long Rebuffers => queue.Rebuffers;
    public int TargetMilliseconds => queue.CurrentTargetMilliseconds;
    public int PeakTargetMilliseconds => queue.PeakTargetMilliseconds;
    public long TrimmedBytes => queue.TrimmedBytes;
    public int BufferedMilliseconds => queue.BufferedBytes / (48000 * 8 / 1000);
    public long PlayedPcmBytes => queue.PlayedPcmBytes;
    public long? PositionMicroseconds
    {
        get
        {
            lock (gate)
            {
                if (disposed || output == null) return null;
                return queue.Timeline.At(output.GetPosition() * 1000000L / output.OutputWaveFormat.AverageBytesPerSecond);
            }
        }
    }
    public LiveAudio()
    {
        try
        {
            enumerator = new MMDeviceEnumerator();
            if (!enumerator.HasDefaultAudioEndpoint(DataFlow.Render, Role.Console)) return;
            endpoint = enumerator.GetDefaultAudioEndpoint(DataFlow.Render, Role.Console);
            output = new WasapiOut(endpoint, AudioClientShareMode.Shared, true, Playout.AudioDeviceMilliseconds);
            output.PlaybackStopped += (_, args) => { if (args.Exception != null) Interlocked.Exchange(ref outputFailure, args.Exception); };
            output.Init(queue); output.Play();
        }
        catch { Dispose(); throw; }
    }
    public void Push(byte[] pcm) => Push(pcm, null);
    public void Push(byte[] pcm, long? pts)
    {
        lock (gate)
        {
            if (Volatile.Read(ref outputFailure) is { } error) throw new IOException("Audio output failed.", error);
            if (!disposed && output != null) queue.Push(pcm, pts);
        }
    }
    public void Dispose()
    {
        lock (gate)
        {
            if (disposed) return;
            disposed = true;
            try { output?.Stop(); }
            finally { output?.Dispose(); output = null; endpoint?.Dispose(); enumerator?.Dispose(); queue.Clear(); }
        }
    }
}
