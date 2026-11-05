namespace DexClient.Media;

// Decoder + six queued frames + UI upload. Exact arrays preserve the existing
// pixel-length contract and avoid a new 8.3MB large-object allocation per frame.
internal sealed class VideoBufferPool : IDisposable
{
    private readonly object gate = new();
    private readonly List<byte[]> available = [];
    private int rented;
    private bool disposed;
    public byte[] Rent(int bytes)
    {
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (rented == Playout.VideoBufferFrames) throw new InvalidOperationException("Video buffer ownership exceeded the playout bound.");
            rented++;
            int found = available.FindIndex(b => b.Length == bytes);
            if (found < 0) { available.Clear(); return new byte[bytes]; }
            byte[] result = available[found]; available.RemoveAt(found); return result;
        }
    }
    public void Return(byte[] buffer)
    {
        lock (gate) { rented--; if (!disposed && available.Count < Playout.VideoBufferFrames) available.Add(buffer); }
    }
    public void Dispose() { lock (gate) { disposed = true; available.Clear(); } }
}
