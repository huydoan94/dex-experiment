using System.Text;

namespace DexClient.Media;

// The UI never waits on SSH. Overflow and stale input fail ownership rather
// than silently dropping a key/button release or replaying delayed presses.
public sealed class InputWriter : IAsyncDisposable
{
    private readonly object gate = new();
    private readonly LinkedList<(string Line, long At)> queue = new();
    private readonly SemaphoreSlim ready = new(0, 1);
    private readonly CancellationTokenSource stopped = new();
    private readonly Stream stream;
    private readonly Task worker;
    private bool closing;
    private volatile bool failed;
    public bool Failed => failed;
    public long LinesWritten { get; private set; }
    public long CoalescedMoves { get; private set; }
    public InputWriter(Stream stream) { this.stream = stream; worker = Task.Run(Write); }
    public bool Send(IEnumerable<string> lines)
    {
        lock (gate)
        {
            if (closing || Failed) return false;
            foreach (string line in lines)
            {
                if (line.Length > 64 || line.Contains('\n') || line.Contains('\r')) { failed = true; return false; }
                if (line.StartsWith("M 0 ", StringComparison.Ordinal) && queue.Last?.Value.Line.StartsWith("M 0 ", StringComparison.Ordinal) == true)
                { queue.Last.Value = (line, queue.Last.Value.At); CoalescedMoves++; }
                else if (queue.Count >= 256) { failed = true; queue.Clear(); return false; }
                else queue.AddLast((line, Environment.TickCount64));
            }
            Signal(); return true;
        }
    }
    private void Signal() { if (ready.CurrentCount == 0) ready.Release(); }
    private async Task Write()
    {
        try
        {
            while (true)
            {
                await ready.WaitAsync(stopped.Token).ConfigureAwait(false);
                while (true)
                {
                    (string Line, long At) item;
                    lock (gate)
                    {
                        if (Failed) return;
                        if (queue.First == null) { if (closing) return; break; }
                        item = queue.First.Value; queue.RemoveFirst();
                    }
                    if (Environment.TickCount64 - item.At > 500) throw new TimeoutException("Stale input.");
                    byte[] bytes = Encoding.ASCII.GetBytes(item.Line + "\n");
                    await stream.WriteAsync(bytes, stopped.Token).AsTask().WaitAsync(TimeSpan.FromMilliseconds(500), stopped.Token).ConfigureAwait(false);
                    await stream.FlushAsync(stopped.Token).WaitAsync(TimeSpan.FromMilliseconds(500), stopped.Token).ConfigureAwait(false);
                    LinesWritten++;
                }
            }
        }
        catch (Exception) { lock (gate) { failed = true; queue.Clear(); } }
    }
    public async Task CompleteAsync(IEnumerable<string> releases)
    {
        lock (gate)
        {
            if (!closing)
            {
                var node = queue.First;
                while (node != null) { var next = node.Next; if (node.Value.Line.StartsWith("M 0 ", StringComparison.Ordinal)) queue.Remove(node); node = next; }
                string[] ending = releases.Take(145).ToArray();
                if (ending.Length > 144) failed = true;
                else foreach (string line in ending) queue.AddLast((line, Environment.TickCount64));
                closing = true; Signal();
            }
        }
        try { await worker.WaitAsync(TimeSpan.FromSeconds(1)).ConfigureAwait(false); }
        catch (TimeoutException) { failed = true; stopped.Cancel(); }
    }
    public async ValueTask DisposeAsync()
    {
        await CompleteAsync([]).ConfigureAwait(false);
        stopped.Cancel();
        stream.Dispose(); // EOF permits the existing Python writer-loss release.
        try { await worker.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false); } catch (TimeoutException) { failed = true; }
        if (worker.IsCompleted) { ready.Dispose(); stopped.Dispose(); }
    }
}
