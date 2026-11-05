namespace DexClient.Media;

// Owns a trusted .NET cancellable input stream. A finite <=8MiB sample is captured
// in memory before decoding; this is not continuous/live-frame scheduling.
public static class BoundedTsInput
{
    public static async Task<DecodeResult> DecodeAsync(Stream input, CancellationToken cancellation,
                                                       Action? firstFrame = null)
    {
        ArgumentNullException.ThrowIfNull(input);
        using (input)
        using (var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation))
        {
            deadline.CancelAfter(TimeSpan.FromSeconds(8));
            using var closeOnCancel = deadline.Token.Register(input.Dispose);
            byte[] bytes = new byte[SyntheticDecoder.MaximumInputBytes];
            try
            {
                int length = 0;
                while (length < bytes.Length)
                {
                    int count = await input.ReadAsync(bytes.AsMemory(length), deadline.Token).ConfigureAwait(false);
                    if (count == 0) break;
                    length += count;
                }
                if (length == bytes.Length)
                {
                    byte[] extra = new byte[1];
                    if (await input.ReadAsync(extra, deadline.Token).ConfigureAwait(false) != 0)
                        throw new InvalidDataException("TS input exceeds 8 MiB.");
                }
                deadline.Token.ThrowIfCancellationRequested();
                return await Task.Run(() => SyntheticDecoder.DecodeMemory(bytes, length, deadline.Token, firstFrame),
                                      deadline.Token).ConfigureAwait(false);
            }
            catch (Exception error) when (deadline.IsCancellationRequested)
            {
                if (cancellation.IsCancellationRequested) throw new OperationCanceledException(cancellation);
                throw new TimeoutException("Bounded TS input deadline.", error);
            }
            finally { Array.Clear(bytes); }
        }
    }
}
