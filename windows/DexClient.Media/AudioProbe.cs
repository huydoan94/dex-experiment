using NAudio.CoreAudioApi;
using NAudio.Wave;

namespace DexClient.Media;

public static class AudioProbe
{
    public static async Task<object> PlaySilenceAsync(CancellationToken cancellation, Action? playbackStarted = null)
    {
        // Run without the UI SynchronizationContext: PlaybackStopped completes independently.
        using var enumerator = new MMDeviceEnumerator();
        if (!enumerator.HasDefaultAudioEndpoint(DataFlow.Render, Role.Console))
            return new { available = false, played = false, note = "No default render endpoint." };
        using var endpoint = enumerator.GetDefaultAudioEndpoint(DataFlow.Render, Role.Console);
        var queue = CreateQueue();
        const int duration_ms = 200;
        var silence = new byte[queue.WaveFormat.AverageBytesPerSecond * duration_ms / 1000];
        queue.AddSamples(silence, 0, silence.Length);
        bool eventDriven = true;
        using var output = new WasapiOut(endpoint, AudioClientShareMode.Shared, eventDriven, 50);
        var stopped = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        output.PlaybackStopped += (_, args) =>
        {
            if (args.Exception != null) stopped.TrySetException(args.Exception);
            else stopped.TrySetResult();
        };
        output.Init(queue);
        try
        {
            cancellation.ThrowIfCancellationRequested();
            output.Play();
            playbackStarted?.Invoke();
            await stopped.Task.WaitAsync(TimeSpan.FromSeconds(3), cancellation).ConfigureAwait(false);
            if (queue.BufferedBytes != 0) throw new InvalidDataException("Silence queue not consumed.");
            return new { available = true, played = true, endpoint = endpoint.FriendlyName,
                         duration_ms, queue_limit_ms = 250, bytes = silence.Length };
        }
        finally { output.Stop(); }
    }

    public static BufferedWaveProvider CreateQueue() => new(WaveFormat.CreateIeeeFloatWaveFormat(48000, 2))
    {
        BufferDuration = TimeSpan.FromMilliseconds(250),
        DiscardOnBufferOverflow = false,
        ReadFully = false
    };
}
