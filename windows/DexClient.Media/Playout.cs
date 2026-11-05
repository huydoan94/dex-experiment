namespace DexClient.Media;

// Jitter buffer sizing. With the backend's pipelined writes and asynchronous
// reads (2026-11-06 S6) a ~245 KB keyframe arrives in ~44 ms against ~35 ms for
// ordinary frames, and >100 ms audio gaps fell from ~30 to 2 per minute; the
// original 200 ms target covered the old ~94 ms keyframe bursts. v4 (80 ms) ran
// with 0 drops and one start-up rebuffer. A fixed 40 ms (v6 sessions A/B) gave
// 11-14 rebuffers per 30 s against ~50 ms arrival delays, so the target adapts:
// it starts at TargetMilliseconds, grows after each underrun and shrinks slowly
// after a quiet stretch, settling at the smallest crackle-free size.
public static class Playout
{
    public const int TargetMilliseconds = 40;
    public const int AudioLimitMilliseconds = 400;
    // A start-up burst can leave the queue far above target; with equal input and
    // output rates it would never drain, so trim back to target above this level.
    public const int AudioHighWaterMarginMilliseconds = 40;
    public const int AudioHighWaterMilliseconds = TargetMilliseconds + AudioHighWaterMarginMilliseconds;
    public const int AudioMaxTargetMilliseconds = 160;
    public const int AudioGrowMilliseconds = 20;
    public const int AudioShrinkMilliseconds = 10;
    public const int AudioStableSeconds = 20;
    // Audio target plus device latency plus one keyframe burst, at 30 fps.
    public const int VideoQueueFrames = 12;
    // Shared-mode WASAPI buffer; the device latency every played sample adds.
    public const int AudioDeviceMilliseconds = 20;
    // Jump the video clock only when it is this far behind the oldest picture.
    public const int VideoResyncMilliseconds = 500;
    // Queue plus decoder, presenter and one in-flight frame.
    public const int VideoBufferFrames = VideoQueueFrames + 4;
}
