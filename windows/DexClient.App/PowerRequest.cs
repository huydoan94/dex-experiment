using System.Runtime.InteropServices;

namespace DexClient.App;

// SetThreadExecutionState holds for the calling thread, so it is always called on the
// UI thread, which lives as long as the window.
internal static partial class PowerRequest
{
    private const uint Continuous = 0x80000000, SystemRequired = 0x1, DisplayRequired = 0x2;

    public static void Apply(bool keepAwake) =>
        SetThreadExecutionState(keepAwake ? Continuous | SystemRequired | DisplayRequired : Continuous);

    [LibraryImport("kernel32.dll")]
    private static partial uint SetThreadExecutionState(uint flags);
}
