using System.Runtime.InteropServices;

namespace DexClient.App;

// What is physically held right now, read when the window becomes active: a held
// mouse button means a click activated it; held keys belong to the switch (Alt+Tab).
internal static partial class NativeInput
{
    private static readonly int[] MouseButtons = [0x01, 0x02, 0x04, 0x05, 0x06];

    public static bool MouseButtonHeld() => MouseButtons.Any(Held);

    public static List<int> HeldKeys()
    {
        var held = new List<int>();
        for (int key = 0x08; key <= 0xFE; key++) if (Held(key)) held.Add(key);
        return held;
    }

    private static bool Held(int virtualKey) => (GetAsyncKeyState(virtualKey) & 0x8000) != 0;

    [LibraryImport("user32.dll")]
    private static partial short GetAsyncKeyState(int virtualKey);
}
