using System.ComponentModel;
using System.Runtime.InteropServices;
using DexClient.Core;

namespace DexClient.App;

// Windows keeps the Windows keys, Alt+Tab, Alt+Esc and Ctrl+Esc for itself, so the
// window never receives them. A low-level keyboard hook on the UI thread takes
// them while this window is in the foreground and the session accepts input, and
// hands them to the phone instead. A key whose press was taken has its release
// taken too, so Windows never sees half a key.
internal sealed class SystemKeyHook : IDisposable
{
    private const int KeyboardLowLevel = 13;
    private const uint Extended = 0x01, Injected = 0x10, AltDown = 0x20, Up = 0x80;
    private const int VkControl = 0x11;
    private delegate nint HookProc(int code, nint wParam, nint lParam);
    [StructLayout(LayoutKind.Sequential)]
    private struct KeyboardInfo { public uint VirtualKey, ScanCode, Flags, Time; public nuint ExtraInfo; }
    [DllImport("user32.dll", SetLastError = true)] private static extern nint SetWindowsHookExW(int id, HookProc proc, nint module, uint thread);
    [DllImport("user32.dll")] private static extern bool UnhookWindowsHookEx(nint hook);
    [DllImport("user32.dll")] private static extern nint CallNextHookEx(nint hook, int code, nint wParam, nint lParam);
    [DllImport("user32.dll")] private static extern nint GetForegroundWindow();
    [DllImport("user32.dll")] private static extern short GetAsyncKeyState(int virtualKey);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern nint GetModuleHandleW(string? name);

    private readonly HookProc callback; // Kept alive for the hook's lifetime.
    private readonly nint window;
    private readonly Func<bool> active;
    private readonly Action<int, bool, bool, int> forward;
    private readonly HashSet<uint> taken = [];
    private nint hook;
    public long Forwarded { get; private set; }

    public SystemKeyHook(nint window, Func<bool> active, Action<int, bool, bool, int> forward)
    {
        this.window = window; this.active = active; this.forward = forward;
        callback = OnKey;
        hook = SetWindowsHookExW(KeyboardLowLevel, callback, GetModuleHandleW(null), 0);
        if (hook == 0) throw new Win32Exception(Marshal.GetLastWin32Error());
    }

    private nint OnKey(int code, nint wParam, nint lParam)
    {
        if (code >= 0)
        {
            var key = Marshal.PtrToStructure<KeyboardInfo>(lParam);
            bool up = (key.Flags & Up) != 0;
            if ((key.Flags & Injected) == 0 && Take(key, up))
            {
                try { forward((int)key.ScanCode, (key.Flags & Extended) != 0, !up, (int)key.VirtualKey); Forwarded++; }
                catch (Exception) { } // Never let an exception cross the native hook boundary.
                return 1;
            }
        }
        return CallNextHookEx(hook, code, wParam, lParam);
    }

    private bool Take(KeyboardInfo key, bool up)
    {
        if (taken.Contains(key.VirtualKey)) { if (up) taken.Remove(key.VirtualKey); return true; }
        if (up || GetForegroundWindow() != window || !active()) return false;
        if (!DesktopInput.CapturesSystemKey((int)key.VirtualKey, (key.Flags & AltDown) != 0, GetAsyncKeyState(VkControl) < 0)) return false;
        taken.Add(key.VirtualKey);
        return true;
    }

    public void Dispose()
    {
        if (hook != 0) { UnhookWindowsHookEx(hook); hook = 0; }
        taken.Clear();
    }
}
