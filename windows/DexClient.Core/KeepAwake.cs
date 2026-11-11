namespace DexClient.Core;

// Keeps Windows from sleeping or turning the display off while a session shows a
// picture, as remote-desktop clients do: the phone sends no "media playing" signal,
// and a video in DeX is no keyboard or mouse activity to Windows. Released when the
// session ends or the window is minimized. apply(true/false) is called only on changes.
public sealed class KeepAwake(Action<bool> apply)
{
    private bool streaming, minimized;
    public bool Active { get; private set; }
    public void Streaming(bool value) { streaming = value; Update(); }
    public void Minimized(bool value) { minimized = value; Update(); }
    private void Update()
    {
        bool wanted = streaming && !minimized;
        if (wanted == Active) return;
        Active = wanted;
        apply(wanted);
    }
}
