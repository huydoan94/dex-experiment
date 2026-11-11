using System.Diagnostics;
using System.Text.Json;
using DexClient.Core;
using DexClient.Media;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Input;

namespace DexClient.App;

public sealed partial class MainWindow
{
    // Clipboard text, the way SamsungDeX.exe shares it: the PC text goes to the phone
    // when this window becomes active; the phone's text is asked for when it loses focus.
    private ClipboardSync clipboard = new();
    private bool ClipboardActive => liveBackend != null
        && !syntheticLive && !phoneAcceptance && session.CanSendInput;
    private async void ShareClipboardWithPhone()
    {
        if (!ClipboardActive) return;
        string? text = null;
        try
        {
            if (ClipboardFiles.Files(WinRT.Interop.WindowNative.GetWindowHandle(this)) is { } copied)
            {
                if (fileOffer.Offer(FileOffer.Copy, copied, ClipboardFiles.Sequence.ToString()) is string offerLine) Send([offerLine]);
                return;
            }
            var view = Windows.ApplicationModel.DataTransfer.Clipboard.GetContent();
            if (view.Contains(Windows.ApplicationModel.DataTransfer.StandardDataFormats.Text)) text = await view.GetTextAsync();
        }
        catch (Exception) { return; } // Another program may hold the clipboard; try again next activation.
        if (ClipboardActive && clipboard.Activated(text) is string line) Send([line]);
    }
    private void AskPhoneClipboard() { if (ClipboardActive) Send([ClipboardSync.Request]); }
    private void SetPcClipboard(string text)
    {
        try
        {
            var package = new Windows.ApplicationModel.DataTransfer.DataPackage();
            package.SetText(text);
            Windows.ApplicationModel.DataTransfer.Clipboard.SetContent(package);
        }
        catch (Exception) { } // Clipboard busy: the next phone copy is offered again on the next focus change.
    }
}
