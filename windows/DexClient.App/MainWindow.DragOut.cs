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
    // Files dragged out of the picture (backend phone_files): with the left button held
    // and the pointer leaving the picture, ask the phone ("DP"); if it is dragging files it
    // answers "DS <count>" and a Windows drag of a 1-byte placeholder starts at once, so
    // no drop target waits for the phone. When the placeholder lands in a folder the
    // phone's files are fetched into it ("DD"); any other ending sends "DC".
    private bool dragOutArmed;
    private Microsoft.UI.Input.PointerPoint? dragOutPoint;
    private PhoneDrop? phoneDrop;
    private TaskCompletionSource<List<string>?>? phoneDropDone;
    private void WatchDragOut(Microsoft.UI.Input.PointerPoint point)
    {
        if (!point.Properties.IsLeftButtonPressed || !ClipboardActive) return;
        dragOutPoint = point;
        bool outside = point.Position.X < 0 || point.Position.Y < 0
            || point.Position.X >= VideoSurface.ActualWidth || point.Position.Y >= VideoSurface.ActualHeight;
        if (outside && !dragOutArmed) { dragOutArmed = true; Send(["DP"]); }
    }
    private void PhoneFileLine(string line, long generation)
    {
        if (line.StartsWith("DS ", StringComparison.Ordinal))
        {
            if (int.TryParse(line[3..], out int count) && count > 0)
                DispatcherQueue.TryEnqueue(() => { if (session.Generation == generation) _ = StartPhoneDragAsync(count); });
            return;
        }
        // On the reader thread: file bytes are written here, the panel updates on the UI thread.
        var drop = phoneDrop;
        if (drop?.Line(line) is not { } progress) return;
        if (drop.Done) phoneDropDone?.TrySetResult(drop.Files);
        else if (drop.Error != null) phoneDropDone?.TrySetResult(null);
        DispatcherQueue.TryEnqueue(() => { if (session.Generation == generation) ShowTransfer(progress.Text, progress.Percent, progress.Final); });
    }
    private bool phoneDragActive;
    private async Task StartPhoneDragAsync(int count)
    {
        if (!dragOutArmed || dragOutPoint is not { } point || !ClipboardActive || phoneDragActive) return;
        dragOutArmed = false;
        phoneDragActive = true;
        Send(controls.ReleaseButtons()); // The phone has ended its own drag; its press must not stay down.
        string root = Path.Combine(Path.GetTempPath(), "DexFromPhone");
        DropMarker? marker = null;
        string? copied = null;
        try
        {
            try { foreach (var old in new DirectoryInfo(root).Exists ? new DirectoryInfo(root).GetFiles(DropMarker.Prefix + "*") : []) if (old.CreationTimeUtc < DateTime.UtcNow.AddHours(-1)) old.Delete(); }
            catch (Exception) { } // Old placeholders are only a cleanup nicety.
            marker = new DropMarker(root);
            var item = await Windows.Storage.StorageFile.GetFileFromPathAsync(marker.Source);
            marker.Watch();
            void Starting(UIElement sender, DragStartingEventArgs args)
            {
                args.Data.RequestedOperation = Windows.ApplicationModel.DataTransfer.DataPackageOperation.Copy;
                args.Data.SetStorageItems([item]);
                args.AllowedOperations = Windows.ApplicationModel.DataTransfer.DataPackageOperation.Copy;
            }
            VideoSurface.DragStarting += Starting;
            Windows.ApplicationModel.DataTransfer.DataPackageOperation result;
            try { result = await VideoSurface.StartDragAsync(point); }
            finally { VideoSurface.DragStarting -= Starting; }
            // Explorer copies the placeholder just after the drop; a drop elsewhere never copies it.
            if (result != Windows.ApplicationModel.DataTransfer.DataPackageOperation.None)
                copied = await marker.WaitAsync(TimeSpan.FromSeconds(5));
        }
        catch (Exception) { } // No drag: the phone is told below.
        finally
        {
            marker?.Dispose(); phoneDragActive = false;
            // The phone shows "no drop" while its own drag crosses something, then hands
            // the drag to Windows and never sends a shape again: back to the arrow.
            if (lastCursorType == 1012) { InputSurface.SetShape(CursorKind.Arrow); lastCursorType = 1000; }
        }
        if (copied == null || Path.GetDirectoryName(copied) is not string folder) { Send(["DC"]); return; }
        await ReceivePhoneFilesAsync(count, folder, DropMarker.RemoveAsync(copied));
    }
    private async Task ReceivePhoneFilesAsync(int count, string folder, Task<bool> placeholderRemoved)
    {
        phoneDrop?.Dispose();
        try { phoneDrop = new PhoneDrop(folder, count); }
        catch (Exception error) { Send(["DC"]); ShowTransfer($"Couldn't receive files from the phone: {error.Message}", null, true); return; }
        phoneDropDone = new TaskCompletionSource<List<string>?>(TaskCreationOptions.RunContinuationsAsynchronously);
        ShowTransfer("Getting files from the phone", null, false);
        Send(["DD"]);
        var drop = phoneDrop;
        var done = await Task.WhenAny(phoneDropDone.Task, Task.Delay(TimeSpan.FromMinutes(10)));
        if (done != phoneDropDone.Task)
        {
            // Late lines must not keep writing into the folder: this transfer is over.
            if (phoneDrop == drop) phoneDrop = null;
            drop.Dispose();
            Send(["DC"]);
            ShowTransfer("Couldn't receive files from the phone: no answer", null, true);
        }
        await placeholderRemoved;
    }
}
