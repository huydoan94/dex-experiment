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
    // Files: copied files are offered when this window becomes active; files dropped
    // on the picture are offered as a drag. The phone pulls them chunk by chunk.
    private FileOffer fileOffer = new();
    private static async Task<List<(string Path, string Name, long Size)>> PlainFilesAsync(IReadOnlyList<Windows.Storage.IStorageItem> items)
    {
        var files = new List<(string Path, string Name, long Size)>();
        foreach (var item in items)
            if (item is Windows.Storage.StorageFile file && !string.IsNullOrEmpty(file.Path))
                files.Add((file.Path, file.Name, (long)(await file.GetBasicPropertiesAsync()).Size));
        return files;
    }
    private DispatcherQueueTimer? transferHide;
    // Bottom progress panel for files going to the phone; a finished or failed
    // transfer stays visible for three seconds.
    private void ShowTransfer(string text, double? percent, bool final)
    {
        TransferText.Text = text;
        TransferBar.IsIndeterminate = percent == null && !final;
        TransferBar.Visibility = percent == null && final ? Visibility.Collapsed : Visibility.Visible;
        if (percent is double value) TransferBar.Value = value;
        TransferPanel.Visibility = Visibility.Visible;
        transferHide ??= DispatcherQueue.CreateTimer();
        transferHide.Stop();
        if (final)
        {
            transferHide.Interval = TimeSpan.FromSeconds(3);
            transferHide.IsRepeating = false;
            transferHide.Tick += HideTransfer;
            transferHide.Start();
        }
    }
    private void HideTransfer(DispatcherQueueTimer timer, object args) { timer.Tick -= HideTransfer; TransferPanel.Visibility = Visibility.Collapsed; }
    // A file drag from Explorer drives the phone's own drag, as SamsungDeX.exe does:
    // on entering the picture the files are offered and the phone's drag starts at the
    // pointer (13); it follows the pointer (9) and drops where the button is released (10).
    private bool fileDragStarted;
    private bool fileDragStarting;
    private long lastFileDragMove;
    private long fileDragStartTick;
    private bool fileDropPending;
    private string? lastFileDragPoint;
    private string? FileDragPoint(DragEventArgs args)
    {
        var point = args.GetPosition(VideoSurface);
        return controls.FilePointer(point.X, point.Y, VideoSurface.ActualWidth, VideoSurface.ActualHeight);
    }
    private async void PictureDragEnter(object sender, DragEventArgs args)
    {
        if (!ClipboardActive || phoneDragActive || fileDragStarted || fileDragStarting || fileDropPending
            || !args.DataView.Contains(Windows.ApplicationModel.DataTransfer.StandardDataFormats.StorageItems)) return;
        args.AcceptedOperation = Windows.ApplicationModel.DataTransfer.DataPackageOperation.Copy;
        var deferral = args.GetDeferral();
        fileDragStarting = true;
        try
        {
            var at = FileDragPoint(args);
            var files = await PlainFilesAsync(await args.DataView.GetStorageItemsAsync());
            if (at != null && ClipboardActive && fileOffer.Offer(FileOffer.Drag, files) is string line)
            {
                Send([line, $"M 13 {at}"]);
                fileDragStarted = true; lastFileDragPoint = at; fileDragStartTick = Environment.TickCount64;
            }
        }
        catch (Exception) { } // Items that cannot be read during the drag are not offered.
        finally { fileDragStarting = false; deferral.Complete(); }
    }
    private void PictureDragOver(object sender, DragEventArgs args)
    {
        if (!ClipboardActive || phoneDragActive || !args.DataView.Contains(Windows.ApplicationModel.DataTransfer.StandardDataFormats.StorageItems)) return;
        args.AcceptedOperation = Windows.ApplicationModel.DataTransfer.DataPackageOperation.Copy;
        if (!fileDragStarted || FileDragPoint(args) is not string at || at == lastFileDragPoint) return;
        long now = Environment.TickCount64;
        if (now - lastFileDragMove < 33) return; // About 30 moves a second.
        lastFileDragMove = now; lastFileDragPoint = at;
        Send([$"M 9 {at}"]);
    }
    // Leaving the picture ends the phone's drag without a drop: the backend empties the
    // phone's file list ("FC"), so the drop that follows becomes a cancel there.
    private void PictureDragLeave(object sender, DragEventArgs args)
    {
        if (!fileDragStarted) return;
        fileDragStarted = false;
        if (ClipboardActive && lastFileDragPoint is string at) Send([FileOffer.CancelDrag, $"M 10 {at}"]);
    }
    private async void PictureDrop(object sender, DragEventArgs args)
    {
        if (!fileDragStarted) return;
        fileDragStarted = false;
        if (!ClipboardActive || (FileDragPoint(args) ?? lastFileDragPoint) is not string at) return;
        long generation = session.Generation;
        fileDropPending = true; // No new drag starts until this drop has gone out.
        try
        {
            foreach (var (delay, line) in FileOffer.DropLines(at, Environment.TickCount64 - fileDragStartTick))
            {
                if (delay > 0) await Task.Delay(delay);
                if (session.Generation != generation || !ClipboardActive) return;
                Send([line]);
            }
        }
        finally { fileDropPending = false; }
    }
    private async Task SendFileChunkAsync(string request, long generation)
    {
        if (!FileOffer.TryParseRequest(request, out int index, out long chunk)) return;
        string line = FileOffer.ReadFailed;
        try
        {
            var files = fileOffer.Files;
            if (index < files.Count)
            {
                var buffer = new byte[FileOffer.ChunkBytes];
                await using var stream = new FileStream(files[index].Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 1, true);
                stream.Position = chunk * FileOffer.ChunkBytes;
                int count = 0, read;
                while (count < buffer.Length && (read = await stream.ReadAsync(buffer.AsMemory(count))) > 0) count += read;
                if (count > 0) line = FileOffer.ChunkLine(buffer.AsSpan(0, count));
                else
                {
                    string name = files[index].Name;
                    DispatcherQueue.TryEnqueue(() => { if (session.Generation == generation) ShowTransfer($"Couldn't send {name}", null, true); });
                }
            }
        }
        catch (Exception) { DispatcherQueue.TryEnqueue(() => ShowTransfer("Couldn't read the file to send", null, true)); }
        DispatcherQueue.TryEnqueue(() => { if (session.Generation == generation) Send([line]); });
    }
}
