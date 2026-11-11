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
    private readonly SessionState session = new();
    private readonly DesktopInput controls = new();
    private CancellationTokenSource? liveCancel;
    private Task? liveTask;
    private InputWriter? liveWriter;
    private FramePresenter? livePresenter;
    private VideoSchedule? videoSchedule;
    private LiveAudio? sessionAudio;
    private PlaybackMetrics? playbackMetrics;
    private PythonSession? liveBackend;
    private bool baselineTiming;
    private bool batchAcceptance;
    private int batchIteration;
    private bool focusExerciseCompleted;
    private TaskCompletionSource? firstPicture;
    private bool stoppingLive;
    private bool syntheticLive;
    private bool phoneAcceptance;
    private bool inputHiccupCheck;
    private bool inputCheckCompleted;
    private volatile string playbackPhase = "startup";
    private readonly List<object> inputPhases = new();
    private bool phoneWindowCompleted;
    private long decodedAudioFrames;
    private bool windowActive = true;
    private bool audioAvailable;
    private bool viewportResizeRequested;
    private double initialViewportWidth;
    private bool cancelStreamTest;
    private Exception? presentationError;
    private long decodedFrames, presentedFrames;
    private long cursorChanges; private int lastCursorType = -1;
    private int frameWidth, frameHeight;

    private async void ConnectBackend(object sender, RoutedEventArgs args)
    {
        if (session.State != ConnectionState.Disconnected || mediaRunning) return;
        liveTask = RunBackendAsync(false);
        await liveTask;
    }
    private async void DisconnectBackend(object sender, RoutedEventArgs args) => await StopLiveAsync(false);
    public void BeginStreamTest()
    {
        if (liveTask is { IsCompleted: false }) throw new InvalidOperationException("Already connected.");
        liveTask = RunBackendAsync(true);
    }
    public void BeginPhoneAcceptance()
    {
        // Explicit launch flag is used only by the user-granted bounded live run.
        phoneAcceptance = true;
        string[] args = Environment.GetCommandLineArgs();
        baselineTiming = args.Contains("--baseline-timing");
        inputHiccupCheck = args.Contains("--input-hiccup-check");
        batchAcceptance = args.Contains("--completion-batch");
        _ = RunAcceptanceAsync();
    }
    private async Task RunAcceptanceAsync()
    {
        int count = batchAcceptance ? 2 : 1;
        for (batchIteration = 1; batchIteration <= count; batchIteration++)
        {
            liveTask = RunBackendAsync(false);
            await liveTask;
            if (Environment.ExitCode != 0) break;
            if (batchIteration < count)
            {
                ConnectionStatus.Text = "Reconnecting after backend cleanup…";
                await Task.Delay(TimeSpan.FromSeconds(30), lifetime.Token);
            }
        }
        Close();
    }
    private async Task RunBackendAsync(bool test)
    {
        long generation = session.BeginConnect();
        liveCancel = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
        CancellationToken token = liveCancel.Token;
        var elapsed = Stopwatch.StartNew();
        long allocatedBefore = GC.GetTotalAllocatedBytes();
        int gc2Before = GC.CollectionCount(2);
        var metrics = new PlaybackMetrics(); playbackMetrics = metrics;
        var frames = new VideoSchedule(generation, !test && !baselineTiming) { LowLatency = LowLatencyButton.IsChecked == true }; videoSchedule = frames;
        focusExerciseCompleted = false;
        PythonSession? backend = null;
        LiveAudio? audio = null;
        Stream? source = null;
        MemoryStream? syntheticInput = null;
        Task<LiveDecodeResult>? decoding = null;
        Task? monitoring = null;
        using var monitorStop = CancellationTokenSource.CreateLinkedTokenSource(token);
        bool passed = false, cancellationObserved = false;
        string? failure = null;
        LiveDecodeResult? decoded = null;
        syntheticLive = test; presentationError = null;
        decodedFrames = presentedFrames = decodedAudioFrames = 0; phoneWindowCompleted = false; viewportResizeRequested = false; initialViewportWidth = 0;
        firstPicture = new(TaskCreationOptions.RunContinuationsAsynchronously);
        inputCheckCompleted = false; inputPhases.Clear(); playbackPhase = "startup";
        ConnectButton.IsEnabled = false; DisconnectButton.IsEnabled = true;
        SetSessionShell(true);
        ConnectionStatus.Text = "Connecting…";
        try
        {
            string[] arguments = Environment.GetCommandLineArgs();
            int index = Array.IndexOf(arguments, "--stream-media-test");
            cancelStreamTest = test && arguments.Contains("--stream-cancel-on-frame");
            if (test && (index < 0 || index + 2 >= arguments.Length)) throw new ArgumentException("Synthetic stream arguments required.");
            BackendSettings? settings = test ? null : BackendSettings.Load(Path.GetFullPath(SettingsPath.Text, AppContext.BaseDirectory));
            string native = test ? arguments[index + 1] : settings!.NativeDirectory;
            await Task.Run(() => NativeRuntime.Initialize(native, test ? MediaTrace : null), token);
            if (test)
            {
                source = new FileStream(arguments[index + 2], FileMode.Open, FileAccess.Read, FileShare.Read);
                syntheticInput = new MemoryStream();
                liveWriter = new InputWriter(syntheticInput);
            }
            else
            {
                backend = new PythonSession();
                cursorChanges = 0; lastCursorType = -1;
                // Before ConnectAsync: the reader starts there and may report at once.
                backend.CursorChanged += type => DispatcherQueue.TryEnqueue(() =>
                {
                    if (session.Generation != generation) return;
                    InputSurface.SetShape(CursorShapes.FromAndroid(type)); cursorChanges++; lastCursorType = type;
                });
                clipboard = new ClipboardSync();
                backend.PhoneClipboardLine += line => DispatcherQueue.TryEnqueue(() =>
                {
                    if (session.Generation != generation) return;
                    if (clipboard.PhoneLine(line) is string text) SetPcClipboard(text);
                });
                fileOffer = new FileOffer();
                backend.FileRequestLine += line => _ = SendFileChunkAsync(line, generation);
                backend.FileProgressLine += line => DispatcherQueue.TryEnqueue(() =>
                {
                    if (session.Generation != generation || fileOffer.Delivered(line) is not { } p) return;
                    var files = fileOffer.Files;
                    if (p.Finished) ShowTransfer(files.Count > 1 ? $"Sent {files.Count} files to the phone" : $"Sent {files[0].Name} to the phone", 100, true);
                    else ShowTransfer($"Sending {files[p.File].Name}" + (files.Count > 1 ? $" ({p.File + 1} of {files.Count})" : ""),
                                      p.Total > 0 ? 100d * p.Delivered / p.Total : 0, false);
                });
                await backend.ConnectAsync(settings!, token);
                liveBackend = backend;
                source = backend.MediaStream;
                liveWriter = backend.Writer;
            }
            token.ThrowIfCancellationRequested();
            if (!session.TransportReady(generation) || !session.SessionStarted(generation)) token.ThrowIfCancellationRequested();
            ConnectionStatus.Text = "Starting DeX — waiting for picture…";
            audio = await Task.Run(() => new LiveAudio(), token);
            audioAvailable = audio.Available;
            LiveAudio player = audio; sessionAudio = player;
            source = new MeasuredMediaStream(source, metrics);
            decoding = Task.Run(() => LiveDecoder.Decode(source, frame =>
            {
                Interlocked.Increment(ref decodedFrames); metrics.Mark("decoded");
                if (inputHiccupCheck) metrics.Mark(playbackPhase + "_decoded");
                if (!token.IsCancellationRequested) frames.Push(frame, Stopwatch.GetTimestamp());
                else frame.Dispose();
                if (test) Thread.Sleep(10); // Synthetic pacing only, never in a phone session.
            }, _ => { }, token, reuseVideoBuffers: !baselineTiming,
                timedAudio: (pts, samples) => { Interlocked.Increment(ref decodedAudioFrames); player.Push(samples, pts); if (inputHiccupCheck) metrics.Mark(playbackPhase + "_audio"); }, measure: metrics.Add), token);
            if (backend != null) monitoring = backend.MonitorAsync(monitorStop.Token);
            Task startup = firstPicture.Task.WaitAsync(TimeSpan.FromSeconds(120), token);
            Task first = await Task.WhenAny(decoding, startup, monitoring ?? decoding);
            await first;
            // Test-only: hold the telemetry dialog open over synthetic playback for a screenshot.
            if (test && Environment.GetCommandLineArgs().Contains("--open-telemetry"))
            { OpenTelemetry(this, new RoutedEventArgs()); await Task.Delay(TimeSpan.FromSeconds(5), token); }
            if (!test)
            {
                if (phoneAcceptance)
                {
                    Task window = inputHiccupCheck ? RunInputCheckAsync(token) : Task.Delay(TimeSpan.FromSeconds(batchAcceptance || baselineTiming ? 60 : 30), token);
                    Task end = await Task.WhenAny(decoding, monitoring!, window);
                    await end;
                    if (end == window) { phoneWindowCompleted = true; liveCancel.Cancel(); }
                }
                else
                {
                    Task end = await Task.WhenAny(decoding, monitoring!);
                    await end;
                }
            }
            decoded = await decoding;
            if (test) await Task.Delay(100, token);
            passed = test && decoded.VideoFrames > 120 && decoded.AudioFrames > 0 && presentedFrames > 1 && !liveWriter.Failed;
            ConnectionStatus.Text = "Disconnected";
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        { cancellationObserved = true;
          passed = (test && cancelStreamTest && presentedFrames > 0 || phoneAcceptance && phoneWindowCompleted && presentedFrames > 1 && decodedAudioFrames > 0) && presentationError == null;
          failure = presentationError?.GetType().Name; ConnectionStatus.Text = presentationError == null ? "Disconnected" : "Display failed"; }
        catch (Exception error)
        { failure = error.GetType().Name; ConnectionStatus.Text = "Connection ended: " + error.Message; }
        finally
        {
            session.BeginDisconnect(generation); controls.Enabled = false;
            string[] releases = controls.ReleaseAll();
            try
            {
                if (liveWriter != null) await liveWriter.CompleteAsync(releases);
                liveCancel.Cancel(); monitorStop.Cancel();
                liveBackend = null;
                if (backend != null) await Task.Run(async () => await backend.DisposeAsync());
                else { source?.Dispose(); if (liveWriter != null) await liveWriter.DisposeAsync(); }
                if (decoding != null) { try { await decoding.WaitAsync(TimeSpan.FromSeconds(5)); } catch (OperationCanceledException) { } catch (Exception) when (decoding.IsCompleted) { } }
                if (monitoring != null) { try { await monitoring.WaitAsync(TimeSpan.FromSeconds(2)); } catch (OperationCanceledException) { } catch (IOException) { } }
            }
            catch (Exception error) { failure ??= error.GetType().Name; passed = false; ConnectionStatus.Text = "Session cleanup failed"; }
            bool layoutVerified = livePresenter?.LayoutScaleVerified ?? false;
            bool viewportResized = viewportResizeRequested && Math.Abs(VideoSurface.ActualWidth - initialViewportWidth) > 1;
            var timing = metrics.Summary();
            long audioDrops = audio?.DroppedBytes ?? 0, audioUnderrun = audio?.UnderrunBytes ?? 0, playedPcmBytes = audio?.PlayedPcmBytes ?? 0, audioPriming = audio?.PrimingBytes ?? 0, audioRebuffers = audio?.Rebuffers ?? 0, audioTrimmed = audio?.TrimmedBytes ?? 0;
            int audioTargetEndMs = audio?.TargetMilliseconds ?? 0, audioTargetPeakMs = audio?.PeakTargetMilliseconds ?? 0;
            audio?.Dispose(); sessionAudio = null; livePresenter?.Dispose(); livePresenter = null;
            frames.Dispose(); videoSchedule = null;
            long writtenInput = liveWriter?.LinesWritten ?? 0;
            liveWriter = null; liveCancel.Dispose(); liveCancel = null;
            if (decoding?.IsCompleted != false) session.Closed(generation);
            ConnectButton.IsEnabled = session.State == ConnectionState.Disconnected; DisconnectButton.IsEnabled = false;
            SetSessionShell(false);
            InputSurface.SetShape(CursorKind.Arrow);
            if (phoneAcceptance)
            {
                passed &= failure == null && (inputHiccupCheck ? inputCheckCompleted && writtenInput >= 100 : writtenInput == 3) && layoutVerified && decoding?.IsCompleted == true && (!batchAcceptance || focusExerciseCompleted);
                var report = new { passed, phoneWindowCompleted, canceled = cancellationObserved,
                    decodedFrames, presentedFrames, audioFrames = decodedAudioFrames, writtenInput,
                    audioAvailable, layoutVerified, focusExerciseCompleted, baselineTiming, batchIteration,
                    inputHiccupCheck, inputCheckCompleted, inputPhases, transport = "direct_tls_pair",
                    width = frameWidth, height = frameHeight, audioDrops, audioUnderrun, audioPriming, audioRebuffers, audioTrimmed, playedPcmBytes, playoutTargetMs = Playout.TargetMilliseconds, audioDeviceMs = Playout.AudioDeviceMilliseconds, audioTargetEndMs, audioTargetPeakMs,
                    framesDropped = frames.Dropped, resynchronizations = frames.Resynchronizations, audioClockUsed = frames.UsedAudioClock, lowLatencyVideo = frames.LowLatency, cursorChanges, lastCursorType, avOffsetLastMs = frames.LastOffsetMicroseconds / 1000.0,
                    allocatedBytes = GC.GetTotalAllocatedBytes() - allocatedBefore, gen2Collections = GC.CollectionCount(2) - gc2Before,
                    timing, failure, elapsedSeconds = elapsed.Elapsed.TotalSeconds,
                    note = "User-granted Python backend session; bounded window, hover and Shift only; no media retained; timing is local software metadata." };
                File.WriteAllText(Path.Combine(AppContext.BaseDirectory, batchAcceptance ? $"phone-result-{batchIteration}.json" : "phone-result.json"), JsonSerializer.Serialize(report));
                Environment.ExitCode = passed ? 0 : 1;
            }
            if (test)
            {
                bool inputReleased = System.Text.Encoding.ASCII.GetString(syntheticInput?.ToArray() ?? []).EndsWith("K u 42\n", StringComparison.Ordinal);
                passed &= layoutVerified && (cancelStreamTest || viewportResized);
                passed &= inputReleased && (cancelStreamTest ? cancellationObserved && writtenInput is 2 or 3 : !cancellationObserved && writtenInput == 3);
                var report = new { passed, canceled = cancellationObserved, decodedFrames, presentedFrames, audioFrames = decoded?.AudioFrames,
                    writtenInput, inputReleased, audioAvailable, layoutVerified, viewportResized,
                    failure, elapsedSeconds = elapsed.Elapsed.TotalSeconds,
                    note = "Continuous synthetic H264/AAC into the native app; no backend/phone connection." };
                File.WriteAllText(Path.Combine(AppContext.BaseDirectory, "stream-result.json"), JsonSerializer.Serialize(report));
                Environment.ExitCode = passed ? 0 : 1;
            }
        }
        if (test) Close();
    }
    private async Task StopLiveAsync(bool closeWindow)
    {
        if (stoppingLive) return;
        stoppingLive = true;
        try
        {
            controls.Enabled = false; session.BeginDisconnect(session.Generation);
            if (liveWriter != null) await liveWriter.CompleteAsync(controls.ReleaseAll());
            liveCancel?.Cancel();
            if (liveTask != null) await liveTask.WaitAsync(TimeSpan.FromSeconds(12));
            if (closeWindow) Close();
        }
        catch (Exception) { ConnectionStatus.Text = "Waiting for session cleanup"; }
        finally { stoppingLive = false; }
    }
    private void RenderLive()
    {
        if (session.CanSendInput && windowActive) Send(controls.FlushMove());
        var frames = videoSchedule;
        if (frames == null || frames.Generation != session.Generation || session.State is ConnectionState.Disconnecting or ConnectionState.Disconnected) return;
        try
        {
            using VideoFrame? frame = frames.Take(Stopwatch.GetTimestamp(), sessionAudio?.PositionMicroseconds);
            if (frame == null) return;
            if (livePresenter == null || frame.Width != frameWidth || frame.Height != frameHeight)
            {
                livePresenter?.Dispose();
                nint panel = ((WinRT.IWinRTObject)VideoSurface).NativeObject.ThisPtr;
                livePresenter = new FramePresenter(panel, frame.Width, frame.Height, PresentationMode.PreferHardware);
                frameWidth = frame.Width; frameHeight = frame.Height;
                LayoutVideo();
                livePresenter.SetLayoutSize(VideoSurface.ActualWidth, VideoSurface.ActualHeight);
            }
            long presenting = Stopwatch.GetTimestamp();
            livePresenter.PresentLive(frame); presentedFrames++;
            playbackMetrics?.Mark("presented");
            if (inputHiccupCheck) playbackMetrics?.Mark(playbackPhase + "_presented");
            playbackMetrics?.Add("uploadPresent", Stopwatch.GetElapsedTime(presenting).TotalMilliseconds);
            if (frames.LastOffsetMicroseconds is { } delta) playbackMetrics?.Add("avOffsetAbsolute", Math.Abs(delta) / 1000d);
            if (syntheticLive && !cancelStreamTest && presentedFrames == 2)
            {
                viewportResizeRequested = true; initialViewportWidth = VideoSurface.ActualWidth;
                VideoSurface.Width = initialViewportWidth * .8;
                VideoSurface.Height = VideoSurface.ActualHeight * .8;
            }
            Placeholder.Visibility = Visibility.Collapsed;
            if (session.PictureReady(session.Generation))
            {
                liveBackend?.RequestCursorShapes();
                controls.Enabled = true; ConnectionStatus.Text = audioAvailable ? "Connected" : "Connected — no audio output device";
                InputSurface.Focus(FocusState.Programmatic);
                if (windowActive) ShareClipboardWithPhone(); // After the cursor opt-in line.
                firstPicture?.TrySetResult();
                if (syntheticLive || phoneAcceptance)
                {
                    Send(controls.Move(VideoSurface.ActualWidth / 2, VideoSurface.ActualHeight / 2, VideoSurface.ActualWidth, VideoSurface.ActualHeight));
                    Send(controls.Key(0x2a, false, true));
                    if (cancelStreamTest) _ = StopLiveAsync(false);
                    else if (batchAcceptance)
                    {
                        // Exercise the same focus-loss release path, without a
                        // click, character or shortcut on the phone.
                        ReleaseFocusedInput();
                        focusExerciseCompleted = controls.ReleaseAll().Length == 0;
                        InputSurface.Focus(FocusState.Programmatic);
                    }
                    else Send(controls.Key(0x2a, false, false));
                }
            }
        }
        catch (Exception error)
        { presentationError = error; firstPicture?.TrySetException(error); liveCancel?.Cancel(); }
    }
    private async Task RunInputCheckAsync(CancellationToken token)
    {
        try
        {
            foreach (var (name, seconds, active) in new[] { ("idle_before", 5, false), ("input", 10, true), ("idle_after", 5, false) })
            {
                playbackPhase = name;
                long video = Interlocked.Read(ref decodedFrames), audio = Interlocked.Read(ref decodedAudioFrames), pictures = presentedFrames;
                long lines = liveWriter?.LinesWritten ?? 0;
                var clock = Stopwatch.StartNew();
                int keyStep = 0;
                while (clock.Elapsed.TotalSeconds < seconds)
                {
                    token.ThrowIfCancellationRequested();
                    if (active)
                    {
                        controls.Enabled = true;
                        double t = clock.Elapsed.TotalSeconds;
                        Send(controls.Move(VideoSurface.ActualWidth / 2 + 30 * Math.Sin(t * 3), VideoSurface.ActualHeight / 2,
                                           VideoSurface.ActualWidth, VideoSurface.ActualHeight));
                        int step = (int)(t * 10);
                        if (step >= keyStep && keyStep < 100)
                        {
                            Send(controls.Key(0x2a, false, keyStep % 2 == 0));
                            keyStep++;
                        }
                    }
                    await Task.Delay(33, token);
                }
                if (active) Send(controls.ReleaseAll());
                inputPhases.Add(new { name, seconds = clock.Elapsed.TotalSeconds,
                    video = Interlocked.Read(ref decodedFrames) - video, audio = Interlocked.Read(ref decodedAudioFrames) - audio,
                    presented = presentedFrames - pictures, inputLines = (liveWriter?.LinesWritten ?? 0) - lines });
            }
            inputCheckCompleted = true;
        }
        finally { Send(controls.ReleaseAll()); playbackPhase = "cleanup"; }
    }
    private void LayoutVideo()
    {
        if (VideoSurface == null || VideoHost.ActualWidth <= 0 || VideoHost.ActualHeight <= 0) return;
        double width = Math.Min(VideoHost.ActualWidth, VideoHost.ActualHeight * 16 / 9);
        VideoSurface.Width = width; VideoSurface.Height = width * 9 / 16;
    }
    private void VideoSurfaceSizeChanged(object sender, SizeChangedEventArgs args)
    {
        try { livePresenter?.SetLayoutSize(args.NewSize.Width, args.NewSize.Height); }
        catch (Exception error) { presentationError = error; firstPicture?.TrySetException(error); liveCancel?.Cancel(); }
    }
    private void VideoHostSizeChanged(object sender, SizeChangedEventArgs args) => LayoutVideo();
    private void Send(string[] lines)
    {
        if (lines.Length != 0 && liveWriter?.Send(lines) == false) liveCancel?.Cancel();
    }
    private void ReleaseFocusedInput() { Send(controls.ReleaseAll()); controls.Enabled = false; }
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
    private string? lastFileDragPoint;
    private string? FileDragPoint(DragEventArgs args)
    {
        var point = args.GetPosition(VideoSurface);
        return controls.FilePointer(point.X, point.Y, VideoSurface.ActualWidth, VideoSurface.ActualHeight);
    }
    private async void PictureDragEnter(object sender, DragEventArgs args)
    {
        if (!ClipboardActive || fileDragStarted || fileDragStarting
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
                fileDragStarted = true; lastFileDragPoint = at;
            }
        }
        catch (Exception) { } // Items that cannot be read during the drag are not offered.
        finally { fileDragStarting = false; deferral.Complete(); }
    }
    private void PictureDragOver(object sender, DragEventArgs args)
    {
        if (!ClipboardActive || !args.DataView.Contains(Windows.ApplicationModel.DataTransfer.StandardDataFormats.StorageItems)) return;
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
    private void PictureDrop(object sender, DragEventArgs args)
    {
        if (!fileDragStarted) return;
        fileDragStarted = false;
        if (ClipboardActive && (FileDragPoint(args) ?? lastFileDragPoint) is string at) Send([$"M 10 {at}"]);
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
    private void BackendLostFocus(object sender, RoutedEventArgs args) => ReleaseFocusedInput();
    private void BackendKeyDown(object sender, KeyRoutedEventArgs args)
    {
        if (syntheticLive || phoneAcceptance) return;
        controls.Enabled = session.CanSendInput && windowActive;
        var lines = controls.Key((int)args.KeyStatus.ScanCode, args.KeyStatus.IsExtendedKey, true, (int)args.Key);
        Send(lines); if (lines.Length != 0) args.Handled = true;
    }
    private void BackendKeyUp(object sender, KeyRoutedEventArgs args)
    {
        if (syntheticLive || phoneAcceptance) return;
        var lines = controls.Key((int)args.KeyStatus.ScanCode, args.KeyStatus.IsExtendedKey, false, (int)args.Key);
        Send(lines); if (lines.Length != 0) args.Handled = true;
    }
    private void BackendPointerMoved(object sender, PointerRoutedEventArgs args)
    {
        if (syntheticLive || phoneAcceptance || !session.CanSendInput || !windowActive) return;
        controls.Enabled = true;
        var point = args.GetCurrentPoint(VideoSurface);
        if (CursorButton.IsChecked == true)
        {
            var hostPoint = args.GetCurrentPoint(VideoHost).Position;
            CursorPosition.X = hostPoint.X; CursorPosition.Y = hostPoint.Y;
            CursorIndicator.Visibility = Visibility.Visible;
        }
        Send(controls.Move(point.Position.X, point.Position.Y, VideoSurface.ActualWidth, VideoSurface.ActualHeight));
    }
    private void BackendPointerPressed(object sender, PointerRoutedEventArgs args)
    {
        if (syntheticLive || phoneAcceptance || !session.CanSendInput || !windowActive) return;
        var hit = args.GetCurrentPoint(VideoSurface).Position;
        if (hit.X < 0 || hit.Y < 0 || hit.X >= VideoSurface.ActualWidth || hit.Y >= VideoSurface.ActualHeight) return;
        InputSurface.Focus(FocusState.Programmatic);
        BackendPointerMoved(sender, args);
        var p = args.GetCurrentPoint(VideoSurface).Properties;
        foreach (var (button, down) in new[] { (1, p.IsLeftButtonPressed), (2, p.IsMiddleButtonPressed),
                  (3, p.IsRightButtonPressed), (4, p.IsXButton1Pressed), (5, p.IsXButton2Pressed) })
            if (down) Send(controls.Button(button, true));
        VideoSurface.CapturePointer(args.Pointer); args.Handled = true;
    }
    private void BackendPointerReleased(object sender, PointerRoutedEventArgs args)
    {
        if (syntheticLive || phoneAcceptance) return;
        BackendPointerMoved(sender, args);
        var p = args.GetCurrentPoint(VideoSurface).Properties;
        foreach (var (button, down) in new[] { (1, p.IsLeftButtonPressed), (2, p.IsMiddleButtonPressed),
                  (3, p.IsRightButtonPressed), (4, p.IsXButton1Pressed), (5, p.IsXButton2Pressed) })
            if (!down) Send(controls.Button(button, false));
        if (!controls.HasButtons) VideoSurface.ReleasePointerCapture(args.Pointer); args.Handled = true;
    }
    private void BackendWheel(object sender, PointerRoutedEventArgs args)
    {
        if (syntheticLive || phoneAcceptance || !session.CanSendInput || !windowActive) return;
        BackendPointerMoved(sender, args);
        var p = args.GetCurrentPoint(VideoSurface).Properties;
        Send(controls.Wheel(p.MouseWheelDelta, p.IsHorizontalMouseWheel)); args.Handled = true;
    }
    private void BackendPointerCaptureLost(object sender, PointerRoutedEventArgs args) => Send(controls.ReleaseButtons());
}
