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
    private readonly KeepAwake keepAwake = new(PowerRequest.Apply);
    // Video rendering (ClientSettings): the shared GPU device when Hardware works, why it
    // does not otherwise, and whether the last shown frame was decoded on the GPU.
    private GpuVideo? gpuVideo;
    private string? gpuUnavailable;
    private bool lastFrameGpu;
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
    // UI test (synthetic stream only): "--record-input <file>" handles input as in a phone
    // session and writes the lines it would send to that file; "--loop" replays the stream.
    private bool recordingInput;
    private string? loopStream;
    private bool InputBlocked => (syntheticLive && !recordingInput) || phoneAcceptance;
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
                int record = Array.IndexOf(arguments, "--record-input");
                recordingInput = record >= 0 && record + 1 < arguments.Length;
                loopStream = arguments.Contains("--loop") ? arguments[index + 2] : null;
                source = new FileStream(arguments[index + 2], FileMode.Open, FileAccess.Read, FileShare.Read);
                syntheticInput = new MemoryStream();
                liveWriter = new InputWriter(recordingInput
                    ? new FileStream(arguments[record + 1], FileMode.Create, FileAccess.Write, FileShare.Read) : syntheticInput);
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
                backend.PhoneFileLine += line => PhoneFileLine(line, generation);
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
            gpuUnavailable = null; lastFrameGpu = false;
            if (ClientSettings.LoadRendering(ClientSettings.DefaultPath) == VideoRendering.Hardware)
                gpuVideo = await Task.Run(() => GpuVideo.TryCreate(out gpuUnavailable), token);
            else gpuUnavailable = "Software rendering is selected";
            GpuVideo? gpu = gpuVideo;
            LiveDecodeResult DecodeFrom(Stream input) => LiveDecoder.Decode(input, frame =>
            {
                Interlocked.Increment(ref decodedFrames); metrics.Mark("decoded");
                if (inputHiccupCheck) metrics.Mark(playbackPhase + "_decoded");
                if (!token.IsCancellationRequested) frames.Push(frame, Stopwatch.GetTimestamp());
                else frame.Dispose();
                if (test) Thread.Sleep(10); // Synthetic pacing only, never in a phone session.
            }, _ => { }, token, reuseVideoBuffers: !baselineTiming,
                timedAudio: (pts, samples) => { Interlocked.Increment(ref decodedAudioFrames); player.Push(samples, pts); if (inputHiccupCheck) metrics.Mark(playbackPhase + "_audio"); }, measure: metrics.Add,
                gpu: gpu);
            Stream firstInput = source;
            decoding = Task.Run(() =>
            {
                var result = DecodeFrom(firstInput);
                // UI test only: a fresh decoder per pass over the recorded stream, so it plays until closed.
                while (loopStream != null && !token.IsCancellationRequested)
                {
                    using var again = new FileStream(loopStream, FileMode.Open, FileAccess.Read, FileShare.Read);
                    result = DecodeFrom(again);
                }
                return result;
            }, token);
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
            // After the decoder (it holds the device through FFmpeg) and every queued frame are gone.
            if (decoding?.IsCompleted != false) { gpuVideo?.Dispose(); gpuVideo = null; }
            long writtenInput = liveWriter?.LinesWritten ?? 0;
            liveWriter = null; liveCancel.Dispose(); liveCancel = null;
            if (decoding?.IsCompleted != false) session.Closed(generation);
            ConnectButton.IsEnabled = session.State == ConnectionState.Disconnected; DisconnectButton.IsEnabled = false;
            keepAwake.Streaming(false);
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
        if (session.CanSendInput) Send(controls.FlushMove()); // hover moves too, focused or not
        var frames = videoSchedule;
        if (frames == null || frames.Generation != session.Generation || session.State is ConnectionState.Disconnecting or ConnectionState.Disconnected) return;
        try
        {
            using VideoFrame? frame = frames.Take(Stopwatch.GetTimestamp(), sessionAudio?.PositionMicroseconds);
            if (frame == null) return;
            if (livePresenter == null || frame.Width != frameWidth || frame.Height != frameHeight || frame.IsGpu != lastFrameGpu)
            {
                livePresenter?.Dispose();
                nint panel = ((WinRT.IWinRTObject)VideoSurface).NativeObject.ThisPtr;
                livePresenter = new FramePresenter(panel, frame.Width, frame.Height, PresentationMode.PreferHardware, gpu: frame.IsGpu ? gpuVideo : null);
                frameWidth = frame.Width; frameHeight = frame.Height;
                LayoutVideo();
                livePresenter.SetLayoutSize(VideoSurface.ActualWidth, VideoSurface.ActualHeight);
            }
            long presenting = Stopwatch.GetTimestamp();
            livePresenter.PresentLive(frame); presentedFrames++; lastFrameGpu = frame.IsGpu;
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
                keepAwake.Streaming(true); // until the session ends (or while minimized)
                if (syntheticLive || phoneAcceptance)
                {
                    if (!recordingInput) // a UI test records only what its own input produces
                    {
                        Send(controls.Move(VideoSurface.ActualWidth / 2, VideoSurface.ActualHeight / 2, VideoSurface.ActualWidth, VideoSurface.ActualHeight));
                        Send(controls.Key(0x2a, false, true));
                    }
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
}
