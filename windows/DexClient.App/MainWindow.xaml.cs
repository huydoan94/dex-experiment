using System.Text.Json;
using DexClient.Media;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;

namespace DexClient.App;

public sealed partial class MainWindow : Window
{
    private int renderEvents;
    private bool mediaRunning;
    private int releasedPresenters;
    private readonly CancellationTokenSource lifetime = new();
    private DispatcherQueueTimer? smokeTimer;
    private SystemKeyHook? systemKeys;

    public MainWindow()
    {
        InitializeComponent();
        Title = "Samsung DeX";
        string icon = Path.Combine(AppContext.BaseDirectory, "Assets", "DexClient.ico");
        if (File.Exists(icon)) AppWindow.SetIcon(icon);
        CompositionTarget.Rendering += OnRendering;
        try
        {
            systemKeys = new SystemKeyHook(WinRT.Interop.WindowNative.GetWindowHandle(this),
                () => !syntheticLive && !phoneAcceptance && session.CanSendInput && windowActive,
                (scan, extended, down, virtualKey) =>
                {
                    controls.Enabled = session.CanSendInput && windowActive;
                    Send(controls.Key(scan, extended, down, virtualKey, system: true));
                });
        }
        catch (System.ComponentModel.Win32Exception) { } // Without the hook these keys stay with Windows.
        Activated += (window, args) =>
        {
            windowActive = args.WindowActivationState != WindowActivationState.Deactivated;
            if (!windowActive) { Send(controls.ReleaseAll()); controls.Enabled = false; AskPhoneClipboard(); }
            else ShareClipboardWithPhone();
        };
        AppWindow.Changed += (appWindow, _) =>
            keepAwake.Minimized(appWindow.Presenter is Microsoft.UI.Windowing.OverlappedPresenter { State: Microsoft.UI.Windowing.OverlappedPresenterState.Minimized });
        AppWindow.Closing += (appWindow, args) =>
        {
            if (mediaRunning) { args.Cancel = true; lifetime.Cancel(); }
            else if (liveTask is { IsCompleted: false }) { args.Cancel = true; _ = StopLiveAsync(true); }
        };
        Closed += (_, _) =>
        {
            CompositionTarget.Rendering -= OnRendering;
            keepAwake.Streaming(false);
            systemKeys?.Dispose(); systemKeys = null;
            smokeTimer?.Stop();
            telemetryDialog?.Hide();
            lifetime.Cancel();
        };
    }

    public async void BeginMediaTest()
    {
        if (mediaRunning) throw new InvalidOperationException("Media test already running.");
        mediaRunning = true;
        string[] args = Environment.GetCommandLineArgs();
        string cancelPhase = args.FirstOrDefault(a => a.StartsWith("--cancel-at=", StringComparison.Ordinal))?[12..] ?? "";
        bool memoryInput = args.Contains("--memory-media-test");
        int index = Array.IndexOf(args, memoryInput ? "--memory-media-test" : "--media-test");
        bool phaseReached = false;
        void CloseAtPhase()
        {
            phaseReached = true;
            if (!DispatcherQueue.TryEnqueue(RequestClose) || !lifetime.Token.WaitHandle.WaitOne(1000))
                throw new TimeoutException("UI close request was not observed.");
        }
        object result;
        try
        {
            if (index < 0 || index + 2 >= args.Length)
                throw new ArgumentException("--media-test native-directory fixture-ts");
            MediaTrace("native_initialize");
            var native = await Task.Run(() => NativeRuntime.Initialize(args[index + 1], MediaTrace), lifetime.Token);
            MediaTrace("decode_start");
            Task<DecodeResult> decoding = memoryInput
                ? BoundedTsInput.DecodeAsync(new FileStream(args[index + 2], FileMode.Open, FileAccess.Read, FileShare.Read,
                                                            4096, FileOptions.Asynchronous), lifetime.Token,
                                             cancelPhase == "decode" ? CloseAtPhase : null)
                : Task.Run(() => SyntheticDecoder.Decode(args[index + 2], lifetime.Token, cancelPhase == "decode" ? CloseAtPhase : null));
            var decoded = await decoding;
            MediaTrace("decode_complete");
            lifetime.Token.ThrowIfCancellationRequested();
            Placeholder.Visibility = Visibility.Collapsed;
            // Window and its panel remain rooted throughout both UI-thread presenters.
            nint panel = ((WinRT.IWinRTObject)VideoSurface).NativeObject.ThisPtr;
            var presentations = new List<object>();
            foreach (var mode in new[] { PresentationMode.PreferHardware, PresentationMode.Software })
            {
                MediaTrace("presenter_start " + mode + " ui=" + DispatcherQueue.HasThreadAccess +
                           " context=" + SynchronizationContext.Current?.GetType().FullName);
                var presenter = new FramePresenter(panel, decoded.Width, decoded.Height, mode, MediaTrace);
                MediaTrace("presenter_created");
                try
                {
                    string hash = "";
                    for (int i = 0; i < 3; i++)
                    {
                        lifetime.Token.ThrowIfCancellationRequested();
                        hash = presenter.Present(decoded.LastFrame);
                        if (cancelPhase == "presentation") { phaseReached = true; RequestClose(); }
                        await Task.Delay(150, lifetime.Token);
                    }
                    presentations.Add(new { mode = mode.ToString(), presenter.Driver, presenter.Adapter,
                                            presenter.HardwareFailure, presenter.Presents, readbackSha256 = hash });
                }
                finally { presenter.Dispose(); releasedPresenters++; }
            }
            MediaTrace("audio_start");
            Task<object> playing = Task.Run(() => AudioProbe.PlaySilenceAsync(lifetime.Token, cancelPhase == "audio" ? CloseAtPhase : null));
            var audio = await playing;
            MediaTrace("audio_complete");
            result = new { passed = true, native, decoded.Frames, decoded.Width, decoded.Height,
                           presentations, audio, renderEvents, releasedPresenters,
                           memoryInput, note = "Last synthetic decoded frame; actual swapchain/readback. Bounded finite memory mode when selected; no phone stream." };
            Environment.ExitCode = 0;
        }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested && cancelPhase.Length > 0)
        {
            result = new { passed = true, canceled = true, cancelPhase, phaseReached, releasedPresenters };
            Environment.ExitCode = 0;
        }
        catch (Exception e)
        {
            result = new { passed = false, error = e.ToString() };
            Environment.ExitCode = 1;
        }
        MediaTrace("report");
        File.WriteAllText(Path.Combine(AppContext.BaseDirectory, "media-result.json"),
                          JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
        mediaRunning = false;
        Close();
    }

    private static void MediaTrace(string phase) =>
        File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "media-trace.log"),
                           $"{DateTime.UtcNow:o} thread={Environment.CurrentManagedThreadId} {phase}\n");

    private void OnRendering(object? sender, object args) { renderEvents++; RenderLive(); }
    private void RequestClose()
    {
        if (mediaRunning) lifetime.Cancel();
        else if (liveTask is { IsCompleted: false }) _ = StopLiveAsync(true);
        else Close();
    }
    private void ClosePreview(object sender, RoutedEventArgs args) => RequestClose();

    public void BeginSmokeTest()
    {
        smokeTimer = DispatcherQueue.CreateTimer();
        smokeTimer.Interval = TimeSpan.FromSeconds(2);
        smokeTimer.IsRepeating = false;
        smokeTimer.Tick += (_, _) =>
        {
            bool passed = renderEvents > 0 && VideoSurface.ActualWidth > 0 && VideoSurface.ActualHeight > 0;
            var result = new
            {
                passed,
                renderEvents,
                surfaceWidth = VideoSurface.ActualWidth,
                surfaceHeight = VideoSurface.ActualHeight,
                processArchitecture = System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture.ToString(),
                note = "Local XAML composition only; no swap chain, decoder, audio, transport or phone access."
            };
            File.WriteAllText(Path.Combine(AppContext.BaseDirectory, "smoke-result.json"),
                              JsonSerializer.Serialize(result));
            Environment.ExitCode = passed ? 0 : 1;
            Close();
        };
        smokeTimer.Start();
    }
}
