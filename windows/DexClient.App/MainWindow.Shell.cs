using System.Diagnostics;
using DexClient.Core;
using DexClient.Media;
using Microsoft.UI;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Documents;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;

namespace DexClient.App;

public sealed partial class MainWindow
{
    private readonly Stopwatch sessionDuration = new();
    private ContentDialog? telemetryDialog;

    private void SetSessionShell(bool connected)
    {
        HomePanel.Visibility = connected ? Visibility.Collapsed : Visibility.Visible;
        SessionToolbar.Visibility = connected ? Visibility.Visible : Visibility.Collapsed;
        ToolbarHandle.Visibility = Visibility.Collapsed;
        Placeholder.Visibility = connected ? Visibility.Visible : Visibility.Collapsed;
        CursorIndicator.Visibility = Visibility.Collapsed;
        CursorButton.IsChecked = false;
        telemetryDialog?.Hide();
        if (connected) sessionDuration.Restart(); else sessionDuration.Stop();
    }
    private void HideToolbar(object sender, RoutedEventArgs args)
    {
        SessionToolbar.Visibility = Visibility.Collapsed;
        ToolbarHandle.Visibility = Visibility.Visible;
        InputSurface.Focus(FocusState.Programmatic);
    }
    private void ShowToolbar(object sender, RoutedEventArgs args)
    {
        SessionToolbar.Visibility = Visibility.Visible;
        ToolbarHandle.Visibility = Visibility.Collapsed;
    }
    private void ToggleCursor(object sender, RoutedEventArgs args)
    {
        if (CursorButton.IsChecked != true) CursorIndicator.Visibility = Visibility.Collapsed;
        InputSurface.Focus(FocusState.Programmatic);
    }
    private void ToggleLowLatency(object sender, RoutedEventArgs args)
    {
        if (videoSchedule is { } frames) frames.LowLatency = LowLatencyButton.IsChecked == true;
        InputSurface.Focus(FocusState.Programmatic);
    }
    private static SolidColorBrush Brush(uint rgb) => new(ColorHelper.FromArgb(255, (byte)(rgb >> 16), (byte)(rgb >> 8), (byte)rgb));
    private static Border Card(UIElement content, double radius, Thickness padding) => new()
    { Child = content, CornerRadius = new CornerRadius(radius), Background = Brush(0x1C1F24), BorderBrush = Brush(0x2A2D33), BorderThickness = new Thickness(1), Padding = padding };
    private static TextBlock Label(string text) => new() { Text = text, FontSize = 12, Foreground = Brush(0x9BA1AA) };

    // Layout from design-reference/remote-desktop-ui (telemetry board). Every value
    // is a real client counter; latency is the kernel TCP round-trip to the gateway.
    private async void OpenTelemetry(object sender, RoutedEventArgs args)
    {
        if (telemetryDialog != null) return;
        // A modal takes input ownership through the existing release path.
        ReleaseFocusedInput();
        var dot = new Ellipse { Width = 8, Height = 8, Fill = Brush(0x3FB950) };
        var live = new TextBlock { FontSize = 13, Foreground = Brush(0x9BA1AA) };
        var close = new Button { Width = 44, Height = 44, Margin = new Thickness(0, -8, -4, 0), Padding = new Thickness(0), CornerRadius = new CornerRadius(10),
            Background = new SolidColorBrush(Colors.Transparent), BorderThickness = new Thickness(0), Foreground = Brush(0xC3C8CF),
            Content = new FontIcon { Glyph = "\uE711", FontSize = 16 }, VerticalAlignment = VerticalAlignment.Top, HorizontalAlignment = HorizontalAlignment.Right };
        AutomationProperties.SetName(close, "Close telemetry");
        var heading = new StackPanel { Spacing = 4, Children = { new TextBlock { Text = "Connection telemetry", FontSize = 18, FontWeight = FontWeights.SemiBold, Foreground = Brush(0xF1F3F5) },
            new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, Children = { dot, live } } } };
        var header = new Grid { Children = { heading, close } };

        var latencyValue = new Run { FontSize = 28, FontWeight = FontWeights.SemiBold, Foreground = Brush(0xF1F3F5) };
        var latencyText = new TextBlock(); latencyText.Inlines.Add(latencyValue);
        latencyText.Inlines.Add(new Run { Text = " ms", FontSize = 15, FontWeight = FontWeights.Medium, Foreground = Brush(0x9BA1AA) });
        var spark = new Polyline { Stroke = Brush(0x5B9BF8), StrokeThickness = 2, StrokeLineJoin = PenLineJoin.Round, StrokeStartLineCap = PenLineCap.Round, StrokeEndLineCap = PenLineCap.Round };
        var sparkHost = new Canvas { Width = 240, Height = 52, Children = { spark }, HorizontalAlignment = HorizontalAlignment.Right, VerticalAlignment = VerticalAlignment.Center };
        AutomationProperties.SetName(sparkHost, "Latency over the last 30 seconds");
        var latencyLeft = new StackPanel { Spacing = 4, Children = { Label("Round-trip latency"), latencyText } };
        var latencyCard = Card(new Grid { ColumnSpacing = 16, Children = { latencyLeft, sparkHost } }, 12, new Thickness(16, 14, 16, 14));
        ToolTipService.SetToolTip(latencyCard, "TCP round-trip time to the gateway. Display latency is not measured.");

        string[] labels = { "Frame rate", "Resolution", "Download", "Upload", "Frames dropped", "Codec", "Audio buffer", "Route" };
        var values = new TextBlock[labels.Length];
        var stats = new Grid { ColumnSpacing = 10, RowSpacing = 10 };
        stats.ColumnDefinitions.Add(new ColumnDefinition()); stats.ColumnDefinitions.Add(new ColumnDefinition());
        for (int i = 0; i < labels.Length; i++)
        {
            if (i % 2 == 0) stats.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            values[i] = new TextBlock { FontSize = 16, FontWeight = FontWeights.SemiBold, Foreground = Brush(0xF1F3F5), TextWrapping = TextWrapping.Wrap };
            var card = Card(new StackPanel { Spacing = 4, Children = { Label(labels[i]), values[i] } }, 10, new Thickness(14, 12, 14, 12));
            Grid.SetRow(card, i / 2); Grid.SetColumn(card, i % 2); stats.Children.Add(card);
        }
        var done = new Button { Content = "Close", Height = 44, Padding = new Thickness(20, 0, 20, 0), CornerRadius = new CornerRadius(10), Background = Brush(0x22252B),
            BorderBrush = Brush(0x33373E), BorderThickness = new Thickness(1), Foreground = Brush(0xF1F3F5), HorizontalAlignment = HorizontalAlignment.Right };
        // Video rendering: saved per user, used from the next connection (switching decoders
        // mid-stream would need a new keyframe from the phone).
        var rendering = new ComboBox { HorizontalAlignment = HorizontalAlignment.Stretch, MinHeight = 40,
            Items = { "Hardware (GPU)", "Software (CPU)" },
            SelectedIndex = ClientSettings.LoadRendering(ClientSettings.DefaultPath) == VideoRendering.Software ? 1 : 0 };
        AutomationProperties.SetName(rendering, "Video rendering");
        var renderingNote = new TextBlock { Text = "Applies from the next connection.", FontSize = 12, Foreground = Brush(0x9BA1AA) };
        rendering.SelectionChanged += (_, _) =>
            renderingNote.Text = ClientSettings.SaveRendering(ClientSettings.DefaultPath, rendering.SelectedIndex == 1 ? VideoRendering.Software : VideoRendering.Hardware)
                ? "Saved. Applies from the next connection." : "Couldn't save the setting.";
        var renderingCard = Card(new StackPanel { Spacing = 6, Children = { Label("Video rendering"), rendering, renderingNote } }, 10, new Thickness(14, 12, 14, 12));
        var body = new StackPanel { Spacing = 18, HorizontalAlignment = HorizontalAlignment.Stretch, Children = { header, latencyCard, stats, renderingCard, done } };

        var samples = new Queue<double>();
        var clock = Stopwatch.StartNew();
        long lastPresented = presentedFrames; TcpCounters? lastMedia = liveBackend?.MediaCounters, lastInput = liveBackend?.InputCounters;
        double lastAt = 0;
        void Refresh()
        {
            double now = clock.Elapsed.TotalSeconds, dt = Math.Max(now - lastAt, .001);
            TcpCounters? media = liveBackend?.MediaCounters, input = liveBackend?.InputCounters;
            bool streaming = media != null && presentedFrames > 0;
            dot.Fill = Brush(streaming ? 0x3FB950u : 0x9BA1AAu);
            var elapsed = sessionDuration.Elapsed;
            live.Text = (streaming ? "Live" : ConnectionStatus.Text) + " · session " + (elapsed.TotalHours >= 1 ? elapsed.ToString(@"h\:mm\:ss") : elapsed.ToString(@"mm\:ss"));
            if (media != null)
            {
                double rtt = media.RoundTripMicroseconds / 1000d;
                latencyValue.Text = rtt < 10 ? rtt.ToString("0.0") : rtt.ToString("0");
                samples.Enqueue(rtt); while (samples.Count > 30) samples.Dequeue();
            }
            else latencyValue.Text = "—";
            double top = Math.Max(60, samples.DefaultIfEmpty(0).Max() * 1.2);
            var points = new PointCollection(); int n = 0;
            foreach (double v in samples) points.Add(new Windows.Foundation.Point(samples.Count < 2 ? 0 : n++ * 240d / (samples.Count - 1), 50 - v / top * 48));
            spark.Points = points;
            string Rate(ulong? now2, ulong? before) => now2 is { } a && before is { } b && a >= b ? $"{(a - b) * 8 / dt / 1e6:0.0} Mbps" : "—";
            values[0].Text = lastAt > 0 ? $"{(presentedFrames - lastPresented) / dt:0} fps" : "—";
            values[1].Text = frameWidth > 0 ? $"{frameWidth} × {frameHeight}" : "—";
            values[2].Text = lastAt > 0 ? Rate(media?.BytesIn, lastMedia?.BytesIn) : "—";
            values[3].Text = lastAt > 0 ? Rate(input?.BytesOut + media?.BytesOut, lastInput?.BytesOut + lastMedia?.BytesOut) : "—";
            values[4].Text = videoSchedule is { } schedule ? schedule.Dropped.ToString("N0") : "—";
            string decode = presentedFrames == 0 ? "—" : lastFrameGpu ? "GPU" : "CPU";
            string display = livePresenter?.Driver switch { "Hardware" => "GPU", "WARP" => "WARP (CPU)", _ => "—" };
            values[5].Text = $"H.264 · AAC\nDecode {decode} · display {display}";
            ToolTipService.SetToolTip(values[5], gpuVideo is { } gpu && lastFrameGpu ? gpu.Adapter
                : gpuUnavailable is { } reason ? "Not on the GPU: " + reason : livePresenter?.Adapter);
            values[6].Text = sessionAudio is { } player ? $"{player.BufferedMilliseconds} ms · target {player.TargetMilliseconds}" : audioAvailable ? "—" : "No output device";
            values[7].Text = media != null ? "Direct TLS" : "—";
            lastPresented = presentedFrames; lastMedia = media; lastInput = input; lastAt = now;
        }
        var timer = DispatcherQueue.CreateTimer(); timer.Interval = TimeSpan.FromSeconds(1);
        timer.Tick += (_, _) => Refresh();
        var dialog = new ContentDialog { XamlRoot = AppRoot.XamlRoot, RequestedTheme = ElementTheme.Dark, Content = body,
            Background = Brush(0x16181C), BorderBrush = Brush(0x2A2D33), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(16), Padding = new Thickness(22, 20, 22, 22) };
        dialog.Resources["ContentDialogMaxWidth"] = 560d; dialog.Resources["ContentDialogMinWidth"] = 560d;
        close.Click += (_, _) => dialog.Hide(); done.Click += (_, _) => dialog.Hide();
        telemetryDialog = dialog;
        try { Refresh(); timer.Start(); await dialog.ShowAsync(); }
        finally { timer.Stop(); telemetryDialog = null; if (session.CanSendInput) InputSurface.Focus(FocusState.Programmatic); }
    }
}
