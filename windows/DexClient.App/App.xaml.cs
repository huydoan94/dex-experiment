using Microsoft.UI.Xaml;

namespace DexClient.App;

public partial class App : Application
{
    private MainWindow? window;

    public App()
    {
        TraceStartup("app_constructor");
        InitializeComponent();
        TraceStartup("app_initialized");
    }

    private static void TraceStartup(string phase)
    {
        string[] arguments = Environment.GetCommandLineArgs();
        if (!arguments.Contains("--media-test") && !arguments.Contains("--memory-media-test") && !arguments.Contains("--stream-media-test")) return;
        File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "media-trace.log"),
                          $"{DateTime.UtcNow:o} thread={Environment.CurrentManagedThreadId} {phase}\n");
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        TraceStartup("launch_enter");
        bool smoke = Environment.GetCommandLineArgs().Contains("--smoke-test");
        TraceStartup("window_construct_start");
        window = new MainWindow();
        TraceStartup("window_construct_end");
        window.Activate();
        TraceStartup("window_activated");
        if (smoke) window.BeginSmokeTest();
        if (Environment.GetCommandLineArgs().Contains("--approved-python-session")) window.BeginPhoneAcceptance();
        if (Environment.GetCommandLineArgs().Contains("--stream-media-test")) window.BeginStreamTest();
        if (Environment.GetCommandLineArgs().Contains("--media-test") || Environment.GetCommandLineArgs().Contains("--memory-media-test")) window.BeginMediaTest();
    }
}
