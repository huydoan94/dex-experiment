using System.Security.Authentication;
using System.Text;
using DexClient.Media;

if (args.Length != 2) throw new ArgumentException("config mode");
var settings = BackendSettings.Load(args[0]);
using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
switch (args[1])
{
    case "probe":
        using (var channel = await DirectChannel.OpenAsync(settings, "probe", "", deadline.Token))
            await channel.ReadyAsync("authenticated", deadline.Token);
        break;
    case "wrong-pin":
        try
        {
            using var refused = await DirectChannel.OpenAsync(settings with { CertificateSha256 = Convert.ToBase64String(new byte[32]) }, "probe", "", deadline.Token);
            throw new InvalidOperationException("Wrong TLS pin accepted");
        }
        catch (AuthenticationException) { }
        break;
    case "cancel":
        using (var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(200)))
        {
            try
            {
                using var half = await DirectChannel.OpenAsync(settings, "input", Guid.NewGuid().ToString("N"), cancel.Token);
                await half.ReadyAsync("ready", cancel.Token);
                throw new InvalidOperationException("Unpaired startup did not cancel");
            }
            catch (OperationCanceledException) { }
        }
        break;
    case "pair":
        await using (var backend = new PythonSession())
        {
            await backend.ConnectAsync(settings, deadline.Token);
            if (!backend.Writer.Send(["K d 42", "M 0 10 20", "K u 42"]))
                throw new InvalidOperationException("Input queue refused");
            byte[] expected = Encoding.ASCII.GetBytes("synthetic-media");
            byte[] actual = new byte[expected.Length];
            await backend.MediaStream.ReadExactlyAsync(actual, deadline.Token);
            if (!actual.AsSpan().SequenceEqual(expected)) throw new InvalidOperationException("Media bytes changed");
            await backend.Writer.CompleteAsync([]);
            if (backend.Writer.Failed || backend.Writer.LinesWritten != 3) throw new InvalidOperationException("Input did not drain");
        }
        break;
    case "cursor":
        await using (var backend = new PythonSession())
        {
            var shape = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
            backend.CursorChanged += type => shape.TrySetResult(type);
            await backend.ConnectAsync(settings, deadline.Token);
            if (!backend.RequestCursorShapes()) throw new InvalidOperationException("Opt-in refused");
            int reported = await shape.Task.WaitAsync(deadline.Token);
            if (reported != 1002 || backend.CursorLines != 1) throw new InvalidOperationException("Cursor line not delivered: " + reported);
            await backend.Writer.CompleteAsync([]);
        }
        break;
    default: throw new ArgumentException("Unknown check");
}
Console.WriteLine("PASS direct TLS " + args[1]);
