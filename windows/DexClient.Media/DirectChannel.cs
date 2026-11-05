using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DexClient.Media;

public sealed record TcpCounters(uint RoundTripMicroseconds, ulong BytesIn, ulong BytesOut);

// One TCP/TLS connection, one direction. Media never shares the input socket,
// TLS record lock, congestion window or protocol work queue.
public sealed class DirectChannel : IDisposable
{
    private readonly TcpClient socket;
    public SslStream Stream { get; }
    private DirectChannel(TcpClient socket, SslStream stream) { this.socket = socket; Stream = stream; }
    public static bool MatchesCertificate(byte[] certificate, byte[] pin) => pin.Length == 32 &&
        CryptographicOperations.FixedTimeEquals(SHA256.HashData(certificate), pin);

    public static async Task<DirectChannel> OpenAsync(BackendSettings settings, string role, string session,
                                                       CancellationToken cancellation)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        deadline.CancelAfter(TimeSpan.FromSeconds(5));
        var socket = new TcpClient { NoDelay = true };
        SslStream? stream = null;
        try
        {
            await socket.ConnectAsync(settings.Host, settings.Port, deadline.Token).ConfigureAwait(false);
            byte[] pin = settings.Pin();
            stream = new SslStream(socket.GetStream(), false, (_, certificate, _, _) =>
                certificate != null && MatchesCertificate(certificate.GetRawCertData(), pin));
            await stream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = settings.Host,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                CertificateRevocationCheckMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck
            }, deadline.Token).ConfigureAwait(false);
            string token = (await File.ReadAllTextAsync(settings.TokenFile, deadline.Token).ConfigureAwait(false)).Trim();
            if (token.Length is < 32 or > 128) throw new InvalidDataException("Invalid gateway token file.");
            byte[] hello = JsonSerializer.SerializeToUtf8Bytes(new { version = 1, role, session, token });
            await stream.WriteAsync(hello, deadline.Token).ConfigureAwait(false);
            await stream.WriteAsync(new byte[] { (byte)'\n' }, deadline.Token).ConfigureAwait(false);
            return new DirectChannel(socket, stream);
        }
        catch { stream?.Dispose(); socket.Dispose(); throw; }
    }
    public async Task ReadyAsync(string expected, CancellationToken cancellation)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        deadline.CancelAfter(TimeSpan.FromSeconds(20));
        var bytes = new List<byte>();
        var one = new byte[1];
        while (bytes.Count < 256)
        {
            if (await Stream.ReadAsync(one, deadline.Token).ConfigureAwait(false) == 0)
                throw new IOException("Gateway closed during startup.");
            if (one[0] == '\n')
            {
                using var reply = JsonDocument.Parse(bytes.ToArray());
                if (reply.RootElement.GetProperty("version").GetInt32() != 1)
                    throw new IOException("Unsupported gateway version.");
                string? status = reply.RootElement.GetProperty("status").GetString();
                if (status == "busy") throw new IOException("Another viewer is already attached.");
                if (status != expected) throw new IOException("Gateway refused the connection.");
                return;
            }
            bytes.Add(one[0]);
        }
        throw new InvalidDataException("Gateway greeting exceeds bounds.");
    }
    // Kernel TCP counters for this connection (SIO_TCP_INFO, TCP_INFO_v0); null
    // when unavailable or closed. Round-trip time is the network path to the
    // gateway, not end-to-end display latency.
    public TcpCounters? Counters()
    {
        try
        {
            byte[] info = new byte[88];
            if (socket.Client.IOControl(unchecked((IOControlCode)0xD8000027), BitConverter.GetBytes(0), info) < 88) return null;
            return new TcpCounters(BitConverter.ToUInt32(info, 20), BitConverter.ToUInt64(info, 56), BitConverter.ToUInt64(info, 48));
        }
        catch (Exception error) when (error is SocketException or ObjectDisposedException or NotSupportedException or InvalidOperationException) { return null; }
    }
    public void Dispose() { try { Stream.Dispose(); } finally { socket.Dispose(); } }
}
