namespace DexClient.Core;

public enum ConnectionState
{
    Disconnected,
    Contacting,
    Starting,
    WaitingForPicture,
    Connected,
    Disconnecting
}

// Owned by the UI thread. A transport completion must carry its generation;
// a late callback can never activate input for a replacement session.
public sealed class SessionState
{
    public ConnectionState State { get; private set; } = ConnectionState.Disconnected;
    public long Generation { get; private set; }
    public bool CanSendInput => State == ConnectionState.Connected;

    public long BeginConnect()
    {
        if (State != ConnectionState.Disconnected)
            throw new InvalidOperationException("A session is already active.");
        Generation = checked(Generation + 1);
        State = ConnectionState.Contacting;
        return Generation;
    }

    public bool TransportReady(long generation) =>
        Advance(generation, ConnectionState.Contacting, ConnectionState.Starting);

    public bool SessionStarted(long generation) =>
        Advance(generation, ConnectionState.Starting, ConnectionState.WaitingForPicture);

    public bool PictureReady(long generation) =>
        Advance(generation, ConnectionState.WaitingForPicture, ConnectionState.Connected);

    public bool BeginDisconnect(long generation)
    {
        if (generation != Generation || State is ConnectionState.Disconnected or ConnectionState.Disconnecting)
            return false;
        State = ConnectionState.Disconnecting;
        return true;
    }

    public bool Closed(long generation)
    {
        if (generation != Generation || State == ConnectionState.Disconnected)
            return false;
        State = ConnectionState.Disconnected;
        return true;
    }

    private bool Advance(long generation, ConnectionState expected, ConnectionState next)
    {
        if (generation != Generation || State != expected)
            return false;
        State = next;
        return true;
    }
}
