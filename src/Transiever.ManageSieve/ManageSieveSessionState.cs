namespace Transiever.ManageSieve;

/// <summary>
/// Current lifecycle state of a ManageSieve session.
/// </summary>
public enum ManageSieveSessionState
{
    Disconnected,
    Connected,
    Secured,
    Authenticated,
    Closed
}
