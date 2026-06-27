namespace Transiever.ManageSieve;

/// <summary>
/// Transport security choices for ManageSieve connections.
/// </summary>
public enum ManageSieveSecurityMode
{
    StartTlsRequired,
    ImplicitTls,
    PlainText
}
