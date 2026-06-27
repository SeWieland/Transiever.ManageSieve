namespace Transiever.ManageSieve;

/// <summary>
/// Base exception for ManageSieve failures.
/// </summary>
public class ManageSieveException : Exception
{
    public ManageSieveException(string message)
        : base(message)
    {
    }

    public ManageSieveException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// Raised when the client cannot establish or keep a transport connection.
/// </summary>
public sealed class ManageSieveConnectionException : ManageSieveException
{
    public ManageSieveConnectionException(string message)
        : base(message)
    {
    }

    public ManageSieveConnectionException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// Raised when SASL authentication fails.
/// </summary>
public sealed class ManageSieveAuthenticationException : ManageSieveException
{
    public ManageSieveAuthenticationException(
        string message,
        string? responseCode = null)
        : base(message)
    {
        ResponseCode = responseCode;
    }

    public string? ResponseCode { get; }
}

/// <summary>
/// Raised when the server sends malformed protocol data.
/// </summary>
public sealed class ManageSieveProtocolException : ManageSieveException
{
    public ManageSieveProtocolException(string message)
        : base(message)
    {
    }

    public ManageSieveProtocolException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// Raised when a ManageSieve command fails.
/// </summary>
public sealed class ManageSieveCommandException : ManageSieveException
{
    public ManageSieveCommandException(
        string command,
        string message,
        string? responseCode = null)
        : base(message)
    {
        Command = command;
        ResponseCode = responseCode;
    }

    public string Command { get; }

    public string? ResponseCode { get; }
}
