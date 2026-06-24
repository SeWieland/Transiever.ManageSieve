namespace Transiever.ManageSieve;

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
