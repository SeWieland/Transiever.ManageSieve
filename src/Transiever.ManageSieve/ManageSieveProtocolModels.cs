using System.Text;

namespace Transiever.ManageSieve;

internal enum ManageSieveResponseStatus
{
    Continue,
    Ok,
    No,
    Bye
}

internal enum ManageSieveProtocolValueKind
{
    Atom,
    QuotedString,
    Literal
}

internal sealed record ManageSieveProtocolValue(
    ReadOnlyMemory<byte> Bytes,
    ManageSieveProtocolValueKind Kind)
{
    public string Text => Encoding.UTF8.GetString(Bytes.Span);
}

internal sealed record ManageSieveDataLine(IReadOnlyList<ManageSieveProtocolValue> Values);

internal sealed record ManageSieveResponseCode(
    string Atom,
    IReadOnlyList<ManageSieveProtocolValue> Arguments,
    string Text);

internal sealed record ManageSieveResponse(
    ManageSieveResponseStatus Status,
    IReadOnlyList<ManageSieveDataLine> Data,
    ManageSieveResponseCode? Code = null,
    string? Message = null)
{
    public string? ResponseCode => Code?.Text;
}
