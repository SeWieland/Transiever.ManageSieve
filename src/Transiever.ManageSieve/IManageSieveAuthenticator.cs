namespace Transiever.ManageSieve;

public interface IManageSieveAuthenticator
{
    string Mechanism { get; }

    ValueTask<ReadOnlyMemory<byte>?> GetInitialResponseAsync(
        CancellationToken cancellationToken = default);

    ValueTask<ReadOnlyMemory<byte>> RespondAsync(
        ReadOnlyMemory<byte> challenge,
        CancellationToken cancellationToken = default);
}
