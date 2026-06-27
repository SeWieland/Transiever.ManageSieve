namespace Transiever.ManageSieve;

/// <summary>
/// Default factory for <see cref="ManageSieveClient"/>.
/// </summary>
public sealed class ManageSieveClientFactory : IManageSieveClientFactory
{
    public IManageSieveClient CreateClient(ManageSieveClientOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        return new ManageSieveClient(options);
    }
}
