namespace Transiever.ManageSieve;

public sealed class ManageSieveClientFactory : IManageSieveClientFactory
{
    public IManageSieveClient CreateClient(ManageSieveClientOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        return new ManageSieveClient(options);
    }
}
