namespace Transiever.ManageSieve;

public interface IManageSieveClientFactory
{
    IManageSieveClient CreateClient(ManageSieveClientOptions options);
}
