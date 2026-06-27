namespace Transiever.ManageSieve;

/// <summary>
/// Creates <see cref="IManageSieveClient"/> instances.
/// </summary>
public interface IManageSieveClientFactory
{
    /// <summary>
    /// Creates a client for the supplied options.
    /// </summary>
    IManageSieveClient CreateClient(ManageSieveClientOptions options);
}
