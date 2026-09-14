namespace Transiever.ManageSieve;

internal interface IManageSieveChannelBindingAuthenticator
{
    bool UsesChannelBinding => true;

    string ChannelBindingName { get; }

    void SetChannelBinding(ReadOnlyMemory<byte> binding);
}
