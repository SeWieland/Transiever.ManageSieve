using Transiever.SaslClient;

namespace Transiever.ManageSieve;

/// <summary>
/// Adapts a protocol-neutral SASL mechanism to the ManageSieve authentication exchange.
/// </summary>
public sealed class ManageSieveSaslMechanismAdapter :
    IManageSieveAuthenticator,
    IManageSieveChannelBindingAuthenticator
{
    private const string GenericFailureMessage = "ManageSieve authenticator failed.";
    private readonly ISaslMechanism _mechanism;
    private readonly bool _preserveFailureMessage;

    public ManageSieveSaslMechanismAdapter(ISaslMechanism mechanism)
        : this(mechanism, preserveFailureMessage: false)
    {
    }

    internal ManageSieveSaslMechanismAdapter(
        ISaslMechanism mechanism,
        bool preserveFailureMessage)
    {
        ArgumentNullException.ThrowIfNull(mechanism);
        _mechanism = mechanism;
        _preserveFailureMessage = preserveFailureMessage;
    }

    public string Mechanism => Read(() => _mechanism.Mechanism);

    public bool AllowsUnprotectedConnection =>
        Read(() => _mechanism.AllowsUnprotectedConnection);

    public bool RequiresClientCertificate =>
        Read(() => _mechanism.RequiresClientCertificate);

    bool IManageSieveChannelBindingAuthenticator.UsesChannelBinding =>
        _mechanism is ISaslChannelBindingMechanism;

    string IManageSieveChannelBindingAuthenticator.ChannelBindingName
    {
        get
        {
            try
            {
                return ((ISaslChannelBindingMechanism)_mechanism).ChannelBindingName;
            }
            catch (Exception exception)
            {
                throw Translate(exception);
            }
        }
    }

    void IManageSieveChannelBindingAuthenticator.SetChannelBinding(
        ReadOnlyMemory<byte> binding)
    {
        try
        {
            ((ISaslChannelBindingMechanism)_mechanism).SetChannelBinding(binding);
        }
        catch (Exception exception)
        {
            throw Translate(exception);
        }
    }

    public async ValueTask<ReadOnlyMemory<byte>?> GetInitialResponseAsync(
        CancellationToken cancellationToken = default)
    {
        try
        {
            return await _mechanism.GetInitialResponseAsync(cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw Translate(exception);
        }
    }

    public async ValueTask<ReadOnlyMemory<byte>> RespondAsync(
        ReadOnlyMemory<byte> challenge,
        CancellationToken cancellationToken = default)
    {
        try
        {
            return await _mechanism.RespondAsync(challenge, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw Translate(exception);
        }
    }

    public async ValueTask CompleteAsync(
        ReadOnlyMemory<byte>? serverData,
        CancellationToken cancellationToken = default)
    {
        try
        {
            await _mechanism.CompleteAsync(serverData, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw Translate(exception);
        }
    }

    public void Abort()
    {
        try
        {
            _mechanism.Abort();
        }
        catch (Exception exception)
        {
            throw Translate(exception);
        }
    }

    private ManageSieveAuthenticationException Translate(Exception exception) =>
        new(_preserveFailureMessage && exception is SaslAuthenticationException
            ? exception.Message
            : GenericFailureMessage);

    private T Read<T>(Func<T> read)
    {
        try
        {
            return read();
        }
        catch (Exception exception)
        {
            throw Translate(exception);
        }
    }
}
