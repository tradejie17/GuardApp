using System.IO.Pipes;
using System.Runtime.Versioning;
using Guard.Core;
using Guard.Core.Configuration;
using Guard.Core.Messaging;
using Guard.Service.Admin;
using Guard.Service.Configuration;
using Guard.Service.Enforcement;
using Guard.Service.Logging;
using Guard.Service.Security;

namespace Guard.Service.Messaging;

/// <summary>
/// The service's front door: a named pipe that native messaging hosts and guardctl connect to.
///
/// A fixed pool of accept loops bounds how many connections can be open at once, so a local
/// process cannot exhaust the service by opening pipes in a loop.
/// </summary>
public sealed class PipeServerWorker : BackgroundService
{
    private const int MaxInstances = 16;

    private readonly ConfigStore _config;
    private readonly StateStore _state;
    private readonly SecretsStore _secrets;
    private readonly EnforcementManager _enforcement;
    private readonly AdminCommandHandler _admin;
    private readonly SessionRegistry _sessions;
    private readonly GuardLogger _guardLog;
    private readonly ILogger<PipeServerWorker> _logger;
    private readonly ILoggerFactory _loggerFactory;

    public PipeServerWorker(
        ConfigStore config,
        StateStore state,
        SecretsStore secrets,
        EnforcementManager enforcement,
        AdminCommandHandler admin,
        SessionRegistry sessions,
        GuardLogger guardLog,
        ILogger<PipeServerWorker> logger,
        ILoggerFactory loggerFactory)
    {
        _config = config;
        _state = state;
        _secrets = secrets;
        _enforcement = enforcement;
        _admin = admin;
        _sessions = sessions;
        _guardLog = guardLog;
        _logger = logger;
        _loggerFactory = loggerFactory;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _config.Load();
        _state.Load();
        _secrets.Load();
        _guardLog.PurgeExpired(_config.Current.Logging);

        // Any policy or pause change is pushed straight out to every connected extension, so a
        // newly added keyword takes effect without waiting for a browser restart.
        _config.Changed += _ => Broadcast(stoppingToken);
        _state.Changed += _ => Broadcast(stoppingToken);

        _logger.LogInformation(
            "Guard service listening on pipe '{Pipe}' with {Instances} accept slots.",
            GuardPaths.PipeName, MaxInstances);

        var loops = Enumerable.Range(0, MaxInstances)
            .Select(_ => AcceptLoopAsync(stoppingToken))
            .ToArray();

        await Task.WhenAll(loops);
    }

    private void Broadcast(CancellationToken cancellationToken)
    {
        var message = ConfigMessage.From(_config.Current, _state.Current, MessageTypes.ConfigChanged);

        // Fire-and-forget: a slow or dead client must not block the administrator's command.
        _ = Task.Run(async () =>
        {
            try
            {
                await _sessions.BroadcastAsync(message, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to broadcast the updated policy.");
            }
        }, cancellationToken);
    }

    private async Task AcceptLoopAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;

            try
            {
                pipe = CreateServerStream();
                await pipe.WaitForConnectionAsync(stoppingToken);
                await ServeAsync(pipe, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (IOException ex)
            {
                // A client that vanished mid-handshake; log quietly and take the next one.
                _logger.LogDebug(ex, "Pipe connection ended unexpectedly.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Accept loop error; retrying shortly.");
                await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken);
            }
            finally
            {
                pipe?.Dispose();
            }
        }
    }

    private async Task ServeAsync(NamedPipeServerStream pipe, CancellationToken stoppingToken)
    {
        using var protocol = new LineProtocol(pipe);

        var session = new ClientSession(
            protocol, _config, _state, _enforcement, _admin,
            _loggerFactory.CreateLogger<ClientSession>());

        _sessions.Add(session);
        try
        {
            await session.RunAsync(stoppingToken);
        }
        finally
        {
            _sessions.Remove(session);
            if (pipe.IsConnected)
            {
                pipe.Disconnect();
            }
        }
    }

    private NamedPipeServerStream CreateServerStream()
    {
        if (OperatingSystem.IsWindows())
        {
            return CreateWindowsServerStream();
        }

        // Developer builds on other platforms: .NET maps named pipes onto Unix domain sockets,
        // which is enough to exercise the protocol end to end, but carries none of the ACLs.
        return new NamedPipeServerStream(
            GuardPaths.PipeName,
            PipeDirection.InOut,
            MaxInstances,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);
    }

    [SupportedOSPlatform("windows")]
    private static NamedPipeServerStream CreateWindowsServerStream() =>
        NamedPipeServerStreamAcl.Create(
            GuardPaths.PipeName,
            PipeDirection.InOut,
            MaxInstances,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            inBufferSize: 0,
            outBufferSize: 0,
            WindowsAcl.CreatePipeSecurity());
}
