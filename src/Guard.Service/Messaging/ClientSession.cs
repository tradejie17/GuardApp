using System.Collections.Concurrent;
using System.Text.Json;
using Guard.Core.Configuration;
using Guard.Core.Messaging;
using Guard.Service.Admin;
using Guard.Service.Configuration;
using Guard.Service.Enforcement;

namespace Guard.Service.Messaging;

/// <summary>
/// Tracks every open connection so a policy change can be pushed to all of them at once.
/// </summary>
public sealed class SessionRegistry
{
    private readonly ConcurrentDictionary<Guid, ClientSession> _sessions = new();

    public void Add(ClientSession session) => _sessions[session.Id] = session;

    public void Remove(ClientSession session) => _sessions.TryRemove(session.Id, out _);

    public int Count => _sessions.Count;

    public async Task BroadcastAsync(ConfigMessage message, CancellationToken cancellationToken)
    {
        var json = GuardJson.Serialize(message);

        foreach (var session in _sessions.Values)
        {
            if (session.IsExtension)
            {
                await session.TrySendAsync(json, cancellationToken);
            }
        }
    }
}

/// <summary>
/// One connection from a native messaging host or from guardctl.
///
/// Both speak the same newline-delimited JSON protocol on the same pipe; they are distinguished
/// by the messages they send, not by any claim they make about who they are. Nothing a caller
/// says about its own identity grants it anything: administrative commands are gated on the
/// password alone.
/// </summary>
public sealed class ClientSession
{
    private readonly LineProtocol _protocol;
    private readonly ConfigStore _config;
    private readonly StateStore _state;
    private readonly EnforcementManager _enforcement;
    private readonly AdminCommandHandler _admin;
    private readonly ILogger _logger;

    public ClientSession(
        LineProtocol protocol,
        ConfigStore config,
        StateStore state,
        EnforcementManager enforcement,
        AdminCommandHandler admin,
        ILogger logger)
    {
        _protocol = protocol;
        _config = config;
        _state = state;
        _enforcement = enforcement;
        _admin = admin;
        _logger = logger;
    }

    public Guid Id { get; } = Guid.NewGuid();

    /// <summary>True once the peer has identified itself as a browser extension.</summary>
    public bool IsExtension { get; private set; }

    public string? Browser { get; private set; }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            string? line;
            try
            {
                line = await _protocol.ReadLineAsync(cancellationToken);
            }
            catch (InvalidDataException ex)
            {
                _logger.LogWarning("Dropping connection: {Reason}", ex.Message);
                return;
            }

            if (line is null)
            {
                return;
            }

            if (line.Length == 0)
            {
                continue;
            }

            await HandleLineAsync(line, cancellationToken);
        }
    }

    private async Task HandleLineAsync(string line, CancellationToken cancellationToken)
    {
        string type;
        try
        {
            using var document = JsonDocument.Parse(line);
            type = document.RootElement.TryGetProperty("type", out var typeElement)
                ? typeElement.GetString() ?? string.Empty
                : string.Empty;
        }
        catch (JsonException)
        {
            _logger.LogWarning("Ignoring malformed JSON from a client.");
            await SendAsync(new { type = MessageTypes.Error, error = "malformed json" }, cancellationToken);
            return;
        }

        switch (type)
        {
            case MessageTypes.Hello:
                await HandleHelloAsync(line, cancellationToken);
                break;

            case MessageTypes.Heartbeat:
                await SendAsync(new
                {
                    type = MessageTypes.Pong,
                    revision = _config.Current.Revision,
                    paused = _state.Current.IsPaused
                }, cancellationToken);
                break;

            case MessageTypes.Detection:
                await HandleDetectionAsync(line, cancellationToken);
                break;

            case MessageTypes.Admin:
                await HandleAdminAsync(line, cancellationToken);
                break;

            default:
                await SendAsync(new { type = MessageTypes.Error, error = $"unknown message type '{type}'" }, cancellationToken);
                break;
        }
    }

    private async Task HandleHelloAsync(string line, CancellationToken cancellationToken)
    {
        var hello = Deserialize<DetectionMessage>(line);

        IsExtension = true;
        Browser = hello?.Browser;
        _logger.LogInformation("Extension connected from {Browser}.", Browser ?? "unknown");

        await SendAsync(ConfigMessage.From(_config.Current, _state.Current), cancellationToken);
    }

    private async Task HandleDetectionAsync(string line, CancellationToken cancellationToken)
    {
        var detection = Deserialize<DetectionMessage>(line);
        if (detection is null)
        {
            await SendAsync(new { type = MessageTypes.Error, error = "invalid detection message" }, cancellationToken);
            return;
        }

        IsExtension = true;
        Browser ??= detection.Browser;

        var verdict = _enforcement.Handle(detection);
        await SendAsync(verdict, cancellationToken);
    }

    private async Task HandleAdminAsync(string line, CancellationToken cancellationToken)
    {
        var request = Deserialize<AdminRequest>(line);
        if (request is null || string.IsNullOrWhiteSpace(request.Command))
        {
            await SendAsync(AdminResponse.Fail("Invalid administrative request."), cancellationToken);
            return;
        }

        var response = await _admin.HandleAsync(request, cancellationToken);
        await SendAsync(response, cancellationToken);
    }

    private static T? Deserialize<T>(string line)
    {
        try
        {
            return GuardJson.Deserialize<T>(line);
        }
        catch (JsonException)
        {
            return default;
        }
    }

    private Task SendAsync<T>(T message, CancellationToken cancellationToken) =>
        _protocol.WriteLineAsync(GuardJson.Serialize(message), cancellationToken);

    /// <summary>Sends pre-serialized JSON, swallowing errors from a peer that has gone away.</summary>
    public async Task TrySendAsync(string json, CancellationToken cancellationToken)
    {
        try
        {
            await _protocol.WriteLineAsync(json, cancellationToken);
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or OperationCanceledException)
        {
            _logger.LogDebug("Broadcast to a disconnected client was dropped.");
        }
    }
}
