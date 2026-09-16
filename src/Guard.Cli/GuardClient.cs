using System.IO.Pipes;
using Guard.Core;
using Guard.Core.Messaging;

namespace Guard.Cli;

/// <summary>Opens a short-lived connection to the service for a single administrative command.</summary>
public sealed class GuardClient : IAsyncDisposable
{
    private const int ConnectTimeoutMs = 5000;

    private readonly NamedPipeClientStream _pipe;
    private readonly LineProtocol _protocol;

    private GuardClient(NamedPipeClientStream pipe)
    {
        _pipe = pipe;
        _protocol = new LineProtocol(pipe);
    }

    public static async Task<GuardClient> ConnectAsync(CancellationToken cancellationToken)
    {
        var pipe = new NamedPipeClientStream(
            ".", GuardPaths.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);

        await pipe.ConnectAsync(ConnectTimeoutMs, cancellationToken);
        return new GuardClient(pipe);
    }

    public async Task<AdminResponse> SendAsync(AdminRequest request, CancellationToken cancellationToken)
    {
        await _protocol.WriteLineAsync(GuardJson.Serialize(request), cancellationToken);

        var line = await _protocol.ReadLineAsync(cancellationToken);
        if (line is null)
        {
            return AdminResponse.Fail("The service closed the connection without replying.");
        }

        return GuardJson.Deserialize<AdminResponse>(line)
               ?? AdminResponse.Fail("The service sent a reply that could not be understood.");
    }

    public async ValueTask DisposeAsync()
    {
        _protocol.Dispose();
        await _pipe.DisposeAsync();
    }
}
