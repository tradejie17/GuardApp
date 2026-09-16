/*
 * Guard.NativeHost — the bridge between a browser extension and the Guard Windows service.
 *
 * The browser launches this process inside the user's own session and talks to it over stdio
 * using native-messaging framing. The service runs as SYSTEM and listens on a named pipe. This
 * process does nothing but translate between the two framings; it holds no policy, makes no
 * decisions, and has no privileges of its own, which is what keeps the trust boundary clean.
 *
 * If the service is not reachable the host exits promptly, so the extension sees the port close
 * and retries with backoff, meanwhile continuing to enforce its cached policy.
 */

using System.IO.Pipes;
using Guard.Core;
using Guard.Core.Messaging;
using Guard.NativeHost;

const int ConnectTimeoutMs = 5000;

var log = new HostLog();
using var shutdown = new CancellationTokenSource();

try
{
    await using var pipe = new NamedPipeClientStream(
        ".", GuardPaths.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);

    try
    {
        await pipe.ConnectAsync(ConnectTimeoutMs, shutdown.Token);
    }
    catch (Exception ex) when (ex is TimeoutException or IOException)
    {
        log.Write($"Guard service is not reachable on pipe '{GuardPaths.PipeName}': {ex.Message}");
        return 2;
    }

    var native = new NativeMessageStream(Console.OpenStandardInput(), Console.OpenStandardOutput());
    using var protocol = new LineProtocol(pipe);

    // Both directions run until either side closes, then the whole process goes down together.
    var browserToService = PumpBrowserAsync(native, protocol, log, shutdown);
    var serviceToBrowser = PumpServiceAsync(native, protocol, log, shutdown);

    await Task.WhenAny(browserToService, serviceToBrowser);
    shutdown.Cancel();
    await Task.WhenAll(
        browserToService.ContinueWith(_ => { }, TaskScheduler.Default),
        serviceToBrowser.ContinueWith(_ => { }, TaskScheduler.Default));

    return 0;
}
catch (Exception ex)
{
    log.Write("Native host terminated: " + ex);
    return 1;
}

static async Task PumpBrowserAsync(
    NativeMessageStream native, LineProtocol protocol, HostLog log, CancellationTokenSource shutdown)
{
    try
    {
        while (!shutdown.IsCancellationRequested)
        {
            var message = await native.ReadAsync(shutdown.Token);
            if (message is null)
            {
                return;
            }

            await protocol.WriteLineAsync(message, shutdown.Token);
        }
    }
    catch (OperationCanceledException)
    {
    }
    catch (Exception ex)
    {
        log.Write("browser -> service pump ended: " + ex.Message);
    }
}

static async Task PumpServiceAsync(
    NativeMessageStream native, LineProtocol protocol, HostLog log, CancellationTokenSource shutdown)
{
    try
    {
        while (!shutdown.IsCancellationRequested)
        {
            var line = await protocol.ReadLineAsync(shutdown.Token);
            if (line is null)
            {
                return;
            }

            if (line.Length > 0)
            {
                await native.WriteAsync(line, shutdown.Token);
            }
        }
    }
    catch (OperationCanceledException)
    {
    }
    catch (Exception ex)
    {
        log.Write("service -> browser pump ended: " + ex.Message);
    }
}
