using System.Buffers.Binary;
using System.Text;

namespace Guard.NativeHost;

/// <summary>
/// Chrome and Firefox native messaging framing: each message is a 32-bit little-endian byte
/// count followed by that many bytes of UTF-8 JSON, over the process's standard input/output.
/// </summary>
public sealed class NativeMessageStream
{
    /// <summary>
    /// Browsers cap a message from a native host at 1 MB. Anything larger than this is either a
    /// bug or an attempt to exhaust memory, and the connection is dropped.
    /// </summary>
    public const int MaxMessageBytes = 1024 * 1024;

    private readonly Stream _input;
    private readonly Stream _output;
    private readonly SemaphoreSlim _writeGate = new(1, 1);

    public NativeMessageStream(Stream input, Stream output)
    {
        _input = input;
        _output = output;
    }

    /// <summary>Reads one message, or null when the browser closed the port.</summary>
    public async Task<string?> ReadAsync(CancellationToken cancellationToken)
    {
        var header = new byte[4];
        if (!await ReadExactlyAsync(header, cancellationToken))
        {
            return null;
        }

        var length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length is <= 0 or > MaxMessageBytes)
        {
            throw new InvalidDataException($"Native message length {length} is out of range.");
        }

        var payload = new byte[length];
        if (!await ReadExactlyAsync(payload, cancellationToken))
        {
            return null;
        }

        return Encoding.UTF8.GetString(payload);
    }

    public async Task WriteAsync(string json, CancellationToken cancellationToken)
    {
        var payload = Encoding.UTF8.GetBytes(json);
        if (payload.Length > MaxMessageBytes)
        {
            throw new InvalidDataException("Refusing to send an oversized native message.");
        }

        var header = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, payload.Length);

        await _writeGate.WaitAsync(cancellationToken);
        try
        {
            await _output.WriteAsync(header, cancellationToken);
            await _output.WriteAsync(payload, cancellationToken);
            await _output.FlushAsync(cancellationToken);
        }
        finally
        {
            _writeGate.Release();
        }
    }

    private async Task<bool> ReadExactlyAsync(byte[] buffer, CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await _input.ReadAsync(buffer.AsMemory(offset), cancellationToken);
            if (read == 0)
            {
                return false;
            }

            offset += read;
        }

        return true;
    }
}
