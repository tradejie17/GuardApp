using System.Text;

namespace Guard.Core.Messaging;

/// <summary>
/// Newline-delimited JSON over a duplex stream, with a hard cap on how long one line may be.
///
/// StreamReader.ReadLineAsync would happily buffer an unbounded line, which a local process
/// could use to exhaust the service's memory. This reader gives up on the connection instead.
/// </summary>
public sealed class LineProtocol : IDisposable
{
    public const int MaxLineBytes = 64 * 1024;

    private readonly Stream _stream;
    private readonly SemaphoreSlim _writeGate = new(1, 1);
    private readonly byte[] _readBuffer = new byte[4096];
    private readonly MemoryStream _pending = new();

    private int _bufferOffset;
    private int _bufferLength;

    public LineProtocol(Stream stream) => _stream = stream;

    /// <summary>Reads one line, or null when the peer closed the connection.</summary>
    /// <exception cref="InvalidDataException">The peer sent an over-long line.</exception>
    public async Task<string?> ReadLineAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            if (_bufferOffset >= _bufferLength)
            {
                _bufferLength = await _stream.ReadAsync(_readBuffer, cancellationToken);
                _bufferOffset = 0;

                if (_bufferLength == 0)
                {
                    return _pending.Length > 0 ? TakePending() : null;
                }
            }

            while (_bufferOffset < _bufferLength)
            {
                var current = _readBuffer[_bufferOffset++];

                if (current == (byte)'\n')
                {
                    return TakePending();
                }

                if (current == (byte)'\r')
                {
                    continue;
                }

                if (_pending.Length >= MaxLineBytes)
                {
                    throw new InvalidDataException($"Message exceeded {MaxLineBytes} bytes.");
                }

                _pending.WriteByte(current);
            }
        }
    }

    public async Task WriteLineAsync(string json, CancellationToken cancellationToken)
    {
        var payload = Encoding.UTF8.GetBytes(json + "\n");

        await _writeGate.WaitAsync(cancellationToken);
        try
        {
            await _stream.WriteAsync(payload, cancellationToken);
            await _stream.FlushAsync(cancellationToken);
        }
        finally
        {
            _writeGate.Release();
        }
    }

    private string TakePending()
    {
        var text = Encoding.UTF8.GetString(_pending.GetBuffer(), 0, (int)_pending.Length);
        _pending.SetLength(0);
        return text;
    }

    public void Dispose()
    {
        _writeGate.Dispose();
        _pending.Dispose();
    }
}
