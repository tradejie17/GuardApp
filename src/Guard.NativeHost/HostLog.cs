namespace Guard.NativeHost;

/// <summary>
/// Diagnostics for the native host.
///
/// The host runs as the restricted user, who by design cannot write into the service's log
/// directory under %ProgramData%. Its log therefore lives in the user's own profile, and it
/// records only connection problems — never URLs.
/// </summary>
public sealed class HostLog
{
    private readonly string? _path;

    public HostLog()
    {
        try
        {
            var directory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Guard");

            Directory.CreateDirectory(directory);
            _path = Path.Combine(directory, "nativehost.log");
        }
        catch
        {
            // Without somewhere to write we simply run without diagnostics; stderr still
            // reaches the browser's own extension log.
            _path = null;
        }
    }

    public void Write(string message)
    {
        var line = $"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss} {message}";

        Console.Error.WriteLine(line);

        if (_path is null)
        {
            return;
        }

        try
        {
            File.AppendAllText(_path, line + Environment.NewLine);
        }
        catch
        {
            // Never let logging break the bridge.
        }
    }
}
