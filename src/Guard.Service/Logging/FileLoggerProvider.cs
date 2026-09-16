using System.Collections.Concurrent;
using Guard.Core;

namespace Guard.Service.Logging;

/// <summary>
/// A minimal file logger for guard.log. A Windows service has no console, and pulling in a
/// logging framework for one text file is not worth the dependency; this writes the same lines
/// the console provider would.
/// </summary>
public sealed class FileLoggerProvider : ILoggerProvider
{
    private const long MaxFileBytes = 5 * 1024 * 1024;

    private readonly string _path;
    private readonly object _gate = new();
    private readonly ConcurrentDictionary<string, FileLogger> _loggers = new();

    public FileLoggerProvider(string path)
    {
        _path = path;
        GuardPaths.EnsureDirectories();
    }

    public ILogger CreateLogger(string categoryName) =>
        _loggers.GetOrAdd(categoryName, name => new FileLogger(this, name));

    public void Dispose() => _loggers.Clear();

    private void Write(string line)
    {
        try
        {
            lock (_gate)
            {
                var info = new FileInfo(_path);
                if (info.Exists && info.Length >= MaxFileBytes)
                {
                    File.Move(_path, _path + "." + DateTime.Now.ToString("yyyyMMddHHmmss"));
                }

                File.AppendAllText(_path, line + Environment.NewLine);
            }
        }
        catch
        {
            // A logger that throws would take the service down with it.
        }
    }

    private sealed class FileLogger : ILogger
    {
        private readonly FileLoggerProvider _provider;
        private readonly string _category;

        public FileLogger(FileLoggerProvider provider, string category)
        {
            _provider = provider;
            // Category names are namespace-qualified; the last segment is enough to read a log.
            _category = category.Split('.').Last();
        }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Information;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel))
            {
                return;
            }

            var line = $"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz} [{Abbreviate(logLevel)}] {_category}: {formatter(state, exception)}";
            if (exception is not null)
            {
                line += Environment.NewLine + exception;
            }

            _provider.Write(line);
        }

        private static string Abbreviate(LogLevel level) => level switch
        {
            LogLevel.Trace => "trce",
            LogLevel.Debug => "dbug",
            LogLevel.Information => "info",
            LogLevel.Warning => "warn",
            LogLevel.Error => "fail",
            LogLevel.Critical => "crit",
            _ => "none"
        };
    }
}
