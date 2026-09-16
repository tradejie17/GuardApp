using Guard.Core;
using Guard.Core.Configuration;
using Guard.Core.Detection;

namespace Guard.Service.Logging;

/// <summary>
/// Writes the two records that matter operationally: what was detected, and what an
/// administrator did.
///
/// Privacy is a design constraint, not an afterthought. Unless logging.storeFullUrl is switched
/// on, a detection records the host and the matched keyword but never the full URL with its
/// query string, so the log does not become a browsing history.
/// </summary>
public sealed class GuardLogger
{
    private const long MaxFileBytes = 5 * 1024 * 1024;

    private readonly ILogger<GuardLogger> _logger;
    private readonly object _gate = new();

    public GuardLogger(ILogger<GuardLogger> logger) => _logger = logger;

    public void Detection(string browser, string url, DetectionResult result, EnforcementAction action, LoggingOptions options)
    {
        if (!options.Enabled)
        {
            return;
        }

        var target = options.StoreFullUrl ? url : DescribeHost(url);

        var line = string.Join(" | ",
            Timestamp(),
            $"browser={browser}",
            $"rule={result.RuleType}",
            $"keyword={result.Keyword}",
            $"part={result.MatchedIn}",
            $"target={target}",
            $"action={action}");

        Append(GuardPaths.DetectionLog, line);
    }

    /// <summary>Records an administrative action or a refused attempt at one.</summary>
    public void Audit(string command, bool allowed, string detail)
    {
        var line = string.Join(" | ",
            Timestamp(),
            $"command={command}",
            allowed ? "result=allowed" : "result=refused",
            detail);

        Append(GuardPaths.AuditLog, line);
    }

    /// <summary>
    /// Reduces a URL to scheme and host, which is enough to recognize a pattern of detections
    /// without recording what was searched for.
    /// </summary>
    private static string DescribeHost(string url)
    {
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return $"{uri.Scheme}://{uri.Host}";
        }

        return "(unparsed)";
    }

    private static string Timestamp() => DateTimeOffset.Now.ToString("yyyy-MM-dd HH:mm:ss zzz");

    private void Append(string path, string line)
    {
        try
        {
            lock (_gate)
            {
                GuardPaths.EnsureDirectories();
                RotateIfLarge(path);
                File.AppendAllText(path, line + Environment.NewLine);
            }
        }
        catch (Exception ex)
        {
            // Logging must never take the service down or block a detection from being enforced.
            _logger.LogError(ex, "Failed to append to {Path}.", path);
        }
    }

    private static void RotateIfLarge(string path)
    {
        var info = new FileInfo(path);
        if (!info.Exists || info.Length < MaxFileBytes)
        {
            return;
        }

        var archived = path + "." + DateTime.Now.ToString("yyyyMMddHHmmss");
        File.Move(path, archived);
    }

    /// <summary>Deletes rotated log files older than the configured retention window.</summary>
    public void PurgeExpired(LoggingOptions options)
    {
        if (options.RetentionDays <= 0)
        {
            return;
        }

        var cutoff = DateTime.Now.AddDays(-options.RetentionDays);

        try
        {
            foreach (var file in Directory.EnumerateFiles(GuardPaths.LogDirectory, "*.log.*"))
            {
                if (File.GetLastWriteTime(file) < cutoff)
                {
                    File.Delete(file);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Log retention sweep failed.");
        }
    }
}
