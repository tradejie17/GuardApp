namespace Guard.Core;

/// <summary>
/// Every on-disk location Guard uses. Centralized so the installer, the service, the native
/// host and guardctl can never disagree about where the policy lives.
///
/// On Windows this resolves under %ProgramData%\Guard, which the installer ACLs so that only
/// SYSTEM and Administrators can write. On other platforms it falls back to the local
/// application data folder, which is what makes the detection engine testable off Windows.
/// </summary>
public static class GuardPaths
{
    public const string ServiceName = "GuardService";
    public const string PipeName = "GuardService";
    public const string NativeHostId = "com.guard.windows";

    public static string Root { get; } = ResolveRoot();

    public static string ConfigDirectory => Path.Combine(Root, "config");
    public static string SecretsDirectory => Path.Combine(Root, "secrets");
    public static string LogDirectory => Path.Combine(Root, "logs");

    public static string ConfigFile => Path.Combine(ConfigDirectory, "guard.json");
    public static string StateFile => Path.Combine(ConfigDirectory, "state.json");
    public static string SecretsFile => Path.Combine(SecretsDirectory, "admin.json");

    public static string ServiceLog => Path.Combine(LogDirectory, "guard.log");
    public static string DetectionLog => Path.Combine(LogDirectory, "detections.log");
    public static string AuditLog => Path.Combine(LogDirectory, "audit.log");
    public static string ErrorLog => Path.Combine(LogDirectory, "errors.log");

    /// <summary>Creates the directory tree if it is missing. Safe to call repeatedly.</summary>
    public static void EnsureDirectories()
    {
        Directory.CreateDirectory(ConfigDirectory);
        Directory.CreateDirectory(SecretsDirectory);
        Directory.CreateDirectory(LogDirectory);
    }

    private static string ResolveRoot()
    {
        // GUARD_HOME lets the test suite and a developer sandbox redirect everything without
        // touching the real installation.
        var overridden = Environment.GetEnvironmentVariable("GUARD_HOME");
        if (!string.IsNullOrWhiteSpace(overridden))
        {
            return overridden;
        }

        var baseDir = OperatingSystem.IsWindows()
            ? Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)
            : Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        return Path.Combine(baseDir, "Guard");
    }
}
