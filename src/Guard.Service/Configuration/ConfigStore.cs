using System.Text.Json;
using Guard.Core;
using Guard.Core.Configuration;
using Guard.Core.Detection;
using Guard.Core.Messaging;
using Guard.Service.Security;

namespace Guard.Service.Configuration;

/// <summary>
/// Owns guard.json: loads it at startup, hands out an immutable snapshot plus a prebuilt
/// matcher, and persists edits atomically with the revision bumped so extensions can tell a
/// stale cache from a current one.
/// </summary>
public sealed class ConfigStore
{
    private readonly ILogger<ConfigStore> _logger;
    private readonly object _gate = new();

    private GuardConfig _config = GuardConfig.CreateDefault();
    private KeywordMatcher _matcher;

    /// <summary>Raised after a successful save so connected extensions can be re-pushed.</summary>
    public event Action<GuardConfig>? Changed;

    public ConfigStore(ILogger<ConfigStore> logger)
    {
        _logger = logger;
        _matcher = _config.CreateMatcher();
    }

    public GuardConfig Current
    {
        get { lock (_gate) return _config; }
    }

    public KeywordMatcher Matcher
    {
        get { lock (_gate) return _matcher; }
    }

    public void Load()
    {
        GuardPaths.EnsureDirectories();

        if (!File.Exists(GuardPaths.ConfigFile))
        {
            _logger.LogWarning("No policy at {Path}; writing defaults (LogOnly-safe starter list).", GuardPaths.ConfigFile);
            Save(GuardConfig.CreateDefault(), bumpRevision: false);
            return;
        }

        try
        {
            var json = File.ReadAllText(GuardPaths.ConfigFile);
            var loaded = JsonSerializer.Deserialize<GuardConfig>(json, GuardJson.FileOptions);

            if (loaded is null)
            {
                throw new InvalidDataException("Policy file deserialized to null.");
            }

            lock (_gate)
            {
                _config = loaded;
                _matcher = loaded.CreateMatcher();
            }

            _logger.LogInformation(
                "Loaded policy revision {Revision}: {Keywords} keyword(s), {Blocked} blocked host(s), action {Action}.",
                loaded.Revision, loaded.Keywords.Count, loaded.BlockedHosts.Count, loaded.Enforcement.Action);
        }
        catch (Exception ex)
        {
            // A corrupt policy file must not become a way to disable protection, so the
            // in-memory policy from the previous load (or the default) stays in force.
            _logger.LogError(ex, "Policy at {Path} is unreadable; keeping the previous policy in force.", GuardPaths.ConfigFile);
        }
    }

    /// <summary>Persists a new policy and returns the saved copy, with revision incremented.</summary>
    public GuardConfig Save(GuardConfig config, bool bumpRevision = true)
    {
        GuardPaths.EnsureDirectories();

        GuardConfig toSave;
        lock (_gate)
        {
            toSave = bumpRevision ? config with { Revision = _config.Revision + 1 } : config;
            WriteAtomic(toSave);
            _config = toSave;
            _matcher = toSave.CreateMatcher();
        }

        WindowsAcl.RestrictToAdministrators(GuardPaths.ConfigFile, _logger);
        Changed?.Invoke(toSave);
        return toSave;
    }

    /// <summary>
    /// Writes through a temporary file so a crash mid-write can never leave a half-written
    /// policy that would fail to load on the next start.
    /// </summary>
    private static void WriteAtomic(GuardConfig config)
    {
        var json = JsonSerializer.Serialize(config, GuardJson.FileOptions);
        var temp = GuardPaths.ConfigFile + ".tmp";

        File.WriteAllText(temp, json);

        if (File.Exists(GuardPaths.ConfigFile))
        {
            File.Replace(temp, GuardPaths.ConfigFile, null);
        }
        else
        {
            File.Move(temp, GuardPaths.ConfigFile);
        }
    }
}
