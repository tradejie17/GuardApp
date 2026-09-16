using System.Text.Json;
using Guard.Core;
using Guard.Core.Configuration;
using Guard.Core.Messaging;
using Guard.Service.Security;

namespace Guard.Service.Configuration;

/// <summary>
/// Owns state.json — currently just the pause window. Kept apart from the policy so granting a
/// temporary unlock never rewrites, and so cannot corrupt, the rules themselves.
/// </summary>
public sealed class StateStore
{
    private readonly ILogger<StateStore> _logger;
    private readonly object _gate = new();

    private ProtectionState _state = ProtectionState.Active;

    public event Action<ProtectionState>? Changed;

    public StateStore(ILogger<StateStore> logger) => _logger = logger;

    public ProtectionState Current
    {
        get
        {
            lock (_gate)
            {
                // An expired pause is collapsed on read so nothing downstream has to think
                // about clock arithmetic.
                if (_state.PausedUntilUtc is not null && !_state.IsPaused)
                {
                    _state = ProtectionState.Active;
                }

                return _state;
            }
        }
    }

    public void Load()
    {
        GuardPaths.EnsureDirectories();

        if (!File.Exists(GuardPaths.StateFile))
        {
            return;
        }

        try
        {
            var json = File.ReadAllText(GuardPaths.StateFile);
            var loaded = JsonSerializer.Deserialize<ProtectionState>(json, GuardJson.FileOptions);
            if (loaded is not null)
            {
                lock (_gate) _state = loaded;
                if (loaded.IsPaused)
                {
                    _logger.LogWarning("Protection is paused for another {Seconds}s (reason: {Reason}).",
                        loaded.RemainingSeconds, loaded.PauseReason ?? "none given");
                }
            }
        }
        catch (Exception ex)
        {
            // Failing to read the pause state means protection stays on, which is the safe side.
            _logger.LogError(ex, "Could not read {Path}; protection remains active.", GuardPaths.StateFile);
        }
    }

    public ProtectionState Pause(TimeSpan duration, string? reason)
    {
        var state = new ProtectionState
        {
            PausedUntilUtc = DateTimeOffset.UtcNow.Add(duration),
            PauseReason = reason
        };

        return Apply(state);
    }

    public ProtectionState Resume() => Apply(ProtectionState.Active);

    private ProtectionState Apply(ProtectionState state)
    {
        lock (_gate)
        {
            _state = state;
            var json = JsonSerializer.Serialize(state, GuardJson.FileOptions);
            var temp = GuardPaths.StateFile + ".tmp";
            File.WriteAllText(temp, json);

            if (File.Exists(GuardPaths.StateFile))
            {
                File.Replace(temp, GuardPaths.StateFile, null);
            }
            else
            {
                File.Move(temp, GuardPaths.StateFile);
            }
        }

        WindowsAcl.RestrictToAdministrators(GuardPaths.StateFile, _logger);
        Changed?.Invoke(state);
        return state;
    }
}
