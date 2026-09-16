using System.Text.Json.Serialization;

namespace Guard.Core.Configuration;

/// <summary>
/// Runtime state that an administrator can change without editing policy: whether protection
/// is temporarily paused, and until when. Kept separate from <see cref="GuardConfig"/> so a
/// pause never rewrites the policy file.
/// </summary>
public sealed record ProtectionState
{
    [JsonPropertyName("pausedUntilUtc")]
    public DateTimeOffset? PausedUntilUtc { get; init; }

    /// <summary>Free-text reason recorded in the audit log when the pause was granted.</summary>
    [JsonPropertyName("pauseReason")]
    public string? PauseReason { get; init; }

    [JsonIgnore]
    public bool IsPaused => PausedUntilUtc is { } until && until > DateTimeOffset.UtcNow;

    [JsonIgnore]
    public int RemainingSeconds => IsPaused
        ? (int)Math.Max(0, (PausedUntilUtc!.Value - DateTimeOffset.UtcNow).TotalSeconds)
        : 0;

    public static readonly ProtectionState Active = new();
}
