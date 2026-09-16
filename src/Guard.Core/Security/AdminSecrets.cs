using System.Text.Json.Serialization;

namespace Guard.Core.Security;

/// <summary>
/// Contents of %ProgramData%\Guard\secrets\admin.json. The installer ACLs this file down to
/// SYSTEM and Administrators; it holds no recoverable secret, only the password verifier and
/// the brute-force lockout counters.
/// </summary>
public sealed record AdminSecrets
{
    [JsonPropertyName("password")]
    public PasswordHash? Password { get; init; }

    [JsonPropertyName("failedAttempts")]
    public int FailedAttempts { get; init; }

    [JsonPropertyName("lockedUntilUtc")]
    public DateTimeOffset? LockedUntilUtc { get; init; }

    [JsonPropertyName("createdUtc")]
    public DateTimeOffset CreatedUtc { get; init; } = DateTimeOffset.UtcNow;

    [JsonIgnore]
    public bool IsConfigured => Password is not null;

    [JsonIgnore]
    public bool IsLockedOut => LockedUntilUtc is { } until && until > DateTimeOffset.UtcNow;

    [JsonIgnore]
    public int LockoutRemainingSeconds => IsLockedOut
        ? (int)Math.Max(0, (LockedUntilUtc!.Value - DateTimeOffset.UtcNow).TotalSeconds)
        : 0;
}

/// <summary>Tunables for the lockout policy applied after repeated bad passwords.</summary>
public static class LockoutPolicy
{
    public const int MaxAttempts = 5;
    public static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Minimum time every verification takes, successful or not. Combined with PBKDF2 this
    /// caps the rate at which someone can script guesses against the pipe.
    /// </summary>
    public static readonly TimeSpan MinimumVerifyDelay = TimeSpan.FromMilliseconds(750);
}
