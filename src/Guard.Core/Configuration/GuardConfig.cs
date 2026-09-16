using System.Text.Json.Serialization;
using Guard.Core.Detection;

namespace Guard.Core.Configuration;

/// <summary>
/// What the service does when a detection is confirmed.
/// v1 implements <see cref="LogOnly"/> and <see cref="Block"/>; the remaining values are
/// reserved for later versions and currently degrade to <see cref="Block"/>.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum EnforcementAction
{
    None,
    LogOnly,
    Block,
    CloseBrowser,
    LockWindows,
    Shutdown
}

public sealed record EnforcementOptions
{
    [JsonPropertyName("action")]
    public EnforcementAction Action { get; init; } = EnforcementAction.Block;

    /// <summary>Seconds to wait before a destructive action. Ignored by LogOnly and Block.</summary>
    [JsonPropertyName("delaySeconds")]
    public int DelaySeconds { get; init; } = 5;

    /// <summary>Reserved for v1.5: also terminate the offending browser process.</summary>
    [JsonPropertyName("closeBrowser")]
    public bool CloseBrowser { get; init; }
}

public sealed record LoggingOptions
{
    [JsonPropertyName("enabled")]
    public bool Enabled { get; init; } = true;

    /// <summary>
    /// When false (the default) only the host is recorded, never the full URL with its query
    /// string. See docs/PRIVACY.md.
    /// </summary>
    [JsonPropertyName("storeFullUrl")]
    public bool StoreFullUrl { get; init; }

    [JsonPropertyName("retentionDays")]
    public int RetentionDays { get; init; } = 30;
}

/// <summary>
/// The complete administrator-controlled policy. Serialized to
/// %ProgramData%\Guard\config\guard.json and pushed to every connected extension.
/// </summary>
public sealed record GuardConfig
{
    /// <summary>Schema version of this file, bumped when the shape changes.</summary>
    [JsonPropertyName("version")]
    public int Version { get; init; } = 1;

    /// <summary>
    /// Incremented by the service on every successful save. Extensions compare it to decide
    /// whether their cached copy is stale.
    /// </summary>
    [JsonPropertyName("revision")]
    public long Revision { get; init; }

    [JsonPropertyName("keywords")]
    public IReadOnlyList<string> Keywords { get; init; } = Array.Empty<string>();

    /// <summary>Hosts blocked outright, including all their subdomains.</summary>
    [JsonPropertyName("blockedHosts")]
    public IReadOnlyList<string> BlockedHosts { get; init; } = Array.Empty<string>();

    /// <summary>Hosts exempt from every rule. Checked before anything else.</summary>
    [JsonPropertyName("allowedHosts")]
    public IReadOnlyList<string> AllowedHosts { get; init; } = Array.Empty<string>();

    [JsonPropertyName("matching")]
    public MatchingOptions Matching { get; init; } = new();

    [JsonPropertyName("enforcement")]
    public EnforcementOptions Enforcement { get; init; } = new();

    [JsonPropertyName("logging")]
    public LoggingOptions Logging { get; init; } = new();

    public static GuardConfig CreateDefault() => new()
    {
        Version = 1,
        Revision = 1,
        Keywords = new[] { "keyword1" },
        Matching = new MatchingOptions(),
        Enforcement = new EnforcementOptions { Action = EnforcementAction.Block },
        Logging = new LoggingOptions()
    };

    public KeywordMatcher CreateMatcher() =>
        new(Keywords, Matching, BlockedHosts, AllowedHosts);
}
