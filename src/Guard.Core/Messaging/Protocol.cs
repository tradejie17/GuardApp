using System.Text.Json;
using System.Text.Json.Serialization;
using Guard.Core.Configuration;
using Guard.Core.Detection;

namespace Guard.Core.Messaging;

/// <summary>
/// Well-known message type discriminators. Every frame on the pipe and every native-messaging
/// packet is a JSON object carrying one of these in its "type" field.
/// </summary>
public static class MessageTypes
{
    // Extension -> service
    public const string Hello = "hello";
    public const string Detection = "detection";
    public const string Heartbeat = "heartbeat";

    // Service -> extension
    public const string Config = "config";
    public const string ConfigChanged = "configChanged";
    public const string Verdict = "verdict";
    public const string Pong = "pong";
    public const string Error = "error";

    // guardctl <-> service
    public const string Admin = "admin";
    public const string AdminResult = "adminResult";
}

/// <summary>Shared serializer settings so every process frames JSON identically.</summary>
public static class GuardJson
{
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false
    };

    public static readonly JsonSerializerOptions FileOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = true
    };

    public static string Serialize<T>(T value) => JsonSerializer.Serialize(value, Options);

    public static T? Deserialize<T>(string json) => JsonSerializer.Deserialize<T>(json, Options);
}

/// <summary>A detection reported by a browser extension. Treated as untrusted input.</summary>
public sealed record DetectionMessage
{
    [JsonPropertyName("type")]
    public string Type { get; init; } = MessageTypes.Detection;

    /// <summary>chrome | edge | avast | firefox. Validated against a known set by the service.</summary>
    [JsonPropertyName("browser")]
    public string? Browser { get; init; }

    [JsonPropertyName("url")]
    public string? Url { get; init; }

    /// <summary>The keyword the extension believes matched. Re-verified by the service.</summary>
    [JsonPropertyName("keyword")]
    public string? Keyword { get; init; }

    [JsonPropertyName("part")]
    public string? Part { get; init; }

    [JsonPropertyName("tabId")]
    public int? TabId { get; init; }

    [JsonPropertyName("timestamp")]
    public DateTimeOffset? Timestamp { get; init; }

    /// <summary>Correlates the verdict with the request when several are in flight.</summary>
    [JsonPropertyName("requestId")]
    public string? RequestId { get; init; }
}

/// <summary>The service's answer to a reported detection.</summary>
public sealed record VerdictMessage
{
    [JsonPropertyName("type")]
    public string Type { get; init; } = MessageTypes.Verdict;

    [JsonPropertyName("requestId")]
    public string? RequestId { get; init; }

    /// <summary>True when the navigation should be allowed through after all.</summary>
    [JsonPropertyName("allow")]
    public bool Allow { get; init; }

    [JsonPropertyName("action")]
    public EnforcementAction Action { get; init; }

    /// <summary>Reason shown on the block page, e.g. "restricted keyword".</summary>
    [JsonPropertyName("reason")]
    public string? Reason { get; init; }
}

/// <summary>
/// The policy snapshot pushed to extensions. It intentionally contains only what an extension
/// needs to block locally; nothing about passwords or logging paths crosses this boundary.
/// </summary>
public sealed record ConfigMessage
{
    [JsonPropertyName("type")]
    public string Type { get; init; } = MessageTypes.Config;

    [JsonPropertyName("revision")]
    public long Revision { get; init; }

    [JsonPropertyName("paused")]
    public bool Paused { get; init; }

    [JsonPropertyName("pausedSeconds")]
    public int PausedSeconds { get; init; }

    [JsonPropertyName("keywords")]
    public IReadOnlyList<string> Keywords { get; init; } = Array.Empty<string>();

    [JsonPropertyName("blockedHosts")]
    public IReadOnlyList<string> BlockedHosts { get; init; } = Array.Empty<string>();

    [JsonPropertyName("allowedHosts")]
    public IReadOnlyList<string> AllowedHosts { get; init; } = Array.Empty<string>();

    [JsonPropertyName("matching")]
    public MatchingOptions Matching { get; init; } = new();

    [JsonPropertyName("action")]
    public EnforcementAction Action { get; init; }

    public static ConfigMessage From(GuardConfig config, ProtectionState state, string type = MessageTypes.Config) => new()
    {
        Type = type,
        Revision = config.Revision,
        Paused = state.IsPaused,
        PausedSeconds = state.RemainingSeconds,
        Keywords = config.Keywords,
        BlockedHosts = config.BlockedHosts,
        AllowedHosts = config.AllowedHosts,
        Matching = config.Matching,
        Action = config.Enforcement.Action
    };
}
