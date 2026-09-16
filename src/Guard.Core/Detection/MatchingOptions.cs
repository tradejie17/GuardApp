using System.Text.Json.Serialization;

namespace Guard.Core.Detection;

/// <summary>
/// How URLs are prepared for matching and which components are searched.
/// Mirrors the "matching" block of keywords.json.
/// </summary>
public sealed record MatchingOptions
{
    public static readonly MatchingOptions Default = new();

    [JsonPropertyName("caseSensitive")]
    public bool CaseSensitive { get; init; }

    [JsonPropertyName("decodeUrl")]
    public bool DecodeUrl { get; init; } = true;

    /// <summary>Fold compatibility Unicode forms (full-width characters) onto ASCII.</summary>
    [JsonPropertyName("normalizeUnicode")]
    public bool NormalizeUnicode { get; init; } = true;

    [JsonPropertyName("checkHost")]
    public bool CheckHost { get; init; } = true;

    [JsonPropertyName("checkPath")]
    public bool CheckPath { get; init; } = true;

    [JsonPropertyName("checkQuery")]
    public bool CheckQuery { get; init; } = true;

    [JsonPropertyName("checkFragment")]
    public bool CheckFragment { get; init; } = true;
}
