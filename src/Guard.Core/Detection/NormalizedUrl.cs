namespace Guard.Core.Detection;

/// <summary>
/// A URL broken into its components after decoding and case normalization.
/// Produced by <see cref="UrlNormalizer"/> and consumed by <see cref="KeywordMatcher"/>.
/// </summary>
public sealed record NormalizedUrl
{
    /// <summary>The URL exactly as the browser reported it.</summary>
    public required string Original { get; init; }

    /// <summary>Host name, lowercased. Empty when the input was not a parseable absolute URL.</summary>
    public string Host { get; init; } = string.Empty;

    /// <summary>Path portion, decoded and normalized. Empty when not parseable.</summary>
    public string Path { get; init; } = string.Empty;

    /// <summary>Query string without the leading '?', decoded and normalized.</summary>
    public string Query { get; init; } = string.Empty;

    /// <summary>Fragment without the leading '#', decoded and normalized.</summary>
    public string Fragment { get; init; } = string.Empty;

    /// <summary>
    /// The whole URL decoded and normalized. Used when the input could not be parsed as an
    /// absolute URL, and as the fallback search target when no component checks are enabled.
    /// </summary>
    public required string Full { get; init; }

    /// <summary>False when the input could not be parsed as an absolute URI.</summary>
    public bool IsWellFormed { get; init; }

    /// <summary>The scheme (http, https, file, ...) lowercased, or empty.</summary>
    public string Scheme { get; init; } = string.Empty;
}
