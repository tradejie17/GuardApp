namespace Guard.Core.Detection;

/// <summary>Which part of the URL a keyword was found in.</summary>
public enum UrlPart
{
    None = 0,
    Host,
    Path,
    Query,
    Fragment,
    Full
}

/// <summary>
/// The outcome of running a single URL through the keyword engine.
/// A negative result is represented by <see cref="NoMatch"/> rather than null so callers
/// never have to null-check a detection.
/// </summary>
public sealed record DetectionResult
{
    public static readonly DetectionResult NoMatch = new();

    /// <summary>True when a restricted keyword or blocked host matched.</summary>
    public bool IsMatch { get; init; }

    /// <summary>The keyword (or blocked host pattern) that matched, as written in config.</summary>
    public string? Keyword { get; init; }

    /// <summary>Which URL component the match was found in.</summary>
    public UrlPart MatchedIn { get; init; } = UrlPart.None;

    /// <summary>The rule family that produced the match: "keyword" or "blockedHost".</summary>
    public string? RuleType { get; init; }

    /// <summary>
    /// The normalized text the match was found in. Useful for debugging false positives,
    /// but never written to persistent logs unless logging.storeFullUrl is enabled.
    /// </summary>
    public string? MatchedText { get; init; }

    public static DetectionResult Match(string keyword, UrlPart part, string ruleType, string matchedText) =>
        new()
        {
            IsMatch = true,
            Keyword = keyword,
            MatchedIn = part,
            RuleType = ruleType,
            MatchedText = matchedText
        };
}
