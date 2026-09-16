namespace Guard.Core.Detection;

/// <summary>
/// Literal substring matching of configured keywords against a normalized URL.
/// v1 deliberately avoids regular expressions: substrings are predictable for the person
/// writing the keyword list and cannot be turned into a denial of service by a crafted URL.
/// </summary>
public sealed class KeywordMatcher
{
    private readonly MatchingOptions _options;
    private readonly string[] _keywords;
    private readonly string[] _blockedHosts;
    private readonly string[] _allowedHosts;

    public KeywordMatcher(
        IEnumerable<string> keywords,
        MatchingOptions? options = null,
        IEnumerable<string>? blockedHosts = null,
        IEnumerable<string>? allowedHosts = null)
    {
        _options = options ?? MatchingOptions.Default;

        // Keywords are canonicalized with the same pipeline as the URL, so a keyword written
        // as "Restricted Word" still matches "restricted%20word" in a query string.
        _keywords = keywords
            .Where(k => !string.IsNullOrWhiteSpace(k))
            .Select(k => UrlNormalizer.Canonicalize(k.Trim(), _options))
            .Where(k => k.Length > 0)
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        _blockedHosts = NormalizeHosts(blockedHosts);
        _allowedHosts = NormalizeHosts(allowedHosts);
    }

    public int KeywordCount => _keywords.Length;

    public DetectionResult Match(string? rawUrl)
    {
        return Match(UrlNormalizer.Normalize(rawUrl, _options));
    }

    public DetectionResult Match(NormalizedUrl url)
    {
        // Internal browser pages (chrome://, about:, moz-extension://) are never user browsing
        // and blocking them would break the blocked-page UI itself.
        if (url.IsWellFormed && IsInternalScheme(url.Scheme))
        {
            return DetectionResult.NoMatch;
        }

        // The allowlist wins over every rule so an administrator can carve out a site that
        // would otherwise trip on an unrelated keyword.
        if (url.IsWellFormed && MatchesHostList(url.Host, _allowedHosts) is not null)
        {
            return DetectionResult.NoMatch;
        }

        var blockedHost = url.IsWellFormed ? MatchesHostList(url.Host, _blockedHosts) : null;
        if (blockedHost is not null)
        {
            return DetectionResult.Match(blockedHost, UrlPart.Host, "blockedHost", url.Host);
        }

        if (_keywords.Length == 0)
        {
            return DetectionResult.NoMatch;
        }

        // When the URL did not parse we can only search the whole string.
        if (!url.IsWellFormed)
        {
            return FindIn(url.Full, UrlPart.Full);
        }

        if (_options.CheckHost)
        {
            var hit = FindIn(url.Host, UrlPart.Host);
            if (hit.IsMatch) return hit;
        }

        if (_options.CheckPath)
        {
            var hit = FindIn(url.Path, UrlPart.Path);
            if (hit.IsMatch) return hit;
        }

        if (_options.CheckQuery)
        {
            var hit = FindIn(url.Query, UrlPart.Query);
            if (hit.IsMatch) return hit;
        }

        if (_options.CheckFragment)
        {
            var hit = FindIn(url.Fragment, UrlPart.Fragment);
            if (hit.IsMatch) return hit;
        }

        return DetectionResult.NoMatch;
    }

    private DetectionResult FindIn(string haystack, UrlPart part)
    {
        if (haystack.Length == 0)
        {
            return DetectionResult.NoMatch;
        }

        foreach (var keyword in _keywords)
        {
            if (haystack.Contains(keyword, StringComparison.Ordinal))
            {
                return DetectionResult.Match(keyword, part, "keyword", haystack);
            }
        }

        return DetectionResult.NoMatch;
    }

    /// <summary>
    /// Host rules match the host itself and any subdomain of it, so "example.com" also covers
    /// "www.example.com" without covering "notexample.com".
    /// </summary>
    private static string? MatchesHostList(string host, string[] hosts)
    {
        if (host.Length == 0 || hosts.Length == 0)
        {
            return null;
        }

        foreach (var candidate in hosts)
        {
            if (host.Equals(candidate, StringComparison.Ordinal) ||
                host.EndsWith("." + candidate, StringComparison.Ordinal))
            {
                return candidate;
            }
        }

        return null;
    }

    private static string[] NormalizeHosts(IEnumerable<string>? hosts) =>
        (hosts ?? Enumerable.Empty<string>())
            .Where(h => !string.IsNullOrWhiteSpace(h))
            .Select(h => h.Trim().TrimStart('.').ToLowerInvariant())
            .Where(h => h.Length > 0)
            .Distinct(StringComparer.Ordinal)
            .ToArray();

    private static bool IsInternalScheme(string scheme) => scheme is
        "chrome" or "chrome-extension" or "edge" or "about" or "moz-extension" or
        "devtools" or "view-source" or "data" or "blob";
}
