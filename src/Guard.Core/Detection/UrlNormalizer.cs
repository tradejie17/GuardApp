using System.Text;

namespace Guard.Core.Detection;

/// <summary>
/// Turns a raw browser URL into a <see cref="NormalizedUrl"/> so that keyword matching is not
/// defeated by percent-encoding, '+' separators, mixed case or compatibility Unicode forms.
/// The normalizer never touches the network and never allocates per-keyword state, so it is
/// safe to call on every navigation event.
/// </summary>
public static class UrlNormalizer
{
    /// <summary>
    /// Percent-decoding is applied repeatedly so that double-encoded payloads such as
    /// "%2520" collapse to a space, but capped so a hostile URL cannot spin the CPU.
    /// </summary>
    private const int MaxDecodePasses = 3;

    /// <summary>Upper bound on the input we will process; anything longer is truncated.</summary>
    public const int MaxUrlLength = 8192;

    public static NormalizedUrl Normalize(string? rawUrl, MatchingOptions? options = null)
    {
        options ??= MatchingOptions.Default;
        var raw = rawUrl ?? string.Empty;
        if (raw.Length > MaxUrlLength)
        {
            raw = raw[..MaxUrlLength];
        }

        var full = Canonicalize(raw, options);

        if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri))
        {
            return new NormalizedUrl { Original = rawUrl ?? string.Empty, Full = full, IsWellFormed = false };
        }

        // Uri splits the components for us; each one is decoded independently so a keyword
        // that spans a component boundary in the raw string still cannot produce a false match.
        var query = uri.Query.StartsWith('?') ? uri.Query[1..] : uri.Query;
        var fragment = uri.Fragment.StartsWith('#') ? uri.Fragment[1..] : uri.Fragment;

        return new NormalizedUrl
        {
            Original = rawUrl ?? string.Empty,
            Scheme = uri.Scheme.ToLowerInvariant(),
            Host = Canonicalize(uri.Host, options),
            Path = Canonicalize(uri.AbsolutePath, options),
            Query = Canonicalize(query, options),
            Fragment = Canonicalize(fragment, options),
            Full = full,
            IsWellFormed = true
        };
    }

    /// <summary>
    /// Applies the decode / case / Unicode pipeline to a single piece of text.
    /// Exposed so the search-query extractor and the tests can reuse the exact same rules.
    /// </summary>
    public static string Canonicalize(string value, MatchingOptions options)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        var text = value;

        if (options.DecodeUrl)
        {
            // '+' means space in query strings; doing this before unescaping matches how
            // browsers and servers interpret form encoding.
            text = text.Replace('+', ' ');
            text = DecodeRepeatedly(text);
        }

        // Compatibility normalization folds full-width and other look-alike forms
        // (e.g. "ｋｅｙｗｏｒｄ") onto their ASCII equivalents.
        if (options.NormalizeUnicode)
        {
            try
            {
                text = text.Normalize(NormalizationForm.FormKC);
            }
            catch (ArgumentException)
            {
                // Invalid surrogate pairs cannot be normalized; matching against the raw text
                // is still better than dropping the navigation event entirely.
            }
        }

        if (!options.CaseSensitive)
        {
            text = text.ToLowerInvariant();
        }

        return text;
    }

    private static string DecodeRepeatedly(string text)
    {
        var current = text;
        for (var pass = 0; pass < MaxDecodePasses; pass++)
        {
            string decoded;
            try
            {
                decoded = Uri.UnescapeDataString(current);
            }
            catch (UriFormatException)
            {
                // A stray '%' that is not a valid escape sequence; keep what we have.
                return current;
            }

            if (string.Equals(decoded, current, StringComparison.Ordinal))
            {
                return decoded;
            }

            current = decoded;
        }

        return current;
    }
}
