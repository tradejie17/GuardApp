using Guard.Core.Detection;
using Xunit;

namespace Guard.Core.Tests;

public class KeywordMatcherTests
{
    private static KeywordMatcher Matcher(params string[] keywords) => new(keywords);

    [Theory]
    [InlineData("https://google.com/search?q=keyword")]
    [InlineData("https://google.com/search?q=hello+keyword")]
    [InlineData("https://google.com/search?q=hello%20keyword")]
    [InlineData("https://example.com/article/keyword/test")]
    [InlineData("https://example.com/search?q=KEYWORD")]
    [InlineData("https://example.com/page#keyword")]
    [InlineData("https://keyword.example.com/")]
    public void MatchesKeywordAnywhereInUrl(string url)
    {
        var result = Matcher("keyword").Match(url);

        Assert.True(result.IsMatch);
        Assert.Equal("keyword", result.Keyword);
        Assert.Equal("keyword", result.RuleType);
    }

    [Theory]
    [InlineData("https://www.google.com/search?q=normal+topic")]
    [InlineData("https://example.com/")]
    [InlineData("https://example.com/keywo/rd")]
    public void AllowsUnrelatedUrls(string url)
    {
        Assert.False(Matcher("keyword").Match(url).IsMatch);
    }

    [Fact]
    public void MatchesSubstringsInsideLargerWords()
    {
        // Documented v1 behaviour: literal substring matching, so partial words count.
        Assert.True(Matcher("keyword").Match("https://example.com/keyword123").IsMatch);
        Assert.True(Matcher("keyword").Match("https://example.com/123keyword").IsMatch);
        Assert.True(Matcher("keyword").Match("https://example.com/hello-keyword").IsMatch);
    }

    [Fact]
    public void MatchesMultiWordKeywordsAcrossEncoding()
    {
        var matcher = Matcher("restricted word");
        Assert.True(matcher.Match("https://google.com/search?q=a+restricted+word+here").IsMatch);
        Assert.True(matcher.Match("https://google.com/search?q=restricted%20word").IsMatch);
    }

    [Fact]
    public void ReportsWhichPartMatched()
    {
        Assert.Equal(UrlPart.Host, Matcher("bad").Match("https://bad.example.com/").MatchedIn);
        Assert.Equal(UrlPart.Path, Matcher("bad").Match("https://example.com/bad").MatchedIn);
        Assert.Equal(UrlPart.Query, Matcher("bad").Match("https://example.com/?q=bad").MatchedIn);
        Assert.Equal(UrlPart.Fragment, Matcher("bad").Match("https://example.com/#bad").MatchedIn);
    }

    [Fact]
    public void RespectsDisabledComponentChecks()
    {
        var options = new MatchingOptions { CheckQuery = false };
        var matcher = new KeywordMatcher(new[] { "keyword" }, options);

        Assert.False(matcher.Match("https://example.com/?q=keyword").IsMatch);
        Assert.True(matcher.Match("https://example.com/keyword").IsMatch);
    }

    [Fact]
    public void RespectsCaseSensitiveMatching()
    {
        var options = new MatchingOptions { CaseSensitive = true };
        var matcher = new KeywordMatcher(new[] { "KeyWord" }, options);

        Assert.True(matcher.Match("https://example.com/KeyWord").IsMatch);
        Assert.False(matcher.Match("https://example.com/keyword").IsMatch);
    }

    [Fact]
    public void MatchesAnyOfSeveralKeywords()
    {
        var matcher = Matcher("alpha", "beta", "gamma");

        Assert.Equal("beta", matcher.Match("https://example.com/?q=beta").Keyword);
        Assert.Equal("gamma", matcher.Match("https://example.com/gamma").Keyword);
        Assert.False(matcher.Match("https://example.com/delta").IsMatch);
    }

    [Fact]
    public void BlocksHostsAndTheirSubdomains()
    {
        var matcher = new KeywordMatcher(Array.Empty<string>(), blockedHosts: new[] { "example.com" });

        Assert.True(matcher.Match("https://example.com/anything").IsMatch);
        Assert.True(matcher.Match("https://www.example.com/").IsMatch);
        Assert.Equal("blockedHost", matcher.Match("https://example.com/").RuleType);
        Assert.False(matcher.Match("https://notexample.com/").IsMatch);
    }

    [Fact]
    public void AllowListOverridesEveryRule()
    {
        var matcher = new KeywordMatcher(
            new[] { "keyword" },
            blockedHosts: new[] { "example.com" },
            allowedHosts: new[] { "example.com" });

        Assert.False(matcher.Match("https://example.com/keyword").IsMatch);
        Assert.True(matcher.Match("https://other.com/keyword").IsMatch);
    }

    [Theory]
    [InlineData("chrome://extensions")]
    [InlineData("about:config")]
    [InlineData("chrome-extension://abcdef/blocked.html?keyword=keyword")]
    public void IgnoresInternalBrowserPages(string url)
    {
        Assert.False(Matcher("keyword", "extensions", "config").Match(url).IsMatch);
    }

    [Fact]
    public void IgnoresBlankAndDuplicateKeywords()
    {
        var matcher = Matcher("  keyword  ", "keyword", "", "   ");
        Assert.Equal(1, matcher.KeywordCount);
        Assert.True(matcher.Match("https://example.com/keyword").IsMatch);
    }

    [Fact]
    public void EmptyKeywordListNeverMatches()
    {
        Assert.False(new KeywordMatcher(Array.Empty<string>()).Match("https://example.com/keyword").IsMatch);
    }

    [Fact]
    public void MatchesInsideUnparseableInput()
    {
        Assert.True(Matcher("keyword").Match("keyword").IsMatch);
    }
}
