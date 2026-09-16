using Guard.Core.Detection;
using Xunit;

namespace Guard.Core.Tests;

public class UrlNormalizerTests
{
    [Fact]
    public void SplitsComponents()
    {
        var url = UrlNormalizer.Normalize("https://WWW.Example.COM/Articles/Test?q=Hello#Section");

        Assert.True(url.IsWellFormed);
        Assert.Equal("https", url.Scheme);
        Assert.Equal("www.example.com", url.Host);
        Assert.Equal("/articles/test", url.Path);
        Assert.Equal("q=hello", url.Query);
        Assert.Equal("section", url.Fragment);
    }

    [Fact]
    public void DecodesPercentEncoding()
    {
        var url = UrlNormalizer.Normalize("https://google.com/search?q=hello%20keyword");
        Assert.Equal("q=hello keyword", url.Query);
    }

    [Fact]
    public void TreatsPlusAsSpaceInQuery()
    {
        var url = UrlNormalizer.Normalize("https://google.com/search?q=hello+keyword");
        Assert.Equal("q=hello keyword", url.Query);
    }

    [Fact]
    public void DecodesDoubleEncodedPayloads()
    {
        // %2520 decodes to %20 on the first pass and to a space on the second.
        var url = UrlNormalizer.Normalize("https://google.com/search?q=hello%2520keyword");
        Assert.Equal("q=hello keyword", url.Query);
    }

    [Fact]
    public void FoldsFullWidthCharactersToAscii()
    {
        var url = UrlNormalizer.Normalize("https://example.com/ｋｅｙｗｏｒｄ");
        Assert.Equal("/keyword", url.Path);
    }

    [Fact]
    public void PreservesCaseWhenCaseSensitiveMatchingIsOn()
    {
        var options = new MatchingOptions { CaseSensitive = true };
        var url = UrlNormalizer.Normalize("https://example.com/KeyWord", options);
        Assert.Equal("/KeyWord", url.Path);
    }

    [Fact]
    public void HandlesNonAbsoluteInputWithoutThrowing()
    {
        var url = UrlNormalizer.Normalize("not a url at all");

        Assert.False(url.IsWellFormed);
        Assert.Equal("not a url at all", url.Full);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void HandlesEmptyInput(string? input)
    {
        var url = UrlNormalizer.Normalize(input);

        Assert.False(url.IsWellFormed);
        Assert.Equal(string.Empty, url.Full);
    }

    [Fact]
    public void TruncatesAbsurdlyLongUrls()
    {
        var url = UrlNormalizer.Normalize("https://example.com/" + new string('a', 20_000));
        Assert.True(url.Full.Length <= UrlNormalizer.MaxUrlLength);
    }

    [Fact]
    public void DoesNotThrowOnMalformedEscapeSequences()
    {
        var url = UrlNormalizer.Normalize("https://example.com/search?q=100%+of+%zz");
        Assert.True(url.IsWellFormed);
    }
}
