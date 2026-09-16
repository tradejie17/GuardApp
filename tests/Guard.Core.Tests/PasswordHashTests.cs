using Guard.Core.Security;
using Xunit;

namespace Guard.Core.Tests;

public class PasswordHashTests
{
    // A low cost factor keeps the suite fast; production uses PasswordHash.DefaultIterations.
    private const int TestIterations = 1_000;

    [Fact]
    public void VerifiesTheCorrectPassword()
    {
        var hash = PasswordHash.Create("correct horse battery staple", TestIterations);
        Assert.True(hash.Verify("correct horse battery staple"));
    }

    [Theory]
    [InlineData("wrong password")]
    [InlineData("Correct horse battery staple")]
    [InlineData("")]
    [InlineData(null)]
    public void RejectsEverythingElse(string? attempt)
    {
        var hash = PasswordHash.Create("correct horse battery staple", TestIterations);
        Assert.False(hash.Verify(attempt));
    }

    [Fact]
    public void UsesAFreshSaltEachTime()
    {
        var a = PasswordHash.Create("same password", TestIterations);
        var b = PasswordHash.Create("same password", TestIterations);

        Assert.NotEqual(a.Salt, b.Salt);
        Assert.NotEqual(a.Hash, b.Hash);
        Assert.True(a.Verify("same password"));
        Assert.True(b.Verify("same password"));
    }

    [Fact]
    public void RejectsBlankPasswordsAtCreation()
    {
        Assert.Throws<ArgumentException>(() => PasswordHash.Create("   ", TestIterations));
    }

    [Fact]
    public void SurvivesCorruptedStoredValues()
    {
        var hash = PasswordHash.Create("password", TestIterations) with { Salt = "not base64!!" };
        Assert.False(hash.Verify("password"));
    }
}
