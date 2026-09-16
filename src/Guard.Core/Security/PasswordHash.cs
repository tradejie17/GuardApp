using System.Security.Cryptography;
using System.Text.Json.Serialization;

namespace Guard.Core.Security;

/// <summary>
/// A PBKDF2-HMAC-SHA256 password verifier, stored in admin-only secrets.json.
///
/// The admin password is the only thing standing between a determined local user and turning
/// protection off, and any local account can reach the service pipe, so the cost factor is set
/// high deliberately: a wrong guess should be expensive even for someone scripting attempts.
/// </summary>
public sealed record PasswordHash
{
    /// <summary>OWASP's current floor for PBKDF2-HMAC-SHA256.</summary>
    public const int DefaultIterations = 600_000;

    private const int SaltSize = 16;
    private const int KeySize = 32;

    [JsonPropertyName("algorithm")]
    public string Algorithm { get; init; } = "PBKDF2-HMAC-SHA256";

    [JsonPropertyName("iterations")]
    public int Iterations { get; init; } = DefaultIterations;

    [JsonPropertyName("salt")]
    public required string Salt { get; init; }

    [JsonPropertyName("hash")]
    public required string Hash { get; init; }

    public static PasswordHash Create(string password, int iterations = DefaultIterations)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(password);

        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var key = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, KeySize);

        return new PasswordHash
        {
            Iterations = iterations,
            Salt = Convert.ToBase64String(salt),
            Hash = Convert.ToBase64String(key)
        };
    }

    public bool Verify(string? password)
    {
        if (string.IsNullOrEmpty(password))
        {
            return false;
        }

        byte[] salt;
        byte[] expected;
        try
        {
            salt = Convert.FromBase64String(Salt);
            expected = Convert.FromBase64String(Hash);
        }
        catch (FormatException)
        {
            return false;
        }

        var actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, expected.Length);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }
}
