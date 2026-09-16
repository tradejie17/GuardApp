using System.Diagnostics;
using System.Text.Json;
using Guard.Core;
using Guard.Core.Messaging;
using Guard.Core.Security;

namespace Guard.Service.Security;

/// <summary>The outcome of checking an administrator password.</summary>
public enum AuthResult
{
    Ok,
    WrongPassword,
    LockedOut,
    NotConfigured
}

/// <summary>
/// Owns admin.json: the password verifier and the failed-attempt counters.
///
/// Any local account can open the service pipe, so this is the component that actually resists
/// someone trying to switch protection off. Three things make guessing impractical: PBKDF2 at a
/// high cost factor, a fixed floor on how long every attempt takes, and a lockout after a few
/// failures that survives a service restart because it is persisted.
/// </summary>
public sealed class SecretsStore
{
    private readonly ILogger<SecretsStore> _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);

    private AdminSecrets _secrets = new();

    public SecretsStore(ILogger<SecretsStore> logger) => _logger = logger;

    public bool IsConfigured => _secrets.IsConfigured;
    public bool IsLockedOut => _secrets.IsLockedOut;
    public int LockoutRemainingSeconds => _secrets.LockoutRemainingSeconds;
    public int FailedAttempts => _secrets.FailedAttempts;

    public void Load()
    {
        GuardPaths.EnsureDirectories();

        if (!File.Exists(GuardPaths.SecretsFile))
        {
            _logger.LogWarning(
                "No administrator password is set. Run 'guardctl set-password' to finish installation; " +
                "until then administrative commands are refused.");
            return;
        }

        try
        {
            var json = File.ReadAllText(GuardPaths.SecretsFile);
            _secrets = JsonSerializer.Deserialize<AdminSecrets>(json, GuardJson.FileOptions) ?? new AdminSecrets();
        }
        catch (Exception ex)
        {
            // Deliberately fail closed: an unreadable secrets file leaves no usable password,
            // so administrative commands are refused rather than allowed through.
            _logger.LogError(ex, "Could not read {Path}. Administrative commands will be refused.", GuardPaths.SecretsFile);
            _secrets = new AdminSecrets();
        }

        WindowsAcl.RestrictToAdministrators(GuardPaths.SecretsFile, _logger);
    }

    /// <summary>
    /// Checks a password, applying the lockout policy. Always takes at least
    /// <see cref="LockoutPolicy.MinimumVerifyDelay"/> so that timing gives nothing away and the
    /// attempt rate stays low.
    /// </summary>
    public async Task<AuthResult> VerifyAsync(string? password, CancellationToken cancellationToken = default)
    {
        var started = Stopwatch.StartNew();
        await _gate.WaitAsync(cancellationToken);

        try
        {
            if (!_secrets.IsConfigured)
            {
                return AuthResult.NotConfigured;
            }

            if (_secrets.IsLockedOut)
            {
                _logger.LogWarning("Administrative attempt refused: locked out for another {Seconds}s.",
                    _secrets.LockoutRemainingSeconds);
                return AuthResult.LockedOut;
            }

            if (_secrets.Password!.Verify(password))
            {
                if (_secrets.FailedAttempts > 0)
                {
                    Persist(_secrets with { FailedAttempts = 0, LockedUntilUtc = null });
                }

                return AuthResult.Ok;
            }

            var attempts = _secrets.FailedAttempts + 1;
            var lockout = attempts >= LockoutPolicy.MaxAttempts
                ? DateTimeOffset.UtcNow.Add(LockoutPolicy.LockoutDuration)
                : (DateTimeOffset?)null;

            Persist(_secrets with { FailedAttempts = attempts, LockedUntilUtc = lockout });

            if (lockout is not null)
            {
                _logger.LogWarning("Administrator password locked out after {Attempts} failed attempts.", attempts);
            }

            return AuthResult.WrongPassword;
        }
        finally
        {
            _gate.Release();
            await EnforceMinimumDelayAsync(started, cancellationToken);
        }
    }

    /// <summary>
    /// Sets or replaces the administrator password. Replacing an existing password requires the
    /// current one, which is verified by the caller before this is reached.
    /// </summary>
    public void SetPassword(string newPassword)
    {
        GuardPaths.EnsureDirectories();

        Persist(new AdminSecrets
        {
            Password = PasswordHash.Create(newPassword),
            FailedAttempts = 0,
            LockedUntilUtc = null,
            CreatedUtc = _secrets.CreatedUtc
        });

        _logger.LogInformation("Administrator password updated.");
    }

    private void Persist(AdminSecrets secrets)
    {
        _secrets = secrets;

        var json = JsonSerializer.Serialize(secrets, GuardJson.FileOptions);
        var temp = GuardPaths.SecretsFile + ".tmp";
        File.WriteAllText(temp, json);

        if (File.Exists(GuardPaths.SecretsFile))
        {
            File.Replace(temp, GuardPaths.SecretsFile, null);
        }
        else
        {
            File.Move(temp, GuardPaths.SecretsFile);
        }

        WindowsAcl.RestrictToAdministrators(GuardPaths.SecretsFile, _logger);
    }

    private static async Task EnforceMinimumDelayAsync(Stopwatch started, CancellationToken cancellationToken)
    {
        var remaining = LockoutPolicy.MinimumVerifyDelay - started.Elapsed;
        if (remaining > TimeSpan.Zero)
        {
            try
            {
                await Task.Delay(remaining, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                // Shutting down; the caller is going away anyway.
            }
        }
    }
}
