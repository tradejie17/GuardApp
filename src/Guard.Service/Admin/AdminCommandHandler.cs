using Guard.Core;
using Guard.Core.Configuration;
using Guard.Core.Messaging;
using Guard.Service.Configuration;
using Guard.Service.Logging;
using Guard.Service.Security;

namespace Guard.Service.Admin;

/// <summary>
/// Executes guardctl commands.
///
/// Authorization rule: every command that can weaken protection requires the administrator
/// password. <see cref="AdminCommands.Status"/> is the single exception — a restricted user is
/// allowed to see *that* they are protected and that a password is set, because hiding it only
/// creates confusion, and the response deliberately contains no keywords and no log content.
///
/// Every attempt, allowed or refused, is written to the audit log.
/// </summary>
public sealed class AdminCommandHandler
{
    /// <summary>An upper bound on a pause so protection cannot be disabled indefinitely.</summary>
    private const int MaxPauseMinutes = 480;

    private const int MinPasswordLength = 8;
    private const int MaxTailLines = 200;

    private readonly ConfigStore _config;
    private readonly StateStore _state;
    private readonly SecretsStore _secrets;
    private readonly GuardLogger _guardLog;
    private readonly ILogger<AdminCommandHandler> _logger;

    public AdminCommandHandler(
        ConfigStore config,
        StateStore state,
        SecretsStore secrets,
        GuardLogger guardLog,
        ILogger<AdminCommandHandler> logger)
    {
        _config = config;
        _state = state;
        _secrets = secrets;
        _guardLog = guardLog;
        _logger = logger;
    }

    public async Task<AdminResponse> HandleAsync(AdminRequest request, CancellationToken cancellationToken)
    {
        var command = request.Command?.Trim() ?? string.Empty;

        if (command == AdminCommands.Status)
        {
            return Status();
        }

        // Bootstrap: the very first password may be set without one, because there is nothing
        // yet to authenticate against. The installer does this immediately after installing the
        // service, and it is recorded in the audit log because it is a sensitive moment.
        var isBootstrap = command == AdminCommands.PasswordSet && !_secrets.IsConfigured;

        if (!isBootstrap)
        {
            var auth = await _secrets.VerifyAsync(request.Password, cancellationToken);
            if (auth != AuthResult.Ok)
            {
                var error = Describe(auth);
                _guardLog.Audit(command, allowed: false, error);
                return AdminResponse.Fail(error);
            }
        }

        try
        {
            var response = Execute(command, request, isBootstrap);
            _guardLog.Audit(command, response.Ok, response.Ok
                ? response.Message ?? "ok"
                : response.Error ?? "failed");

            return response;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Admin command {Command} failed.", command);
            _guardLog.Audit(command, allowed: false, "internal error");
            return AdminResponse.Fail("The service failed to execute that command; see guard.log.");
        }
    }

    private AdminResponse Execute(string command, AdminRequest request, bool isBootstrap) => command switch
    {
        AdminCommands.Verify => AdminResponse.Success("Password accepted."),
        AdminCommands.Pause => Pause(request),
        AdminCommands.Resume => Resume(),
        AdminCommands.KeywordsList => ListRules(),
        AdminCommands.KeywordsAdd => AddKeyword(request),
        AdminCommands.KeywordsRemove => RemoveKeyword(request),
        AdminCommands.HostsAdd => AddHost(request),
        AdminCommands.HostsRemove => RemoveHost(request),
        AdminCommands.EnforcementSet => SetEnforcement(request),
        AdminCommands.PasswordSet => SetPassword(request, isBootstrap),
        AdminCommands.LogTail => TailLog(request),
        _ => AdminResponse.Fail($"Unknown command '{command}'.")
    };

    private AdminResponse Status()
    {
        var config = _config.Current;
        var state = _state.Current;

        return AdminResponse.Success(data: new
        {
            protectionActive = !state.IsPaused,
            paused = state.IsPaused,
            pausedSeconds = state.RemainingSeconds,
            pauseReason = state.PauseReason,
            revision = config.Revision,
            keywordCount = config.Keywords.Count,
            blockedHostCount = config.BlockedHosts.Count,
            allowedHostCount = config.AllowedHosts.Count,
            action = config.Enforcement.Action.ToString(),
            passwordConfigured = _secrets.IsConfigured,
            lockedOut = _secrets.IsLockedOut,
            lockoutSeconds = _secrets.LockoutRemainingSeconds,
            configPath = GuardPaths.ConfigFile,
            logPath = GuardPaths.LogDirectory
        });
    }

    private AdminResponse Pause(AdminRequest request)
    {
        var minutes = request.Minutes ?? 15;
        if (minutes < 1 || minutes > MaxPauseMinutes)
        {
            return AdminResponse.Fail($"Pause duration must be between 1 and {MaxPauseMinutes} minutes.");
        }

        var state = _state.Pause(TimeSpan.FromMinutes(minutes), request.Reason);
        _logger.LogWarning("Protection paused for {Minutes} minute(s). Reason: {Reason}.",
            minutes, request.Reason ?? "none given");

        return AdminResponse.Success(
            $"Protection paused for {minutes} minute(s); it resumes automatically at {state.PausedUntilUtc!.Value.ToLocalTime():HH:mm}.",
            new { pausedUntilUtc = state.PausedUntilUtc, minutes });
    }

    private AdminResponse Resume()
    {
        _state.Resume();
        _logger.LogInformation("Protection resumed.");
        return AdminResponse.Success("Protection resumed.");
    }

    private AdminResponse ListRules()
    {
        var config = _config.Current;
        return AdminResponse.Success(data: new
        {
            keywords = config.Keywords,
            blockedHosts = config.BlockedHosts,
            allowedHosts = config.AllowedHosts,
            revision = config.Revision
        });
    }

    private AdminResponse AddKeyword(AdminRequest request)
    {
        if (!TryNormalizeValue(request.Value, out var keyword, out var error))
        {
            return AdminResponse.Fail(error);
        }

        var config = _config.Current;
        if (config.Keywords.Contains(keyword, StringComparer.OrdinalIgnoreCase))
        {
            return AdminResponse.Success($"'{keyword}' is already in the keyword list.");
        }

        var saved = _config.Save(config with { Keywords = config.Keywords.Append(keyword).ToArray() });
        return AdminResponse.Success($"Added keyword '{keyword}'.", new { revision = saved.Revision });
    }

    private AdminResponse RemoveKeyword(AdminRequest request)
    {
        if (!TryNormalizeValue(request.Value, out var keyword, out var error))
        {
            return AdminResponse.Fail(error);
        }

        var config = _config.Current;
        var remaining = config.Keywords
            .Where(k => !string.Equals(k, keyword, StringComparison.OrdinalIgnoreCase))
            .ToArray();

        if (remaining.Length == config.Keywords.Count)
        {
            return AdminResponse.Fail($"'{keyword}' is not in the keyword list.");
        }

        var saved = _config.Save(config with { Keywords = remaining });
        return AdminResponse.Success($"Removed keyword '{keyword}'.", new { revision = saved.Revision });
    }

    private AdminResponse AddHost(AdminRequest request)
    {
        if (!TryNormalizeHost(request.Value, out var host, out var error))
        {
            return AdminResponse.Fail(error);
        }

        var toAllowed = IsAllowedList(request.List);
        var config = _config.Current;
        var list = toAllowed ? config.AllowedHosts : config.BlockedHosts;

        if (list.Contains(host, StringComparer.OrdinalIgnoreCase))
        {
            return AdminResponse.Success($"'{host}' is already in that list.");
        }

        var updated = list.Append(host).ToArray();
        var saved = _config.Save(toAllowed
            ? config with { AllowedHosts = updated }
            : config with { BlockedHosts = updated });

        return AdminResponse.Success(
            $"Added '{host}' to the {(toAllowed ? "allowed" : "blocked")} host list.",
            new { revision = saved.Revision });
    }

    private AdminResponse RemoveHost(AdminRequest request)
    {
        if (!TryNormalizeHost(request.Value, out var host, out var error))
        {
            return AdminResponse.Fail(error);
        }

        var fromAllowed = IsAllowedList(request.List);
        var config = _config.Current;
        var list = fromAllowed ? config.AllowedHosts : config.BlockedHosts;

        var remaining = list.Where(h => !string.Equals(h, host, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (remaining.Length == list.Count)
        {
            return AdminResponse.Fail($"'{host}' is not in that list.");
        }

        var saved = _config.Save(fromAllowed
            ? config with { AllowedHosts = remaining }
            : config with { BlockedHosts = remaining });

        return AdminResponse.Success(
            $"Removed '{host}' from the {(fromAllowed ? "allowed" : "blocked")} host list.",
            new { revision = saved.Revision });
    }

    private AdminResponse SetEnforcement(AdminRequest request)
    {
        if (!Enum.TryParse<EnforcementAction>(request.Action, ignoreCase: true, out var action))
        {
            var valid = string.Join(", ", Enum.GetNames<EnforcementAction>());
            return AdminResponse.Fail($"Unknown action '{request.Action}'. Valid actions: {valid}.");
        }

        var config = _config.Current;
        var saved = _config.Save(config with
        {
            Enforcement = config.Enforcement with { Action = action }
        });

        var note = action is EnforcementAction.LogOnly or EnforcementAction.Block or EnforcementAction.None
            ? string.Empty
            : " (not implemented in v1; navigations will be blocked)";

        return AdminResponse.Success($"Enforcement action set to {action}{note}.", new { revision = saved.Revision });
    }

    private AdminResponse SetPassword(AdminRequest request, bool isBootstrap)
    {
        var password = request.NewPassword;

        if (string.IsNullOrWhiteSpace(password) || password.Length < MinPasswordLength)
        {
            return AdminResponse.Fail($"The password must be at least {MinPasswordLength} characters.");
        }

        _secrets.SetPassword(password);

        if (isBootstrap)
        {
            _logger.LogWarning("Administrator password set for the first time (no prior password existed).");
        }

        return AdminResponse.Success("Administrator password updated.");
    }

    private AdminResponse TailLog(AdminRequest request)
    {
        var count = Math.Clamp(request.Count ?? 20, 1, MaxTailLines);

        if (!File.Exists(GuardPaths.DetectionLog))
        {
            return AdminResponse.Success("No detections have been recorded yet.", new { lines = Array.Empty<string>() });
        }

        var lines = File.ReadLines(GuardPaths.DetectionLog).TakeLast(count).ToArray();
        return AdminResponse.Success(data: new { lines });
    }

    private static bool IsAllowedList(string? list) =>
        string.Equals(list, "allowed", StringComparison.OrdinalIgnoreCase);

    private static bool TryNormalizeValue(string? value, out string normalized, out string error)
    {
        normalized = value?.Trim() ?? string.Empty;

        if (normalized.Length < 2)
        {
            error = "A keyword must be at least 2 characters.";
            return false;
        }

        if (normalized.Length > 128)
        {
            error = "A keyword must be 128 characters or fewer.";
            return false;
        }

        error = string.Empty;
        return true;
    }

    private static bool TryNormalizeHost(string? value, out string normalized, out string error)
    {
        normalized = value?.Trim().TrimStart('.').ToLowerInvariant() ?? string.Empty;

        // Accept a bare host or a full URL and reduce it to the host.
        if (Uri.TryCreate(normalized, UriKind.Absolute, out var uri) && !string.IsNullOrEmpty(uri.Host))
        {
            normalized = uri.Host.ToLowerInvariant();
        }

        if (normalized.Length is < 3 or > 253 || !normalized.Contains('.') || normalized.Contains('/'))
        {
            error = $"'{value}' is not a valid host name.";
            return false;
        }

        error = string.Empty;
        return true;
    }

    private static string Describe(AuthResult result) => result switch
    {
        AuthResult.WrongPassword => "Incorrect administrator password.",
        AuthResult.LockedOut => "Too many failed attempts; administrative commands are locked out. Try again later.",
        AuthResult.NotConfigured => "No administrator password is set. Run 'guardctl set-password' first.",
        _ => "Not authorized."
    };
}
