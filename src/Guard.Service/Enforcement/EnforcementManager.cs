using Guard.Core.Configuration;
using Guard.Core.Messaging;
using Guard.Service.Configuration;
using Guard.Service.Logging;

namespace Guard.Service.Enforcement;

/// <summary>
/// Decides what happens when an extension reports a detection.
///
/// The extension is untrusted input: it has already blocked the navigation locally, but the
/// service re-runs the same rules over the reported URL before it records or acts on anything.
/// A report the service cannot reproduce is logged and dropped, so a compromised or buggy
/// extension cannot manufacture enforcement events.
///
/// v1 implements LogOnly and Block. The remaining actions are accepted by the config schema and
/// deliberately degrade to Block, so a policy written for a later version is never silently
/// treated as "do nothing".
/// </summary>
public sealed class EnforcementManager
{
    private static readonly HashSet<string> KnownBrowsers =
        new(StringComparer.OrdinalIgnoreCase) { "chrome", "edge", "avast", "firefox" };

    private const int MaxUrlLength = 8192;
    private const int MaxKeywordLength = 256;

    private readonly ConfigStore _config;
    private readonly StateStore _state;
    private readonly GuardLogger _guardLog;
    private readonly ILogger<EnforcementManager> _logger;

    private bool _warnedAboutUnimplementedAction;

    public EnforcementManager(
        ConfigStore config,
        StateStore state,
        GuardLogger guardLog,
        ILogger<EnforcementManager> logger)
    {
        _config = config;
        _state = state;
        _guardLog = guardLog;
        _logger = logger;
    }

    public VerdictMessage Handle(DetectionMessage detection)
    {
        if (!Validate(detection, out var reason))
        {
            _logger.LogWarning("Rejected detection report: {Reason}.", reason);
            return new VerdictMessage { RequestId = detection.RequestId, Allow = true, Action = EnforcementAction.None, Reason = reason };
        }

        if (_state.Current.IsPaused)
        {
            return new VerdictMessage
            {
                RequestId = detection.RequestId,
                Allow = true,
                Action = EnforcementAction.None,
                Reason = "protection paused"
            };
        }

        // Re-verify against our own copy of the policy rather than trusting the reported keyword.
        var result = _config.Matcher.Match(detection.Url);
        if (!result.IsMatch)
        {
            _logger.LogWarning(
                "Extension on {Browser} reported keyword '{Keyword}' but the service policy does not match that URL; ignoring.",
                detection.Browser, Truncate(detection.Keyword, 64));

            return new VerdictMessage { RequestId = detection.RequestId, Allow = true, Action = EnforcementAction.None, Reason = "not confirmed by service policy" };
        }

        var config = _config.Current;
        var action = config.Enforcement.Action;

        _guardLog.Detection(detection.Browser!, detection.Url!, result, action, config.Logging);

        _logger.LogInformation(
            "Detection on {Browser}: rule {Rule} matched '{Keyword}' in {Part}; action {Action}.",
            detection.Browser, result.RuleType, result.Keyword, result.MatchedIn, action);

        return Decide(detection.RequestId, action, result.Keyword!);
    }

    private VerdictMessage Decide(string? requestId, EnforcementAction action, string keyword)
    {
        switch (action)
        {
            case EnforcementAction.None:
            case EnforcementAction.LogOnly:
                return new VerdictMessage
                {
                    RequestId = requestId,
                    Allow = true,
                    Action = action,
                    Reason = "recorded only"
                };

            case EnforcementAction.Block:
                return Blocked(requestId, EnforcementAction.Block, keyword);

            default:
                if (!_warnedAboutUnimplementedAction)
                {
                    _warnedAboutUnimplementedAction = true;
                    _logger.LogWarning(
                        "Enforcement action {Action} is not implemented in v1; navigations will be blocked instead.",
                        action);
                }

                return Blocked(requestId, EnforcementAction.Block, keyword);
        }
    }

    private static VerdictMessage Blocked(string? requestId, EnforcementAction action, string keyword) => new()
    {
        RequestId = requestId,
        Allow = false,
        Action = action,
        Reason = $"blocked by rule '{keyword}'"
    };

    private static bool Validate(DetectionMessage detection, out string reason)
    {
        if (string.IsNullOrWhiteSpace(detection.Url))
        {
            reason = "missing url";
            return false;
        }

        if (detection.Url.Length > MaxUrlLength)
        {
            reason = "url too long";
            return false;
        }

        if (string.IsNullOrWhiteSpace(detection.Browser) || !KnownBrowsers.Contains(detection.Browser))
        {
            reason = "unknown browser identity";
            return false;
        }

        if (detection.Keyword is { Length: > MaxKeywordLength })
        {
            reason = "keyword too long";
            return false;
        }

        // A timestamp far outside the present suggests a replayed or forged message.
        if (detection.Timestamp is { } stamp &&
            Math.Abs((DateTimeOffset.UtcNow - stamp).TotalMinutes) > 10)
        {
            reason = "timestamp outside the accepted window";
            return false;
        }

        reason = string.Empty;
        return true;
    }

    private static string Truncate(string? value, int max) =>
        value is null ? string.Empty : value.Length <= max ? value : value[..max];
}
