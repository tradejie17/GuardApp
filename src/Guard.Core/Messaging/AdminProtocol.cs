using System.Text.Json;
using System.Text.Json.Serialization;

namespace Guard.Core.Messaging;

/// <summary>Commands guardctl can ask the service to perform.</summary>
public static class AdminCommands
{
    public const string Status = "status";
    public const string Verify = "verify";
    public const string Pause = "pause";
    public const string Resume = "resume";
    public const string KeywordsList = "keywords.list";
    public const string KeywordsAdd = "keywords.add";
    public const string KeywordsRemove = "keywords.remove";
    public const string HostsAdd = "hosts.add";
    public const string HostsRemove = "hosts.remove";
    public const string EnforcementSet = "enforcement.set";
    public const string PasswordSet = "password.set";
    public const string LogTail = "log.tail";
}

/// <summary>
/// An administrative request. Every command except <see cref="AdminCommands.Status"/> requires
/// the correct password; status is unauthenticated so a user can see *that* they are protected
/// without being able to change anything.
/// </summary>
public sealed record AdminRequest
{
    [JsonPropertyName("type")]
    public string Type { get; init; } = MessageTypes.Admin;

    [JsonPropertyName("command")]
    public required string Command { get; init; }

    [JsonPropertyName("password")]
    public string? Password { get; init; }

    /// <summary>Used by password.set to authorize a change with the existing password.</summary>
    [JsonPropertyName("newPassword")]
    public string? NewPassword { get; init; }

    /// <summary>Keyword or host operand for the list-editing commands.</summary>
    [JsonPropertyName("value")]
    public string? Value { get; init; }

    /// <summary>Which list hosts.add / hosts.remove operate on: "blocked" or "allowed".</summary>
    [JsonPropertyName("list")]
    public string? List { get; init; }

    [JsonPropertyName("minutes")]
    public int? Minutes { get; init; }

    [JsonPropertyName("reason")]
    public string? Reason { get; init; }

    [JsonPropertyName("action")]
    public string? Action { get; init; }

    [JsonPropertyName("count")]
    public int? Count { get; init; }
}

public sealed record AdminResponse
{
    [JsonPropertyName("type")]
    public string Type { get; init; } = MessageTypes.AdminResult;

    [JsonPropertyName("ok")]
    public bool Ok { get; init; }

    [JsonPropertyName("error")]
    public string? Error { get; init; }

    [JsonPropertyName("message")]
    public string? Message { get; init; }

    /// <summary>Command-specific payload, shaped by the handler.</summary>
    [JsonPropertyName("data")]
    public JsonElement? Data { get; init; }

    public static AdminResponse Fail(string error) => new() { Ok = false, Error = error };

    public static AdminResponse Success(string? message = null, object? data = null) => new()
    {
        Ok = true,
        Message = message,
        Data = data is null
            ? null
            : JsonSerializer.SerializeToElement(data, GuardJson.Options)
    };
}
