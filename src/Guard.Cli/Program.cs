/*
 * guardctl — the administrative front end for the Guard service.
 *
 * It holds no policy and no secrets of its own: every command is a message to the service over
 * the named pipe, and the service decides whether the password supplied is good enough. That is
 * why running guardctl as an administrator is not sufficient to change anything, and why an
 * ordinary user running it can still ask for status.
 */

using System.Text.Json;
using Guard.Cli;
using Guard.Core.Messaging;

using var cancellation = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    cancellation.Cancel();
};

var cli = new CommandLine(args);

try
{
    return await RunAsync(cli, cancellation.Token);
}
catch (OperationCanceledException)
{
    Console.Error.WriteLine("Cancelled.");
    return 1;
}
catch (TimeoutException)
{
    return ServiceUnreachable();
}
catch (IOException)
{
    return ServiceUnreachable();
}

static int ServiceUnreachable()
{
    Console.Error.WriteLine("Could not reach the Guard service.");
    Console.Error.WriteLine("Check that it is running:  sc query GuardService");
    return 2;
}

static async Task<int> RunAsync(CommandLine cli, CancellationToken cancellationToken)
{
    switch (cli.Command)
    {
        case "help" or "--help" or "-h":
            PrintUsage();
            return 0;

        case "status":
            return await StatusAsync(cancellationToken);

        case "set-password":
            return await SetPasswordAsync(cli, cancellationToken);

        default:
            return await SendAuthenticatedAsync(cli, cancellationToken);
    }
}

static async Task<int> StatusAsync(CancellationToken cancellationToken)
{
    await using var client = await GuardClient.ConnectAsync(cancellationToken);
    var response = await client.SendAsync(new AdminRequest { Command = AdminCommands.Status }, cancellationToken);

    if (!response.Ok || response.Data is not { } data)
    {
        Console.Error.WriteLine(response.Error ?? "The service did not report its status.");
        return 1;
    }

    var paused = data.GetProperty("paused").GetBoolean();
    var passwordSet = data.GetProperty("passwordConfigured").GetBoolean();

    Console.WriteLine("Guard for Windows");
    Console.WriteLine("  Status          : " + (paused
        ? $"PAUSED ({data.GetProperty("pausedSeconds").GetInt32() / 60} min remaining)"
        : "PROTECTED"));
    Console.WriteLine($"  Enforcement     : {data.GetProperty("action").GetString()}");
    Console.WriteLine($"  Keywords        : {data.GetProperty("keywordCount").GetInt32()}");
    Console.WriteLine($"  Blocked hosts   : {data.GetProperty("blockedHostCount").GetInt32()}");
    Console.WriteLine($"  Allowed hosts   : {data.GetProperty("allowedHostCount").GetInt32()}");
    Console.WriteLine($"  Policy revision : {data.GetProperty("revision").GetInt64()}");
    Console.WriteLine($"  Admin password  : {(passwordSet ? "set" : "NOT SET")}");

    if (data.GetProperty("lockedOut").GetBoolean())
    {
        Console.WriteLine($"  Lockout         : active for another {data.GetProperty("lockoutSeconds").GetInt32()}s");
    }

    Console.WriteLine($"  Policy file     : {data.GetProperty("configPath").GetString()}");
    Console.WriteLine($"  Logs            : {data.GetProperty("logPath").GetString()}");

    if (!passwordSet)
    {
        Console.WriteLine();
        Console.WriteLine("No administrator password is set. Run 'guardctl set-password' to finish setup.");
    }

    return 0;
}

static async Task<int> SetPasswordAsync(CommandLine cli, CancellationToken cancellationToken)
{
    await using var client = await GuardClient.ConnectAsync(cancellationToken);

    // Ask the service whether a password already exists, so we only prompt for the current one
    // when there is a current one.
    var status = await client.SendAsync(new AdminRequest { Command = AdminCommands.Status }, cancellationToken);
    var alreadySet = status.Data?.GetProperty("passwordConfigured").GetBoolean() ?? false;

    string? current = null;
    if (alreadySet)
    {
        current = cli.GetString("password") ?? ConsoleInput.ReadPassword("Current administrator password: ");
        if (string.IsNullOrEmpty(current))
        {
            Console.Error.WriteLine("Cancelled.");
            return 1;
        }
    }

    var next = cli.GetString("new-password") ?? ConsoleInput.ReadPassword("New administrator password: ");
    if (string.IsNullOrEmpty(next))
    {
        Console.Error.WriteLine("Cancelled.");
        return 1;
    }

    if (cli.GetString("new-password") is null)
    {
        var confirm = ConsoleInput.ReadPassword("Confirm new password: ");
        if (!string.Equals(next, confirm, StringComparison.Ordinal))
        {
            Console.Error.WriteLine("The passwords did not match.");
            return 1;
        }
    }

    var response = await client.SendAsync(new AdminRequest
    {
        Command = AdminCommands.PasswordSet,
        Password = current,
        NewPassword = next
    }, cancellationToken);

    return Report(response);
}

static async Task<int> SendAuthenticatedAsync(CommandLine cli, CancellationToken cancellationToken)
{
    var request = BuildRequest(cli);
    if (request is null)
    {
        Console.Error.WriteLine($"Unknown command '{cli.Command}'. Run 'guardctl help'.");
        return 1;
    }

    var password = cli.GetString("password") ?? ConsoleInput.ReadPassword("Administrator password: ");
    if (string.IsNullOrEmpty(password))
    {
        Console.Error.WriteLine("Cancelled.");
        return 1;
    }

    await using var client = await GuardClient.ConnectAsync(cancellationToken);
    var response = await client.SendAsync(request with { Password = password }, cancellationToken);

    if (response.Ok && cli.Command is "list" or "log")
    {
        PrintListing(cli.Command, response);
        return 0;
    }

    return Report(response);
}

static AdminRequest? BuildRequest(CommandLine cli) => cli.Command switch
{
    "verify" => new AdminRequest { Command = AdminCommands.Verify },

    "pause" => new AdminRequest
    {
        Command = AdminCommands.Pause,
        Minutes = cli.GetInt("minutes") ?? 15,
        Reason = cli.GetString("reason")
    },

    "resume" => new AdminRequest { Command = AdminCommands.Resume },

    "list" => new AdminRequest { Command = AdminCommands.KeywordsList },

    "add-keyword" => new AdminRequest { Command = AdminCommands.KeywordsAdd, Value = cli.Operand },
    "remove-keyword" => new AdminRequest { Command = AdminCommands.KeywordsRemove, Value = cli.Operand },

    "block-host" => new AdminRequest { Command = AdminCommands.HostsAdd, Value = cli.Operand, List = "blocked" },
    "unblock-host" => new AdminRequest { Command = AdminCommands.HostsRemove, Value = cli.Operand, List = "blocked" },
    "allow-host" => new AdminRequest { Command = AdminCommands.HostsAdd, Value = cli.Operand, List = "allowed" },
    "unallow-host" => new AdminRequest { Command = AdminCommands.HostsRemove, Value = cli.Operand, List = "allowed" },

    "set-action" => new AdminRequest { Command = AdminCommands.EnforcementSet, Action = cli.Operand },

    "log" => new AdminRequest { Command = AdminCommands.LogTail, Count = cli.GetInt("count") ?? 20 },

    _ => null
};

static void PrintListing(string command, AdminResponse response)
{
    if (response.Data is not { } data)
    {
        return;
    }

    if (command == "log")
    {
        var lines = data.GetProperty("lines").EnumerateArray().Select(line => line.GetString()).ToArray();

        if (lines.Length == 0)
        {
            Console.WriteLine(response.Message ?? "No detections recorded.");
            return;
        }

        foreach (var line in lines)
        {
            Console.WriteLine(line);
        }

        return;
    }

    PrintSection("Keywords", data.GetProperty("keywords"));
    PrintSection("Blocked hosts", data.GetProperty("blockedHosts"));
    PrintSection("Allowed hosts", data.GetProperty("allowedHosts"));
    Console.WriteLine($"Policy revision {data.GetProperty("revision").GetInt64()}");
}

static void PrintSection(string title, JsonElement values)
{
    Console.WriteLine(title + ":");

    var any = false;
    foreach (var value in values.EnumerateArray())
    {
        Console.WriteLine("  " + value.GetString());
        any = true;
    }

    if (!any)
    {
        Console.WriteLine("  (none)");
    }

    Console.WriteLine();
}

static int Report(AdminResponse response)
{
    if (response.Ok)
    {
        Console.WriteLine(response.Message ?? "Done.");
        return 0;
    }

    Console.Error.WriteLine(response.Error ?? "The command failed.");
    return 1;
}

static void PrintUsage()
{
    Console.WriteLine("""
        guardctl — administer Guard for Windows

        Every command except 'status' asks for the administrator password. Supply it
        interactively, or with --password for scripted use.

          guardctl status                          Show protection status (no password needed)
          guardctl verify                          Check that a password is correct
          guardctl set-password                    Set or change the administrator password

          guardctl list                            Show keywords and host rules
          guardctl add-keyword <text>              Add a restricted keyword
          guardctl remove-keyword <text>           Remove a restricted keyword

          guardctl block-host example.com          Block a site and its subdomains
          guardctl unblock-host example.com        Remove a blocked site
          guardctl allow-host example.com          Exempt a site from every rule
          guardctl unallow-host example.com        Remove an exemption

          guardctl set-action <action>             LogOnly | Block  (v1 implements these two)
          guardctl pause --minutes 15 --reason ""  Temporarily suspend protection
          guardctl resume                          Resume protection immediately
          guardctl log --count 20                  Show recent detections

        Examples:
          guardctl add-keyword "restricted phrase"
          guardctl pause --minutes 30 --reason "software update"
        """);
}
