namespace Guard.Cli;

/// <summary>
/// A small positional + "--option value" parser. A dedicated parsing library would be more than
/// this tool needs, and keeping guardctl dependency-free means it can be copied next to the
/// service without dragging anything else along.
/// </summary>
public sealed class CommandLine
{
    private readonly Dictionary<string, string?> _options = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> _positional = new();

    public CommandLine(IReadOnlyList<string> args)
    {
        for (var i = 0; i < args.Count; i++)
        {
            var arg = args[i];

            if (!arg.StartsWith("--", StringComparison.Ordinal))
            {
                _positional.Add(arg);
                continue;
            }

            var name = arg[2..];

            // "--flag" with no value, or "--option value".
            if (i + 1 < args.Count && !args[i + 1].StartsWith("--", StringComparison.Ordinal))
            {
                _options[name] = args[++i];
            }
            else
            {
                _options[name] = null;
            }
        }
    }

    public string Command => _positional.Count > 0 ? _positional[0].ToLowerInvariant() : "help";

    /// <summary>Everything after the command, joined — so a multi-word keyword needs no quoting.</summary>
    public string? Operand => _positional.Count > 1
        ? string.Join(' ', _positional.Skip(1))
        : null;

    public bool HasFlag(string name) => _options.ContainsKey(name);

    public string? GetString(string name) => _options.TryGetValue(name, out var value) ? value : null;

    public int? GetInt(string name) =>
        _options.TryGetValue(name, out var value) && int.TryParse(value, out var parsed) ? parsed : null;
}
