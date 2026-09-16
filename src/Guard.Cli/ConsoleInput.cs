using System.Text;

namespace Guard.Cli;

public static class ConsoleInput
{
    /// <summary>
    /// Reads a password without echoing it. Falls back to a plain read when input is redirected,
    /// which is how the installer feeds a password in non-interactively.
    /// </summary>
    public static string? ReadPassword(string prompt)
    {
        Console.Write(prompt);

        if (Console.IsInputRedirected)
        {
            var piped = Console.ReadLine();
            Console.WriteLine();
            return piped;
        }

        var builder = new StringBuilder();

        while (true)
        {
            var key = Console.ReadKey(intercept: true);

            switch (key.Key)
            {
                case ConsoleKey.Enter:
                    Console.WriteLine();
                    return builder.ToString();

                case ConsoleKey.Escape:
                    Console.WriteLine();
                    return null;

                case ConsoleKey.Backspace:
                    if (builder.Length > 0)
                    {
                        builder.Length--;
                    }
                    break;

                default:
                    if (!char.IsControl(key.KeyChar))
                    {
                        builder.Append(key.KeyChar);
                    }
                    break;
            }
        }
    }

    public static bool Confirm(string question)
    {
        Console.Write($"{question} [y/N] ");
        var answer = Console.ReadLine();
        return answer is not null && answer.Trim().StartsWith("y", StringComparison.OrdinalIgnoreCase);
    }
}
