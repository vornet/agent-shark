using System.Text.Json;
using Tomlyn;
using Tomlyn.Model;

namespace AgentShark.Setup;

public static class TomlConfigEditor
{
    private const string Begin = "# >>> AgentShark managed MCP configuration";
    private const string End = "# <<< AgentShark managed MCP configuration";

    public static string? Entry(string text)
    {
        var model = TomlSerializer.Deserialize<TomlTable>(text)!;
        int begin = text.IndexOf(Begin, StringComparison.Ordinal), end = text.IndexOf(End, StringComparison.Ordinal);
        if (begin >= 0 || end >= 0)
        {
            if (begin < 0 || end < begin || text.IndexOf(Begin, begin + Begin.Length, StringComparison.Ordinal) >= 0 || text.IndexOf(End, end + End.Length, StringComparison.Ordinal) >= 0)
                throw new InvalidDataException("Invalid AgentShark managed markers; configuration was left unchanged.");
            return text[begin..(end + End.Length)];
        }
        if (model.TryGetValue("mcp_servers", out var servers) && servers is TomlTable table && table.ContainsKey("agent-shark"))
            throw new InvalidDataException("An unmanaged agent-shark Codex entry already exists; configuration was left unchanged.");
        return null;
    }

    public static string Block(string server, string data) => $"""
        {Begin}
        [mcp_servers.agent-shark]
        command = {Quote(server)}
        args = []
        startup_timeout_sec = 30

        [mcp_servers.agent-shark.env]
        AGENTSHARK_DATA_DIRECTORY = {Quote(data)}
        {End}
        """;

    public static string Set(string text, string? block)
    {
        string? current = Entry(text);
        if (current != null)
        {
            int position = text.IndexOf(current, StringComparison.Ordinal);
            text = text.Remove(position, current.Length);
        }
        if (block != null) text += (text.EndsWith('\n') || text.Length == 0 ? "" : "\n") + "\n" + block + "\n";
        _ = TomlSerializer.Deserialize<TomlTable>(text);
        return text;
    }

    private static string Quote(string value)
    {
        string text = TomlSerializer.Serialize(new TomlTable { ["value"] = value });
        return text[(text.IndexOf('=') + 1)..].Trim();
    }
}
