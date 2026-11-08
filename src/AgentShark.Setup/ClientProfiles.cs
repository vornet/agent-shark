namespace AgentShark.Setup;

public enum DesktopPlatform { Windows, MacOS, Linux }
public sealed record ClientProfile(string Id, string Name, string ConfigPath, string Format, bool Detected);
public sealed record SetupPaths(string Home, string Roaming, string Local, string CodexHome, DesktopPlatform Platform)
{
    public string StateDirectory => Path.Combine(Local, "AgentShark", "setup");
    public static SetupPaths Current(string? homeOverride = null)
    {
        var platform = OperatingSystem.IsWindows() ? DesktopPlatform.Windows : OperatingSystem.IsMacOS() ? DesktopPlatform.MacOS : DesktopPlatform.Linux;
        string home = Path.GetFullPath(homeOverride ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
        string roaming = platform switch
        {
            DesktopPlatform.Windows => homeOverride == null ? Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) : Path.Combine(home, "AppData", "Roaming"),
            DesktopPlatform.MacOS => Path.Combine(home, "Library", "Application Support"),
            _ => homeOverride == null ? Environment.GetEnvironmentVariable("XDG_CONFIG_HOME") ?? Path.Combine(home, ".config") : Path.Combine(home, ".config")
        };
        string local = platform == DesktopPlatform.Windows ? homeOverride == null ? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) : Path.Combine(home, "AppData", "Local") :
            platform == DesktopPlatform.MacOS ? roaming : homeOverride == null ? Environment.GetEnvironmentVariable("XDG_DATA_HOME") ?? Path.Combine(home, ".local", "share") : Path.Combine(home, ".local", "share");
        string codex = homeOverride == null ? Environment.GetEnvironmentVariable("CODEX_HOME") ?? Path.Combine(home, ".codex") : Path.Combine(home, ".codex");
        return new(home, Path.GetFullPath(roaming), Path.GetFullPath(local), Path.GetFullPath(codex), platform);
    }

    public IReadOnlyList<ClientProfile> Profiles()
    {
        ClientProfile Profile(string id, string name, string path, string format, string? detection = null) =>
            new(id, name, path, format, File.Exists(path) || Directory.Exists(detection ?? Path.GetDirectoryName(path)!));
        return
        [
            Profile("codex", "Codex", Path.Combine(CodexHome, "config.toml"), "toml"),
            Profile("claude-desktop", "Claude Desktop", Path.Combine(Roaming, "Claude", "claude_desktop_config.json"), "json"),
            Profile("claude-code", "Claude Code", Path.Combine(Home, ".claude.json"), "json", Path.Combine(Home, ".claude")),
            Profile("cursor", "Cursor", Path.Combine(Home, ".cursor", "mcp.json"), "json"),
            Profile("vscode", "VS Code", Path.Combine(Roaming, "Code", "User", "mcp.json"), "vscode"),
            Profile("windsurf", "Windsurf (existing profiles)", Path.Combine(Home, ".codeium", "windsurf", "mcp_config.json"), "json")
        ];
    }
}
