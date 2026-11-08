using System.Text.Json.Nodes;
using AgentShark.Setup;
using Tomlyn;
using Tomlyn.Model;

namespace AgentShark.Tests;

public sealed class SetupTests
{
    [Theory]
    [InlineData("{}")]
    [InlineData("{ // keep this comment\n \"theme\": \"dark\" // keep this too\n}")]
    [InlineData("{\"mcpServers\":{\"other\":{\"command\":\"keep\"},},\"x\":1,}")]
    [InlineData("{\"mcpServers\":{ /* retained */ }}")]
    public void JsonEditsPreserveUnrelatedContentAndComments(string original)
    {
        const string entry = "{\"command\":\"AgentShark.Server\",\"args\":[]}";
        string added = JsonConfigEditor.Set(original, "mcpServers", "agent-shark", entry);
        Assert.Equal(entry, JsonConfigEditor.Entry(added, "mcpServers", "agent-shark"));
        string updated = JsonConfigEditor.Set(added, "mcpServers", "agent-shark", "{\"command\":\"new\"}");
        string removed = JsonConfigEditor.Set(updated, "mcpServers", "agent-shark", null);
        Assert.Null(JsonConfigEditor.Entry(removed, "mcpServers", "agent-shark"));
        if (original.Contains("keep this comment")) { Assert.Contains("keep this comment", removed); Assert.Contains("keep this too", removed); }
        if (original.Contains("retained")) Assert.Contains("retained", removed);
        if (original.Contains("other")) Assert.Contains("\"other\":{\"command\":\"keep\"}", removed);
    }

    [Theory]
    [InlineData("{\"mcpServers\":{\"agent-shark\":{},\"other\":{}}}")]
    [InlineData("{\"mcpServers\":{\"other\":{},\"agent-shark\":{}}}")]
    [InlineData("{\"mcpServers\":{\"other\":{},/* comma , in comment */\"agent-shark\":{},}}")]
    public void JsonRemovalHandlesFirstLastAndTrailingComma(string text)
    {
        var result = JsonConfigEditor.Set(text, "mcpServers", "agent-shark", null);
        Assert.Null(JsonConfigEditor.Entry(result, "mcpServers", "agent-shark"));
        Assert.NotNull(JsonConfigEditor.Entry(result, "mcpServers", "other"));
    }

    [Fact]
    public void TomlPreservesExistingSettingsAndHandlesUnicodePaths()
    {
        const string original = "# keep\nmodel = \"custom\"\n[mcp_servers.other]\ncommand = 'unchanged'\n";
        string block = TomlConfigEditor.Block("C:\\Users\\测试🦈\\AgentShark.Server.exe", "/home/some user/data");
        string updated = TomlConfigEditor.Set(original, block);
        Assert.StartsWith(original, updated); Assert.Equal(block, TomlConfigEditor.Entry(updated));
        var model = TomlSerializer.Deserialize<TomlTable>(updated)!;
        Assert.Equal("custom", model["model"]);
        var servers = (TomlTable)model["mcp_servers"]!;
        Assert.Equal("C:\\Users\\测试🦈\\AgentShark.Server.exe", ((TomlTable)servers["agent-shark"]!)["command"]);
        Assert.StartsWith(original, TomlConfigEditor.Set(updated, null));
        Assert.Throws<InvalidDataException>(() => TomlConfigEditor.Entry("[mcp_servers.'agent-shark']\ncommand='custom'\n"));
    }

    [Fact]
    public async Task IntegratesUpdatesAndUninstallsAllClientsWithoutTouchingOtherEntries()
    {
        await using var workspace = new TestWorkspace();
        var paths = SetupPaths.Current(Path.Combine(workspace.DirectoryPath, "home"));
        var server = Path.Combine(workspace.DirectoryPath, "AgentShark.Server"); await File.WriteAllTextAsync(server, "fixture");
        foreach (var profile in paths.Profiles())
        {
            Directory.CreateDirectory(Path.GetDirectoryName(profile.ConfigPath)!);
            await File.WriteAllTextAsync(profile.ConfigPath, profile.Format == "toml" ? "# custom\nmodel='keep'\n" : "{\"unrelated\":\"keep\"}\n");
        }
        var setup = new ClientIntegrator(paths);
        Assert.All(setup.Integrate(server), result => Assert.Equal("registered", result.Status));
        Assert.All(setup.Integrate(server), result => Assert.Equal("unchanged", result.Status));
        var updatedServer = Path.Combine(workspace.DirectoryPath, "updated"); await File.WriteAllTextAsync(updatedServer, "fixture");
        Assert.All(setup.Integrate(updatedServer), result => Assert.Equal("registered", result.Status));
        Assert.All(setup.Remove(), result => Assert.Equal("removed", result.Status));
        foreach (var profile in paths.Profiles())
        {
            string text = await File.ReadAllTextAsync(profile.ConfigPath); Assert.Contains("keep", text); Assert.DoesNotContain("agent-shark", text);
        }
    }

    [Fact]
    public async Task DetectsProfilesAndRefusesModifiedOrUnmanagedEntries()
    {
        await using var workspace = new TestWorkspace(); var paths = SetupPaths.Current(Path.Combine(workspace.DirectoryPath, "home"));
        string server = Path.Combine(workspace.DirectoryPath, "server"); await File.WriteAllTextAsync(server, "fixture");
        var setup = new ClientIntegrator(paths);
        Assert.All(setup.Integrate(server), result => Assert.Equal("skipped", result.Status));
        var cursor = paths.Profiles().Single(p => p.Id == "cursor"); Directory.CreateDirectory(Path.GetDirectoryName(cursor.ConfigPath)!);
        Assert.Equal("registered", setup.Integrate(server).Single(r => r.Client == "cursor").Status);
        string changed = File.ReadAllText(cursor.ConfigPath).Replace(server.Replace("\\", "\\\\"), "custom-server", StringComparison.Ordinal);
        await File.WriteAllTextAsync(cursor.ConfigPath, changed);
        Assert.Equal("conflict", setup.Integrate(server).Single(r => r.Client == "cursor").Status);
        Assert.Equal("conflict", setup.Remove().Single(r => r.Client == "cursor").Status);
        Assert.Equal(changed, await File.ReadAllTextAsync(cursor.ConfigPath));
    }

    [Fact]
    public async Task InvalidConfigurationAndDryRunNeverRewriteClientFiles()
    {
        await using var workspace = new TestWorkspace(); var paths = SetupPaths.Current(Path.Combine(workspace.DirectoryPath, "home"));
        string server = Path.Combine(workspace.DirectoryPath, "server"); await File.WriteAllTextAsync(server, "fixture");
        var profile = paths.Profiles().Single(p => p.Id == "claude-desktop"); Directory.CreateDirectory(Path.GetDirectoryName(profile.ConfigPath)!);
        await File.WriteAllTextAsync(profile.ConfigPath, "{invalid"); var setup = new ClientIntegrator(paths);
        Assert.Equal("error", setup.Integrate(server).Single(r => r.Client == profile.Id).Status);
        Assert.Equal("{invalid", await File.ReadAllTextAsync(profile.ConfigPath));
        await File.WriteAllTextAsync(profile.ConfigPath, "{\"other\":123}");
        Assert.Equal("planned", setup.Integrate(server, dryRun: true).Single(r => r.Client == profile.Id).Status);
        Assert.Equal("{\"other\":123}", await File.ReadAllTextAsync(profile.ConfigPath));
    }

    [Theory]
    [InlineData(DesktopPlatform.Windows)]
    [InlineData(DesktopPlatform.MacOS)]
    [InlineData(DesktopPlatform.Linux)]
    public void ProfilesHaveDistinctDataTargetsAndDocumentedConfigurationFormats(DesktopPlatform platform)
    {
        var paths = new SetupPaths("/home/test", "/roaming", "/local", "/codex", platform);
        Assert.Equal(6, paths.Profiles().Count); Assert.Equal(6, paths.Profiles().Select(p => p.ConfigPath).Distinct().Count());
        Assert.Equal("vscode", paths.Profiles().Single(p => p.Id == "vscode").Format);
    }
}
