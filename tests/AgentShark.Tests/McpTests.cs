using System.Text.Json;
using AgentShark.Core;
using ModelContextProtocol.Client;

namespace AgentShark.Tests;

public sealed class McpTests
{
    [Fact]
    public async Task RealStdioServerDiscoversToolsAndRunsAnObservation()
    {
        await using var workspace = new TestWorkspace();
        string server = Environment.GetEnvironmentVariable("AGENTSHARK_TEST_SERVER") ?? typeof(AgentShark.Server.AgentTools).Assembly.Location;
        string? image = Environment.GetEnvironmentVariable("AGENTSHARK_TEST_DOCKER_IMAGE");
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var transport = new StdioClientTransport(new()
        {
            Name = "AgentShark test",
            Command = image != null ? "docker" : server.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ? "dotnet" : server,
            Arguments = image != null ? ["run", "--rm", "-i", image] : server.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ? [server] : [],
            EnvironmentVariables = new Dictionary<string, string?>
            {
                ["AGENTSHARK_DATA_DIRECTORY"] = Path.Combine(workspace.DirectoryPath, "server"),
                ["AGENTSHARK_IMPORT_ROOTS"] = workspace.DirectoryPath
            }
        });
        await using var client = await McpClient.CreateAsync(transport, cancellationToken: timeout.Token);
        var tools = await client.ListToolsAsync(cancellationToken: timeout.Token);
        Assert.Equal(11, tools.Count);
        Assert.Contains(tools, t => t.Name == "start_observation");
        var capabilities = await client.CallToolAsync("get_capabilities", cancellationToken: timeout.Token);
        Assert.NotNull(capabilities.StructuredContent); Assert.False(capabilities.IsError ?? false);
        var start = await client.CallToolAsync("start_observation", new Dictionary<string, object?>
        {
            ["request"] = new { mode = "proxy", allowedHosts = new[] { "localhost" }, durationSeconds = 10 }
        }, cancellationToken: timeout.Token);
        Assert.False(start.IsError ?? false);
        var json = JsonSerializer.SerializeToElement(start.StructuredContent);
        string id = json.GetProperty("observation").GetProperty("id").GetString()!;
        var stop = await client.CallToolAsync("stop_observation", new Dictionary<string, object?> { ["observationId"] = id }, cancellationToken: timeout.Token);
        Assert.False(stop.IsError ?? false);
        var query = await client.CallToolAsync("query_exchanges", new Dictionary<string, object?> { ["observationId"] = id }, cancellationToken: timeout.Token);
        Assert.False(query.IsError ?? false);
        var invalid = await client.CallToolAsync("get_observation_status", new Dictionary<string, object?> { ["observationId"] = "missing" }, cancellationToken: timeout.Token);
        Assert.True(invalid.IsError);
    }
}
