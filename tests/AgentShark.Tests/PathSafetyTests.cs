using AgentShark.Core;
using AgentShark.Setup;

namespace AgentShark.Tests;

public sealed class UnixFactAttribute : FactAttribute
{
    public UnixFactAttribute()
    {
        if (OperatingSystem.IsWindows()) Skip = "Exercises Unix directory aliases without requiring Windows symlink privileges.";
    }
}

public sealed class PathSafetyTests
{
    [UnixFact]
    public async Task TrustedImportRootCanHaveAnAliasedAncestorButLinksWithinItAreRejected()
    {
        await using var workspace = new TestWorkspace(o => o with { ImportRoots = [Path.Combine(o.DataDirectory, "alias", "captures")] });
        string canonical = Path.Combine(workspace.DirectoryPath, "canonical");
        string captures = Path.Combine(canonical, "captures"); Directory.CreateDirectory(captures);
        Directory.CreateSymbolicLink(Path.Combine(workspace.DirectoryPath, "alias"), canonical);
        string file = Path.Combine(captures, "generated.pcap"); await File.WriteAllBytesAsync(file, SyntheticTraffic.Pcap(SyntheticTraffic.HttpConversation()));
        var observation = await workspace.Engine.StartAsync(new() { Mode = ObservationMode.Import, ImportPath = Path.Combine(workspace.DirectoryPath, "alias", "captures", "generated.pcap") });
        Assert.Equal(ObservationState.Completed, (await workspace.Wait(observation.Observation.Id)).State);
        File.CreateSymbolicLink(Path.Combine(captures, "linked.pcap"), file);
        await Assert.ThrowsAsync<ArgumentException>(() => workspace.Engine.StartAsync(new() { Mode = ObservationMode.Import, ImportPath = Path.Combine(workspace.DirectoryPath, "alias", "captures", "linked.pcap") }));
    }

    [UnixFact]
    public async Task TrustedProfileHomeCanHaveAnAliasedAncestor()
    {
        await using var workspace = new TestWorkspace();
        string canonical = Path.Combine(workspace.DirectoryPath, "canonical"); Directory.CreateDirectory(canonical);
        string alias = Path.Combine(workspace.DirectoryPath, "alias"); Directory.CreateSymbolicLink(alias, canonical);
        var paths = SetupPaths.Current(Path.Combine(alias, "home"));
        string server = Path.Combine(workspace.DirectoryPath, "server"); await File.WriteAllTextAsync(server, "fixture");
        var integrator = new ClientIntegrator(paths);
        Assert.Equal("registered", integrator.Integrate(server, "cursor").Single(r => r.Client == "cursor").Status);
        Assert.Equal("removed", integrator.Remove("cursor").Single(r => r.Client == "cursor").Status);
    }
}
