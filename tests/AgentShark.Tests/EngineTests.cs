using AgentShark.Core;

namespace AgentShark.Tests;

public sealed class EngineTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ImportsTrafficWithEvidenceAndPrivacyControls(bool retain)
    {
        await using var workspace = new TestWorkspace();
        var path = Path.Combine(workspace.DirectoryPath, "synthetic.pcap");
        await File.WriteAllBytesAsync(path, SyntheticTraffic.Pcap(SyntheticTraffic.HttpConversation()));
        var result = await workspace.Engine.StartAsync(new() { Mode = ObservationMode.Import, ImportPath = path, RetainPayloads = retain });
        var status = await workspace.Wait(result.Observation.Id);
        Assert.Equal(ObservationState.Completed, status.State); Assert.Equal(4, status.Packets);
        var exchange = Assert.Single(workspace.Engine.Exchanges(status.Id, new(), true).Items);
        Assert.Equal(503, exchange.StatusCode); Assert.Equal("http://app.test/health", exchange.Target);
        Assert.Equal("[redacted]", exchange.RequestHeaders["authorization"]);
        Assert.Equal("[redacted]", exchange.ResponseHeaders["set-cookie"]);
        Assert.Equal(retain ? "failed!" : null, exchange.ResponseBody);
        Assert.Null(Assert.Single(workspace.Engine.Exchanges(status.Id, new()).Items).ResponseBody);
        foreach (var id in exchange.EvidenceIds) Assert.NotNull(workspace.Engine.Evidence(status.Id, id, false));
        Assert.Null(workspace.Engine.Evidence(status.Id, "pkt_3", false).PayloadBase64);
        Assert.Equal(retain, workspace.Engine.Evidence(status.Id, "pkt_3", true).PayloadBase64 != null);
        Assert.All(workspace.Engine.Events(status.Id, new()).Items, e => Assert.Null(e.PayloadBase64));
    }

    [Fact]
    public async Task ReassemblesOutOfOrderHttpBeforeDecoding()
    {
        await using var workspace = new TestWorkspace();
        string first = "GET / HTTP/1.1\r\n", rest = "Host: example.test\r\n\r\n";
        byte[][] packets = [SyntheticTraffic.Tcp("", 99, flags: 2), SyntheticTraffic.Tcp(rest, 100 + (uint)first.Length), SyntheticTraffic.Tcp(first, 100), SyntheticTraffic.Tcp("HTTP/1.1 204 No Content\r\n\r\n", 500, true)];
        var path = Path.Combine(workspace.DirectoryPath, "reordered.pcap"); await File.WriteAllBytesAsync(path, SyntheticTraffic.Pcap(packets));
        var result = await workspace.Engine.StartAsync(new() { Mode = ObservationMode.Import, ImportPath = path });
        await workspace.Wait(result.Observation.Id);
        var exchange = Assert.Single(workspace.Engine.Exchanges(result.Observation.Id, new()).Items);
        Assert.Equal(204, exchange.StatusCode); Assert.Equal("complete", exchange.Completeness);
        Assert.Contains(workspace.Engine.Events(result.Observation.Id, new()).Items, e => e.Kind == "tcp_out_of_order");
    }

    [Fact]
    public async Task EnforcesPacketBudgetWithoutOvercounting()
    {
        await using var workspace = new TestWorkspace();
        var path = Path.Combine(workspace.DirectoryPath, "limit.pcap"); await File.WriteAllBytesAsync(path, SyntheticTraffic.Pcap(SyntheticTraffic.HttpConversation()));
        var result = await workspace.Engine.StartAsync(new() { Mode = ObservationMode.Import, ImportPath = path, MaxPackets = 2 });
        var info = await workspace.Wait(result.Observation.Id);
        Assert.Equal(2, info.Packets); Assert.Equal("packet_limit", info.StopReason);
        Assert.Empty(workspace.Engine.Exchanges(info.Id, new()).Items);
    }

    [Fact]
    public async Task RestrictsImportPathsAndHandlesMalformedFiles()
    {
        await using var workspace = new TestWorkspace();
        await Assert.ThrowsAsync<ArgumentException>(() => workspace.Engine.StartAsync(new() { Mode = ObservationMode.Import, ImportPath = Path.Combine(Path.GetTempPath(), "outside.pcap") }));
        var path = Path.Combine(workspace.DirectoryPath, "bad.pcap"); await File.WriteAllBytesAsync(path, [1, 2, 3, 4]);
        var result = await workspace.Engine.StartAsync(new() { Mode = ObservationMode.Import, ImportPath = path });
        Assert.Equal(ObservationState.Failed, (await workspace.Wait(result.Observation.Id)).State);
        Assert.Contains(workspace.Engine.Events(result.Observation.Id, new()).Items, e => e.Kind == "observation_failed");
    }

    [Fact]
    public async Task ConcurrencyStopAndDeleteAreConsistent()
    {
        await using var workspace = new TestWorkspace(o => o with { MaxConcurrentObservations = 1 });
        var result = await workspace.Engine.StartAsync(new() { Mode = ObservationMode.Proxy, AllowedHosts = ["localhost"] });
        await Assert.ThrowsAsync<InvalidOperationException>(() => workspace.Engine.StartAsync(new() { Mode = ObservationMode.Proxy, AllowedHosts = ["localhost"] }));
        Assert.Throws<InvalidOperationException>(() => workspace.Engine.Delete(result.Observation.Id));
        var stops = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => workspace.Engine.StopAsync(result.Observation.Id)));
        Assert.All(stops, s => Assert.Equal(ObservationState.Completed, s.State));
        workspace.Engine.Delete(result.Observation.Id);
        Assert.Throws<KeyNotFoundException>(() => workspace.Engine.Status(result.Observation.Id));
    }

    [Fact]
    public async Task PaginationHasNoDuplicatesAndQueriesAreParameterized()
    {
        await using var workspace = new TestWorkspace();
        var path = Path.Combine(workspace.DirectoryPath, "pagination.pcap"); await File.WriteAllBytesAsync(path, SyntheticTraffic.Pcap(SyntheticTraffic.HttpConversation()));
        var result = await workspace.Engine.StartAsync(new() { Mode = ObservationMode.Import, ImportPath = path }); await workspace.Wait(result.Observation.Id);
        var ids = new List<string>(); long cursor = 0;
        do
        {
            var page = workspace.Engine.Events(result.Observation.Id, new(After: cursor, Limit: 1));
            ids.AddRange(page.Items.Select(e => e.Id));
            if (page.NextCursor == null) break;
            cursor = page.NextCursor.Value;
        } while (true);
        Assert.Equal(4, ids.Count); Assert.Equal(ids.Count, ids.Distinct().Count());
        Assert.Empty(workspace.Engine.Connections(result.Observation.Id, new(Protocol: "tcp' OR 1=1 --")).Items);
        Assert.Throws<ArgumentException>(() => workspace.Engine.Events(result.Observation.Id, new(Limit: 10000)));
    }

    [Fact]
    public async Task PersistsTerminalEvidenceAndRecoversInterruptedSessions()
    {
        await using var workspace = new TestWorkspace();
        workspace.Store.Save(new("interrupted", ObservationMode.Capture, ObservationState.Running, DateTimeOffset.UtcNow, null, 0, 0, 0, null, false, []));
        // Only open a second store after disposing the first to model an exclusive server restart.
        await workspace.Engine.DisposeAsync(); workspace.Store.Dispose();
        using var reopened = new EvidenceStore(workspace.Options);
        Assert.Equal(ObservationState.Interrupted, reopened.Get("interrupted").State);
        Assert.Equal("server_restarted", reopened.Get("interrupted").StopReason);
    }

    [Fact]
    public async Task ExclusiveStoreLeasePreventsASecondServerFromMarkingLiveWorkInterrupted()
    {
        await using var workspace = new TestWorkspace();
        Assert.Throws<StoreInUseException>(() => new EvidenceStore(workspace.Options));
    }

    [Fact]
    public async Task ConcurrentDesktopLaunchesGetIsolatedEvidenceStores()
    {
        await using var workspace = new TestWorkspace();
        using var second = EvidenceStore.OpenForServer(workspace.Options);
        Assert.NotEqual(workspace.Store.DataDirectory, second.DataDirectory);
        Assert.StartsWith(Path.Combine(workspace.DirectoryPath, "instances"), second.DataDirectory);
        second.Save(new("separate", ObservationMode.Proxy, ObservationState.Completed, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, 0, 0, 0, "requested", false, []));
        Assert.Empty(workspace.Store.ListObservations()); Assert.Single(second.ListObservations());
    }

    [Fact]
    public async Task SeparatesReusedTcpTuplesWhenNewSynIsObserved()
    {
        await using var workspace = new TestWorkspace();
        var first = SyntheticTraffic.HttpConversation();
        byte[][] second = [SyntheticTraffic.Tcp("", 999, flags: 2), SyntheticTraffic.Tcp("GET /again HTTP/1.1\r\nHost: app.test\r\n\r\n", 1000), SyntheticTraffic.Tcp("HTTP/1.1 204 No Content\r\n\r\n", 5000, true)];
        var path = Path.Combine(workspace.DirectoryPath, "reused.pcap"); await File.WriteAllBytesAsync(path, SyntheticTraffic.Pcap(first.Concat(second)));
        var result = await workspace.Engine.StartAsync(new() { Mode = ObservationMode.Import, ImportPath = path }); await workspace.Wait(result.Observation.Id);
        Assert.Equal(2, workspace.Engine.Connections(result.Observation.Id, new()).Items.Count);
        var exchanges = workspace.Engine.Exchanges(result.Observation.Id, new()).Items;
        Assert.Equal(2, exchanges.Count); Assert.Equal(2, exchanges.Select(e => e.ConnectionId).Distinct().Count());
    }

    [Fact]
    public async Task LargeGeneratedCaptureRemainsQueryableWithStableCounts()
    {
        await using var workspace = new TestWorkspace();
        var path = Path.Combine(workspace.DirectoryPath, "generated.pcap");
        await File.WriteAllBytesAsync(path, SyntheticTraffic.Pcap(Enumerable.Range(0, 2000).Select(i => SyntheticTraffic.Tcp("test", (uint)(100 + i * 4)))));
        var result = await workspace.Engine.StartAsync(new() { Mode = ObservationMode.Import, ImportPath = path, DurationSeconds = 30 });
        var status = await workspace.Wait(result.Observation.Id);
        Assert.Equal(ObservationState.Completed, status.State); Assert.Equal(2000, status.Packets);
        Assert.Equal(2000, Assert.Single(workspace.Engine.Connections(status.Id, new()).Items).Packets);
    }
}
