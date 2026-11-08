using System.Net;
using System.Net.Sockets;
using AgentShark.Core;

namespace AgentShark.Tests;

public sealed class NativeCaptureFactAttribute : FactAttribute
{
    public NativeCaptureFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("AGENTSHARK_TEST_NATIVE") != "1") Skip = "Set AGENTSHARK_TEST_NATIVE=1 with native capture access to run the isolated loopback integration test.";
    }
}

public sealed class NativeCaptureTests
{
    [NativeCaptureFact]
    public async Task CapturesOnlySyntheticLoopbackTraffic()
    {
        await using var workspace = new TestWorkspace();
        var capabilities = workspace.Engine.Capabilities();
        Assert.True(capabilities.NativeCaptureAvailable, capabilities.CaptureError);
        var device = capabilities.Interfaces.First(d => d.Id is "lo" or "lo0" || d.Id.Contains("NPF_Loopback", StringComparison.OrdinalIgnoreCase));
        using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var origin = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync(timeout.Token);
            var stream = client.GetStream(); var buffer = new byte[4096];
            _ = await stream.ReadAsync(buffer, timeout.Token);
            await stream.WriteAsync("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"u8.ToArray(), timeout.Token);
        }, timeout.Token);
        var observation = await workspace.Engine.StartAsync(new() { Mode = ObservationMode.Capture, InterfaceId = device.Id, CaptureFilter = $"tcp port {port} and host 127.0.0.1", DurationSeconds = 8 });
        using var http = new HttpClient(new HttpClientHandler { UseProxy = false });
        Assert.Equal("ok", await http.GetStringAsync($"http://127.0.0.1:{port}/agent-shark-generated-test", timeout.Token));
        await origin;
        while (workspace.Engine.Exchanges(observation.Observation.Id, new()).Items.All(e => e.StatusCode == null)) await Task.Delay(50, timeout.Token);
        var status = await workspace.Engine.StopAsync(observation.Observation.Id, timeout.Token);
        Assert.Equal(ObservationState.Completed, status.State); Assert.True(status.Packets > 0);
        Assert.Contains(workspace.Engine.Exchanges(status.Id, new()).Items, e => e.StatusCode == 200);
    }
}
