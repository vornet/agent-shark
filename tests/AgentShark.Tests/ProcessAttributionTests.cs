using System.Net;
using System.Net.Sockets;
using AgentShark.Core;
using AgentShark.Core.Capture;
using AgentShark.Core.Protocols;

namespace AgentShark.Tests;

public sealed class WindowsFactAttribute : FactAttribute
{
    public WindowsFactAttribute()
    {
        if (!OperatingSystem.IsWindows()) Skip = "Windows socket ownership API test.";
    }
}

public sealed class ProcessAttributionTests
{
    [WindowsFact]
    public async Task CorrelatesGeneratedTcpAndUdpSocketsToThisProcess()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);
        using var server = await listener.AcceptTcpClientAsync();
        var local = (IPEndPoint)client.Client.LocalEndPoint!; var remote = (IPEndPoint)client.Client.RemoteEndPoint!;
        var tcp = new DecodedPacket(new(local.Address.ToString(), local.Port), new(remote.Address.ToString(), remote.Port), "tcp", [], 0, 0, false);
        var correlator = new WindowsProcessCorrelator();
        Assert.True(correlator.Matches(tcp, Environment.ProcessId)); Assert.False(correlator.Matches(tcp, int.MaxValue));
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        local = (IPEndPoint)udp.Client.LocalEndPoint!;
        var datagram = new DecodedPacket(new(local.Address.ToString(), local.Port), new("192.0.2.2", 12345), "udp", [], 0, 0, false);
        Assert.True(new WindowsProcessCorrelator().Matches(datagram, Environment.ProcessId));
    }
}
