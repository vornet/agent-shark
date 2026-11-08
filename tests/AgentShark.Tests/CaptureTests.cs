using AgentShark.Core.Capture;
using AgentShark.Core.Protocols;

namespace AgentShark.Tests;

public sealed class CaptureTests
{
    [Theory]
    [InlineData(true, false)]
    [InlineData(false, false)]
    [InlineData(true, true)]
    [InlineData(false, true)]
    public async Task ReadsPcapByteOrdersAndTimestampResolutions(bool little, bool nano)
    {
        using var stream = new MemoryStream(SyntheticTraffic.Pcap([SyntheticTraffic.Tcp("abc", 1)], little, nano));
        var packets = new List<CapturedPacket>();
        await foreach (var packet in CaptureReader.ReadAsync(stream)) packets.Add(packet);
        var p = Assert.Single(packets);
        Assert.Equal(101, p.LinkType); Assert.Equal("abc"u8.ToArray(), PacketDecoder.Decode(p)!.Payload);
        Assert.Equal(nano ? 1234567 : 1234560, (p.Timestamp - DateTimeOffset.FromUnixTimeSeconds(1700000000)).Ticks);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ReadsPcapNgSections(bool little)
    {
        using var stream = new MemoryStream(SyntheticTraffic.PcapNg(SyntheticTraffic.Tcp("hello", 1), little));
        await foreach (var packet in CaptureReader.ReadAsync(stream))
        {
            Assert.Equal(101, packet.LinkType);
            Assert.Equal("hello"u8.ToArray(), PacketDecoder.Decode(packet)!.Payload);
            Assert.InRange((packet.Timestamp - DateTimeOffset.UnixEpoch).TotalSeconds, 1.234566, 1.234568);
        }
    }

    [Fact]
    public async Task RejectsMismatchedPcapNgBlockLength()
    {
        var data = SyntheticTraffic.PcapNg(SyntheticTraffic.Tcp("a", 1)); data[^1] ^= 1;
        await Assert.ThrowsAsync<InvalidDataException>(async () => { await foreach (var _ in CaptureReader.ReadAsync(new MemoryStream(data))) { } });
    }

    [Fact]
    public async Task RejectsTruncatedRecords()
    {
        var data = SyntheticTraffic.Pcap([SyntheticTraffic.Tcp("abc", 1)]);
        await Assert.ThrowsAsync<EndOfStreamException>(async () => { await foreach (var _ in CaptureReader.ReadAsync(new MemoryStream(data[..^1]))) { } });
    }

    [Fact]
    public void DecodesVlanAndLoopback()
    {
        var ip = SyntheticTraffic.Tcp("test", 10);
        byte[] ethernet = [.. new byte[12], 0x81, 0, 0, 1, 8, 0, .. ip];
        Assert.Equal("test"u8.ToArray(), PacketDecoder.Decode(new(DateTimeOffset.UtcNow, 1, ethernet, ethernet.Length))!.Payload);
        byte[] loopback = [2, 0, 0, 0, .. ip];
        Assert.NotNull(PacketDecoder.Decode(new(DateTimeOffset.UtcNow, 0, loopback, loopback.Length)));
    }

    [Fact]
    public void NeverTreatsFragmentsAsWholeTcpSegments()
    {
        var bytes = SyntheticTraffic.Tcp("abc", 1); bytes[6] = 0x20;
        Assert.Throws<InvalidDataException>(() => PacketDecoder.Decode(new(DateTimeOffset.UtcNow, 101, bytes, bytes.Length)));
    }

    [Fact]
    public void DecodesIpv6UdpWithHopByHopExtension()
    {
        var bytes = new byte[59]; bytes[0] = 0x60; bytes[5] = 19; bytes[6] = 0; bytes[7] = 64;
        System.Net.IPAddress.Parse("2001:db8::1").GetAddressBytes().CopyTo(bytes, 8);
        System.Net.IPAddress.Parse("2001:db8::2").GetAddressBytes().CopyTo(bytes, 24);
        bytes[40] = 17; bytes[41] = 0;
        bytes[48] = 0xc3; bytes[49] = 0x50; bytes[51] = 53; bytes[53] = 11;
        "abc"u8.CopyTo(bytes.AsSpan(56));
        var packet = PacketDecoder.Decode(new(DateTimeOffset.UnixEpoch, 101, bytes, bytes.Length))!;
        Assert.Equal("2001:db8::1", packet.Source.Address); Assert.Equal(53, packet.Destination.Port);
        Assert.Equal("abc"u8.ToArray(), packet.Payload); Assert.False(packet.Truncated);
    }

    [Fact]
    public void DecodesIcmpErrorsAndMtu()
    {
        var bytes = SyntheticTraffic.Tcp("", 1)[..28];
        bytes[2] = 0; bytes[3] = 28; bytes[9] = 1;
        bytes[20] = 3; bytes[21] = 4; bytes[26] = 0x05; bytes[27] = 0xdc;
        var packet = PacketDecoder.Decode(new(DateTimeOffset.UnixEpoch, 101, bytes, bytes.Length))!;
        var fields = IcmpDecoder.Decode(packet.Payload, false);
        Assert.Equal("icmp", packet.Protocol); Assert.Equal("1500", fields["mtu"]); Assert.Equal("True", fields["isError"]);
    }

    [Fact]
    public void MalformedPacketCorpusDoesNotEscapeBoundsChecks()
    {
        var random = new Random(42);
        int[] links = [0, 1, 101, 113, 276];
        for (int i = 0; i < 10000; i++)
        {
            var bytes = new byte[random.Next(0, 256)]; random.NextBytes(bytes);
            try { PacketDecoder.Decode(new(DateTimeOffset.UnixEpoch, links[i % links.Length], bytes, bytes.Length)); }
            catch (InvalidDataException) { }
        }
    }
}
