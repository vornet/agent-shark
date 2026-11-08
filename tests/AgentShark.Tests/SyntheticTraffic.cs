using System.Buffers.Binary;
using System.Net;
using AgentShark.Core.Capture;

namespace AgentShark.Tests;

internal static class SyntheticTraffic
{
    public static byte[] Tcp(string text, uint sequence, bool reverse = false, byte flags = 0x18)
    {
        var payload = System.Text.Encoding.ASCII.GetBytes(text);
        var packet = new byte[40 + payload.Length];
        packet[0] = 0x45; BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), (ushort)packet.Length);
        packet[8] = 64; packet[9] = 6;
        IPAddress.Parse(reverse ? "192.0.2.2" : "192.0.2.1").GetAddressBytes().CopyTo(packet, 12);
        IPAddress.Parse(reverse ? "192.0.2.1" : "192.0.2.2").GetAddressBytes().CopyTo(packet, 16);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(20), reverse ? (ushort)80 : (ushort)50000);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(22), reverse ? (ushort)50000 : (ushort)80);
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(24), sequence);
        packet[32] = 0x50; packet[33] = flags; payload.CopyTo(packet, 40);
        return packet;
    }

    public static byte[][] HttpConversation() =>
    [
        Tcp("", 99, flags: 2), Tcp("", 199, reverse: true, flags: 0x12),
        Tcp("GET /health?token=private HTTP/1.1\r\nHost: app.test\r\nAuthorization: Bearer hidden\r\n\r\n", 100),
        Tcp("HTTP/1.1 503 Unavailable\r\nContent-Length: 7\r\nContent-Type: text/plain\r\nSet-Cookie: hidden\r\n\r\nfailed!", 200, reverse: true)
    ];

    public static byte[] Pcap(IEnumerable<byte[]> packets, bool little = true, bool nano = false)
    {
        using var output = new MemoryStream();
        void U32(uint value) { var b = new byte[4]; if (little) BinaryPrimitives.WriteUInt32LittleEndian(b, value); else BinaryPrimitives.WriteUInt32BigEndian(b, value); output.Write(b); }
        void U16(ushort value) { var b = new byte[2]; if (little) BinaryPrimitives.WriteUInt16LittleEndian(b, value); else BinaryPrimitives.WriteUInt16BigEndian(b, value); output.Write(b); }
        U32(nano ? 0xa1b23c4du : 0xa1b2c3d4u); U16(2); U16(4); U32(0); U32(0); U32(65535); U32(101);
        uint index = 0;
        foreach (var packet in packets) { U32(1700000000 + index++); U32(nano ? 123456789u : 123456u); U32((uint)packet.Length); U32((uint)packet.Length); output.Write(packet); }
        return output.ToArray();
    }

    public static byte[] PcapNg(byte[] packet, bool little = true)
    {
        using var output = new MemoryStream();
        byte[] U32(uint value) { var b = new byte[4]; if (little) BinaryPrimitives.WriteUInt32LittleEndian(b, value); else BinaryPrimitives.WriteUInt32BigEndian(b, value); return b; }
        void Block(uint type, byte[] body)
        {
            uint length = (uint)(12 + body.Length); output.Write(U32(type)); output.Write(U32(length)); output.Write(body); output.Write(U32(length));
        }
        Block(0x0a0d0d0a, [.. U32(0x1a2b3c4d), .. (little ? new byte[] { 1, 0, 0, 0 } : new byte[] { 0, 1, 0, 0 }), .. Enumerable.Repeat((byte)255, 8)]);
        Block(1, [.. (little ? new byte[] { 101, 0, 0, 0 } : new byte[] { 0, 101, 0, 0 }), .. U32(65535)]);
        Block(6, [.. U32(0), .. U32(0), .. U32(1234567), .. U32((uint)packet.Length), .. U32((uint)packet.Length), .. packet, .. new byte[(4 - packet.Length % 4) % 4]]);
        return output.ToArray();
    }
}
