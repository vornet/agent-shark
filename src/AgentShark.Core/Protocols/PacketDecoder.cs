using System.Buffers.Binary;
using System.Net;
using AgentShark.Core.Capture;

namespace AgentShark.Core.Protocols;

public sealed record DecodedPacket(NetworkEndpoint Source, NetworkEndpoint Destination, string Protocol,
    byte[] Payload, uint Sequence, byte TcpFlags, bool Truncated);

public static class PacketDecoder
{
    public static DecodedPacket? Decode(CapturedPacket packet)
    {
        ReadOnlySpan<byte> b = packet.Data;
        int offset; int etherType;
        switch (packet.LinkType)
        {
            case 1:
                Need(b, 14); offset = 14; etherType = U16(b, 12);
                for (int tags = 0; etherType is 0x8100 or 0x88a8 or 0x9100; tags++)
                {
                    if (tags == 4) throw new InvalidDataException("Excessive VLAN nesting.");
                    Need(b, offset + 4); etherType = U16(b, offset + 2); offset += 4;
                }
                break;
            case 0:
            case 108:
                Need(b, 5); offset = 4; etherType = (b[offset] >> 4) == 6 ? 0x86dd : 0x0800; break;
            case 101:
            case 12:
            case 228:
            case 229:
                Need(b, 1); offset = 0; etherType = (b[0] >> 4) == 6 ? 0x86dd : 0x0800; break;
            case 113: Need(b, 16); offset = 16; etherType = U16(b, 14); break;
            case 276: Need(b, 20); offset = 20; etherType = U16(b, 0); break;
            default: throw new InvalidDataException($"Unsupported link type {packet.LinkType}.");
        }
        if (etherType is not (0x0800 or 0x86dd)) return null;
        b = b[offset..];
        string source, destination; int protocol;
        bool truncated = packet.Data.Length < packet.OriginalLength;
        if (etherType == 0x0800)
        {
            Need(b, 20); int ihl = (b[0] & 15) * 4, total = U16(b, 2);
            if ((b[0] >> 4) != 4 || ihl < 20 || total < ihl) throw new InvalidDataException("Invalid IPv4 header.");
            Need(b, ihl);
            if ((U16(b, 6) & 0x3fff) != 0) throw new InvalidDataException("IPv4 fragments require reassembly; packet was not decoded.");
            truncated |= total > b.Length; b = b[..Math.Min(total, b.Length)];
            source = new IPAddress(b.Slice(12, 4)).ToString(); destination = new IPAddress(b.Slice(16, 4)).ToString();
            protocol = b[9]; b = b[ihl..];
        }
        else
        {
            Need(b, 40);
            if ((b[0] >> 4) != 6) throw new InvalidDataException("Invalid IPv6 header.");
            int total = U16(b, 4) + 40;
            if (total == 40) throw new InvalidDataException("IPv6 jumbograms are not supported.");
            truncated |= total > b.Length; b = b[..Math.Min(total, b.Length)];
            source = new IPAddress(b.Slice(8, 16)).ToString(); destination = new IPAddress(b.Slice(24, 16)).ToString();
            protocol = b[6]; b = b[40..];
            for (int depth = 0; protocol is 0 or 43 or 60 or 51 or 44; depth++)
            {
                if (depth >= 8) throw new InvalidDataException("Excessive IPv6 extension nesting.");
                Need(b, 2);
                if (protocol == 44) throw new InvalidDataException("IPv6 fragments require reassembly; packet was not decoded.");
                int length = protocol == 51 ? (b[1] + 2) * 4 : (b[1] + 1) * 8;
                Need(b, length); protocol = b[0]; b = b[length..];
            }
        }
        if (protocol == 6)
        {
            Need(b, 20); int length = (b[12] >> 4) * 4;
            if (length < 20) throw new InvalidDataException("Invalid TCP header.");
            Need(b, length);
            return new(new(source, U16(b, 0)), new(destination, U16(b, 2)), "tcp", b[length..].ToArray(), BinaryPrimitives.ReadUInt32BigEndian(b[4..]), b[13], truncated);
        }
        if (protocol == 17)
        {
            Need(b, 8); int length = U16(b, 4);
            if (length < 8) throw new InvalidDataException("Invalid UDP length.");
            truncated |= length > b.Length;
            return new(new(source, U16(b, 0)), new(destination, U16(b, 2)), "udp", b.Slice(8, Math.Min(length, b.Length) - 8).ToArray(), 0, 0, truncated);
        }
        if (protocol is 1 or 58)
        {
            Need(b, 8);
            return new(new(source, 0), new(destination, 0), protocol == 1 ? "icmp" : "icmpv6", b.ToArray(), 0, 0, truncated);
        }
        return null;
    }

    private static int U16(ReadOnlySpan<byte> b, int offset) => BinaryPrimitives.ReadUInt16BigEndian(b[offset..]);
    private static void Need(ReadOnlySpan<byte> b, int count)
    {
        if (b.Length < count) throw new InvalidDataException("Truncated packet header.");
    }
}
