using System.Buffers.Binary;
using AgentShark.Core.Capture;

namespace AgentShark.Core.Protocols;

public static class IcmpDecoder
{
    public static Dictionary<string, string> Decode(byte[] payload, bool ipv6)
    {
        if (payload.Length < 8) throw new InvalidDataException("Truncated ICMP header.");
        int type = payload[0], code = payload[1];
        string description = (ipv6, type) switch
        {
            (false, 0) => "ICMP echo reply",
            (false, 8) => "ICMP echo request",
            (false, 3) => "ICMP destination unreachable",
            (false, 11) => "ICMP time exceeded",
            (false, 12) => "ICMP parameter problem",
            (true, 1) => "ICMPv6 destination unreachable",
            (true, 2) => "ICMPv6 packet too big",
            (true, 3) => "ICMPv6 time exceeded",
            (true, 4) => "ICMPv6 parameter problem",
            (true, 128) => "ICMPv6 echo request",
            (true, 129) => "ICMPv6 echo reply",
            _ => "ICMP message"
        };
        bool error = ipv6 ? type < 128 : type is 3 or 4 or 5 or 11 or 12;
        var fields = new Dictionary<string, string> { ["type"] = type.ToString(), ["code"] = code.ToString(), ["isError"] = error.ToString(), ["description"] = description };
        if (ipv6 && type == 2) fields["mtu"] = BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(4)).ToString();
        if (!ipv6 && type == 3 && code == 4) fields["mtu"] = BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan(6)).ToString();
        if (error && payload.Length > 8)
        {
            try
            {
                var quoted = PacketDecoder.Decode(new CapturedPacket(DateTimeOffset.UnixEpoch, 101, payload[8..], payload.Length - 8));
                if (quoted != null) { fields["quotedSource"] = quoted.Source.ToString(); fields["quotedDestination"] = quoted.Destination.ToString(); fields["quotedProtocol"] = quoted.Protocol; }
            }
            catch (InvalidDataException) { fields["quotedPacket"] = "incomplete_or_unsupported"; }
        }
        return fields;
    }
}
