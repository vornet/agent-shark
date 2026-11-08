using System.Buffers.Binary;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using AgentShark.Core.Protocols;

namespace AgentShark.Core.Capture;

/// <summary>Best-effort socket ownership snapshots, never presented as definitive per-packet attribution.</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsProcessCorrelator
{
    private readonly Dictionary<string, HashSet<int>> _owners = [];
    private long _refreshed;

    public bool Matches(DecodedPacket packet, int processId)
    {
        if (_refreshed == 0 || Environment.TickCount64 - _refreshed >= 100)
        {
            _owners.Clear();
            ReadTable(false, false); ReadTable(false, true); ReadTable(true, false); ReadTable(true, true);
            _refreshed = Environment.TickCount64;
        }
        return Owns(packet.Protocol, packet.Source, processId) || Owns(packet.Protocol, packet.Destination, processId);
    }

    private bool Owns(string protocol, NetworkEndpoint endpoint, int pid)
    {
        if (IPAddress.TryParse(endpoint.Address, out var address) && address.IsIPv4MappedToIPv6)
            endpoint = endpoint with { Address = address.MapToIPv4().ToString() };
        return (_owners.TryGetValue($"{protocol}|{endpoint}", out var exact) && exact.Contains(pid)) ||
            (_owners.TryGetValue($"{protocol}|{new NetworkEndpoint(endpoint.Address.Contains(':') ? "::" : "0.0.0.0", endpoint.Port)}", out var wildcard) && wildcard.Contains(pid));
    }

    private void ReadTable(bool udp, bool ipv6)
    {
        uint size = 0; uint family = ipv6 ? 23u : 2u;
        uint result = udp ? GetExtendedUdpTable(IntPtr.Zero, ref size, false, family, 1, 0) : GetExtendedTcpTable(IntPtr.Zero, ref size, false, family, 5, 0);
        if (result != 122 || size > 16 * 1024 * 1024 || size < 4) return;
        IntPtr buffer = Marshal.AllocHGlobal(checked((int)size));
        try
        {
            result = udp ? GetExtendedUdpTable(buffer, ref size, false, family, 1, 0) : GetExtendedTcpTable(buffer, ref size, false, family, 5, 0);
            if (result != 0) return;
            var bytes = new byte[size]; Marshal.Copy(buffer, bytes, 0, bytes.Length);
            int count = BinaryPrimitives.ReadInt32LittleEndian(bytes);
            int rowSize = ipv6 ? (udp ? 28 : 56) : (udp ? 12 : 24);
            if (count < 0 || count > (bytes.Length - 4) / rowSize) return;
            for (int i = 0, offset = 4; i < count; i++, offset += rowSize)
            {
                var row = bytes.AsSpan(offset, rowSize);
                int addressOffset = ipv6 || udp ? 0 : 4;
                var ip = new IPAddress(row.Slice(addressOffset, ipv6 ? 16 : 4));
                string address = (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip).ToString();
                int port = BinaryPrimitives.ReadUInt16BigEndian(row[(ipv6 ? 20 : (udp ? 4 : 8))..]);
                int pid = BinaryPrimitives.ReadInt32LittleEndian(row[(rowSize - 4)..]);
                string key = $"{(udp ? "udp" : "tcp")}|{new NetworkEndpoint(address, port)}";
                if (!_owners.TryGetValue(key, out var owners)) _owners[key] = owners = [];
                owners.Add(pid);
            }
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref uint size, [MarshalAs(UnmanagedType.Bool)] bool order, uint family, uint tableClass, uint reserved);
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint GetExtendedUdpTable(IntPtr table, ref uint size, [MarshalAs(UnmanagedType.Bool)] bool order, uint family, uint tableClass, uint reserved);
}
