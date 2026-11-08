using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace AgentShark.Core.Capture;

public sealed record CapturedPacket(DateTimeOffset Timestamp, int LinkType, byte[] Data, int OriginalLength);

/// <summary>Managed PCAP/PCAPNG reader; native capture libraries are not needed for offline analysis.</summary>
public static class CaptureReader
{
    private const int MaxBlock = 4 * 1024 * 1024;

    public static async IAsyncEnumerable<CapturedPacket> ReadAsync(Stream stream, [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var magic = new byte[4];
        await stream.ReadExactlyAsync(magic, cancellationToken);
        if (magic.AsSpan().SequenceEqual(new byte[] { 10, 13, 13, 10 }))
        {
            await foreach (var packet in ReadNg(stream, cancellationToken)) yield return packet;
            yield break;
        }
        var value = BinaryPrimitives.ReadUInt32LittleEndian(magic);
        bool little = value is 0xa1b2c3d4 or 0xa1b23c4d;
        bool nanos = value is 0xa1b23c4d or 0x4d3cb2a1;
        if (!little && value is not (0xd4c3b2a1 or 0x4d3cb2a1)) throw new InvalidDataException("Unrecognized capture format.");
        var header = new byte[20];
        await stream.ReadExactlyAsync(header, cancellationToken);
        if (U16(header, 0, little) != 2 || U16(header, 2, little) != 4) throw new InvalidDataException("Unsupported PCAP version.");
        int snap = checked((int)U32(header, 12, little));
        int link = (int)(U32(header, 16, little) & 0xffff);
        if (snap is <= 0 or > MaxBlock) throw new InvalidDataException("Invalid capture snapshot length.");
        var record = new byte[16];
        while (await ReadHeader(stream, record, cancellationToken))
        {
            uint length = U32(record, 8, little), original = U32(record, 12, little);
            uint fraction = U32(record, 4, little);
            if (length > snap || length > original || original > int.MaxValue || fraction >= (nanos ? 1_000_000_000 : 1_000_000)) throw new InvalidDataException("Invalid PCAP record.");
            var data = new byte[(int)length];
            await stream.ReadExactlyAsync(data, cancellationToken);
            long ticks = nanos ? fraction / 100 : (long)fraction * 10;
            var time = DateTimeOffset.FromUnixTimeSeconds(U32(record, 0, little)).AddTicks(ticks);
            yield return new(time, link, data, (int)original);
        }
    }

    private sealed record Interface(int Link, uint Snap, double Resolution, long Offset);

    private static async IAsyncEnumerable<CapturedPacket> ReadNg(Stream stream, [EnumeratorCancellation] CancellationToken ct)
    {
        bool little = true, first = true;
        var interfaces = new List<Interface>();
        var header = new byte[8];
        while (true)
        {
            bool section;
            if (first)
            {
                first = false;
                header[0] = 10; header[1] = 13; header[2] = 13; header[3] = 10;
                await stream.ReadExactlyAsync(header.AsMemory(4), ct);
                section = true;
            }
            else
            {
                if (!await ReadHeader(stream, header, ct)) yield break;
                section = BinaryPrimitives.ReadUInt32LittleEndian(header) == 0x0a0d0d0a;
            }
            byte[]? bom = null;
            if (section)
            {
                bom = new byte[4];
                await stream.ReadExactlyAsync(bom, ct);
                var order = BinaryPrimitives.ReadUInt32LittleEndian(bom);
                if (order is not (0x1a2b3c4d or 0x4d3c2b1a)) throw new InvalidDataException("Invalid PCAPNG byte order.");
                little = order == 0x1a2b3c4d;
                interfaces.Clear();
            }
            var length = U32(header, 4, little);
            if (length < (section ? 28 : 12) || length > MaxBlock || length % 4 != 0) throw new InvalidDataException("Invalid PCAPNG block length.");
            var body = new byte[(int)length - 8];
            int already = section ? 4 : 0;
            if (bom != null) bom.CopyTo(body, 0);
            await stream.ReadExactlyAsync(body.AsMemory(already), ct);
            if (U32(body, body.Length - 4, little) != length) throw new InvalidDataException("PCAPNG block length mismatch.");
            var type = U32(header, 0, little);
            if (section)
            {
                if (U16(body, 4, little) != 1) throw new InvalidDataException("Unsupported PCAPNG version.");
            }
            else if (type == 1)
            {
                if (body.Length < 12 || interfaces.Count >= 1024) throw new InvalidDataException("Invalid PCAPNG interface block.");
                double resolution = 0.000001; long offset = 0;
                for (int p = 8; p + 4 <= body.Length - 4;)
                {
                    var code = U16(body, p, little); var size = U16(body, p + 2, little); p += 4;
                    if (code == 0) break;
                    if (p + size > body.Length - 4) throw new InvalidDataException("Invalid PCAPNG option.");
                    if (code == 9 && size == 1) resolution = Math.Pow((body[p] & 128) == 0 ? 10 : 2, -(body[p] & 127));
                    if (code == 14 && size == 8) offset = unchecked((long)U64(body, p, little));
                    p += (size + 3) & ~3;
                }
                uint snap = U32(body, 4, little);
                interfaces.Add(new(U16(body, 0, little), snap, resolution, offset));
            }
            else if (type == 6)
            {
                if (body.Length < 24) throw new InvalidDataException("Truncated PCAPNG packet block.");
                uint index = U32(body, 0, little), captured = U32(body, 12, little), original = U32(body, 16, little);
                if (index >= interfaces.Count || captured > body.Length - 24 || captured > original || original > int.MaxValue) throw new InvalidDataException("Invalid PCAPNG packet.");
                var iface = interfaces[(int)index];
                if (iface.Snap != 0 && captured > iface.Snap) throw new InvalidDataException("Packet exceeds interface snapshot length.");
                ulong timestamp = ((ulong)U32(body, 4, little) << 32) | U32(body, 8, little);
                double seconds = timestamp * iface.Resolution + iface.Offset;
                if (!double.IsFinite(seconds) || seconds < -62135596800d || seconds >= 253402300799d) throw new InvalidDataException("Invalid packet timestamp.");
                yield return new(DateTimeOffset.UnixEpoch.AddSeconds(seconds), iface.Link, body.AsSpan(20, (int)captured).ToArray(), (int)original);
            }
            else if (type is 2 or 3)
            {
                // Simple packet blocks have no timestamp. Reject instead of inventing timing evidence.
                throw new InvalidDataException("PCAPNG simple packet blocks have no timestamps; timestamped enhanced packet blocks are required.");
            }
        }
    }

    private static async Task<bool> ReadHeader(Stream stream, byte[] header, CancellationToken ct)
    {
        int read = await stream.ReadAsync(header.AsMemory(0, 1), ct);
        if (read == 0) return false;
        await stream.ReadExactlyAsync(header.AsMemory(1), ct);
        return true;
    }
    private static ushort U16(byte[] b, int p, bool little) => little ? BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(p)) : BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(p));
    private static uint U32(byte[] b, int p, bool little) => little ? BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(p)) : BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(p));
    private static ulong U64(byte[] b, int p, bool little) => little ? BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(p)) : BinaryPrimitives.ReadUInt64BigEndian(b.AsSpan(p));
}
