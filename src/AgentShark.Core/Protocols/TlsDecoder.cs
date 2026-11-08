using System.Buffers.Binary;
using System.Text;

namespace AgentShark.Core.Protocols;

public static class TlsDecoder
{
    public static Dictionary<string, string>? ClientHello(ReadOnlySpan<byte> data)
    {
        if (data.Length < 5 || data[0] != 22 || data[1] != 3) return null;
        int recordLength = U16(data, 3);
        if (recordLength > 18432) throw new InvalidDataException("Invalid TLS record length.");
        if (data.Length < recordLength + 5) return null;
        data = data.Slice(5, recordLength);
        if (data.Length < 4 || data[0] != 1) return new() { ["recordType"] = "handshake", ["decryption"] = "unavailable" };
        int helloLength = (data[1] << 16) | (data[2] << 8) | data[3];
        if (helloLength + 4 > data.Length) return new() { ["recordType"] = "fragmented_client_hello", ["decryption"] = "unavailable" };
        data = data.Slice(4, helloLength);
        Need(data, 35); int p = 34; int session = data[p++]; p += session;
        Need(data, p + 2); p += U16(data, p) + 2;
        Need(data, p + 1); p += data[p] + 1;
        var fields = new Dictionary<string, string> { ["decryption"] = "unavailable", ["recordType"] = "client_hello" };
        if (p == data.Length) return fields;
        Need(data, p + 2); int end = p + 2 + U16(data, p); p += 2; Need(data, end);
        while (p < end)
        {
            Need(data[..end], p + 4); int type = U16(data, p), length = U16(data, p + 2); p += 4;
            if (p + length > end) throw new InvalidDataException("Invalid TLS extension length.");
            var ext = data.Slice(p, length);
            if (type == 0 && length >= 5)
            {
                int size = U16(ext, 3);
                if (ext[2] == 0 && size <= ext.Length - 5) fields["serverName"] = Privacy.Clip(Encoding.ASCII.GetString(ext.Slice(5, size)), 253);
            }
            if (type == 16 && length >= 3)
            {
                int size = ext[2];
                if (size <= ext.Length - 3) fields["firstAlpn"] = Privacy.Clip(Encoding.ASCII.GetString(ext.Slice(3, size)), 255);
            }
            p += length;
        }
        return fields;
    }
    private static int U16(ReadOnlySpan<byte> data, int p) => BinaryPrimitives.ReadUInt16BigEndian(data[p..]);
    private static void Need(ReadOnlySpan<byte> data, int length) { if (data.Length < length) throw new InvalidDataException("Truncated TLS ClientHello."); }
}
