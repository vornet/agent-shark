using System.Buffers.Binary;
using System.Text;
using System.Net;

namespace AgentShark.Core.Protocols;

public static class DnsDecoder
{
    public static Dictionary<string, string> Decode(ReadOnlySpan<byte> data)
    {
        if (data.Length < 12) throw new InvalidDataException("Truncated DNS header.");
        int count = BinaryPrimitives.ReadUInt16BigEndian(data[4..]);
        if (count > 64) throw new InvalidDataException("DNS question limit exceeded.");
        var fields = new Dictionary<string, string>
        {
            ["transactionId"] = BinaryPrimitives.ReadUInt16BigEndian(data).ToString(),
            ["response"] = ((data[2] & 128) != 0).ToString(),
            ["responseCode"] = (data[3] & 15).ToString(),
            ["truncated"] = ((data[2] & 2) != 0).ToString(),
            ["answers"] = BinaryPrimitives.ReadUInt16BigEndian(data[6..]).ToString()
        };
        int position = 12;
        for (int i = 0; i < count; i++)
        {
            var name = Name(data, ref position);
            if (position + 4 > data.Length) throw new InvalidDataException("Truncated DNS question.");
            if (i < 8) { fields[$"question{i}"] = name; fields[$"type{i}"] = BinaryPrimitives.ReadUInt16BigEndian(data[position..]).ToString(); }
            position += 4;
        }
        int answers = BinaryPrimitives.ReadUInt16BigEndian(data[6..]);
        if (answers > 256) throw new InvalidDataException("DNS answer limit exceeded.");
        for (int i = 0; i < answers; i++)
        {
            string name = Name(data, ref position);
            if (position + 10 > data.Length) throw new InvalidDataException("Truncated DNS answer.");
            int type = BinaryPrimitives.ReadUInt16BigEndian(data[position..]);
            uint ttl = BinaryPrimitives.ReadUInt32BigEndian(data[(position + 4)..]);
            int length = BinaryPrimitives.ReadUInt16BigEndian(data[(position + 8)..]); position += 10;
            if (position + length > data.Length) throw new InvalidDataException("Truncated DNS answer data.");
            string? value = null;
            if ((type == 1 && length == 4) || (type == 28 && length == 16)) value = new IPAddress(data.Slice(position, length)).ToString();
            if (type == 5) { int p = position; value = Name(data, ref p); if (p > position + length) throw new InvalidDataException("Invalid DNS CNAME length."); }
            if (i < 16)
            {
                fields[$"answer{i}.name"] = name; fields[$"answer{i}.type"] = type.ToString(); fields[$"answer{i}.ttl"] = ttl.ToString();
                if (value != null) fields[$"answer{i}.value"] = value;
            }
            position += length;
        }
        return fields;
    }

    private static string Name(ReadOnlySpan<byte> data, ref int position)
    {
        int p = position, jumps = 0; bool jumped = false;
        var name = new StringBuilder();
        while (true)
        {
            if (p >= data.Length || jumps++ > 128) throw new InvalidDataException("Invalid DNS name or compression cycle.");
            int length = data[p++];
            if ((length & 0xc0) == 0xc0)
            {
                if (p >= data.Length) throw new InvalidDataException("Truncated DNS pointer.");
                if (!jumped) position = p + 1;
                jumped = true; p = ((length & 63) << 8) | data[p]; continue;
            }
            if ((length & 0xc0) != 0) throw new InvalidDataException("Invalid DNS label.");
            if (length == 0) { if (!jumped) position = p; return name.ToString(); }
            if (p + length > data.Length || name.Length + length > 253) throw new InvalidDataException("Invalid DNS name length.");
            if (name.Length > 0) name.Append('.');
            foreach (byte c in data.Slice(p, length)) name.Append(c is >= 33 and <= 126 ? (char)c : '?');
            p += length;
        }
    }
}
