using System.Globalization;
using System.Text;

namespace AgentShark.Core.Protocols;

public sealed record HttpMessage(string Method, string Target, int? Status, Dictionary<string, string> Headers, byte[] Body, int Consumed, string Version = "HTTP/1.1");

public static class Http1Decoder
{
    public const int MaxHeaderBytes = 32768;
    private static readonly string[] Methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE"];

    public static bool LooksLikeHttp(ReadOnlySpan<byte> data)
    {
        if (data.Length < 4) return false;
        if (data.StartsWith("HTTP/1."u8)) return true;
        foreach (var method in Methods) if (StartsWith(data, method)) return true;
        return false;
    }

    private static bool StartsWith(ReadOnlySpan<byte> data, string method)
    {
        var bytes = Encoding.ASCII.GetBytes(method + " ");
        return data.StartsWith(bytes);
    }

    public static HttpMessage? TryRead(ReadOnlySpan<byte> data, int maxMessageBytes, bool endOfStream = false, bool responseToHead = false)
    {
        int headerEnd = data.IndexOf("\r\n\r\n"u8);
        if (headerEnd < 0)
        {
            if (data.Length > MaxHeaderBytes) throw new InvalidDataException("HTTP header limit exceeded.");
            return null;
        }
        if (headerEnd > MaxHeaderBytes) throw new InvalidDataException("HTTP header limit exceeded.");
        var lines = Encoding.Latin1.GetString(data[..headerEnd]).Split("\r\n");
        var first = lines[0].Split(' ', 3);
        if (first.Length < 3) throw new InvalidDataException("Invalid HTTP start line.");
        bool response = first[0].StartsWith("HTTP/1.", StringComparison.Ordinal);
        int? status = null;
        if (response)
        {
            if (first[0] is not ("HTTP/1.0" or "HTTP/1.1")) throw new InvalidDataException("Unsupported HTTP response version.");
            if (!int.TryParse(first[1], NumberStyles.None, CultureInfo.InvariantCulture, out int code) || code is < 100 or > 599) throw new InvalidDataException("Invalid HTTP status.");
            status = code;
        }
        else if (!Methods.Contains(first[0]) || first[2] is not ("HTTP/1.0" or "HTTP/1.1")) throw new InvalidDataException("Unsupported HTTP request line.");
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in lines.Skip(1))
        {
            int colon = line.IndexOf(':');
            if (colon <= 0 || line[..colon].Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-' && c != '_')) throw new InvalidDataException("Invalid HTTP header.");
            var name = line[..colon]; var value = line[(colon + 1)..].Trim();
            if (value.Any(c => (c < 32 && c != '\t') || c == 127)) throw new InvalidDataException("Invalid control character in HTTP header.");
            if (headers.ContainsKey(name))
            {
                if (name.Equals("content-length", StringComparison.OrdinalIgnoreCase) || name.Equals("transfer-encoding", StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Ambiguous HTTP framing headers.");
                headers[name] += ", " + value;
            }
            else headers[name] = value;
        }
        int start = headerEnd + 4, consumed;
        byte[] body;
        bool noBody = response && (responseToHead || status is >= 100 and < 200 or 204 or 304);
        if (headers.ContainsKey("transfer-encoding") && headers.ContainsKey("content-length")) throw new InvalidDataException("Conflicting HTTP message framing.");
        if (noBody) { body = []; consumed = start; }
        else if (headers.TryGetValue("transfer-encoding", out var transfer))
        {
            if (!transfer.Equals("chunked", StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Unsupported HTTP transfer coding.");
            var result = ReadChunks(data[start..], maxMessageBytes);
            if (result == null) return null;
            body = result.Value.Body; consumed = start + result.Value.Consumed;
        }
        else if (headers.TryGetValue("content-length", out var rawLength))
        {
            if (!int.TryParse(rawLength, NumberStyles.None, CultureInfo.InvariantCulture, out int length) || length < 0 || length > maxMessageBytes) throw new InvalidDataException("HTTP body limit exceeded or invalid content length.");
            if (data.Length - start < length) return null;
            body = data.Slice(start, length).ToArray(); consumed = start + length;
        }
        else if (response)
        {
            if (!endOfStream) return null;
            if (data.Length - start > maxMessageBytes) throw new InvalidDataException("HTTP body limit exceeded.");
            body = data[start..].ToArray(); consumed = data.Length;
        }
        else { body = []; consumed = start; }
        return new(response ? "" : first[0], response ? "" : first[1], status, headers, body, consumed, response ? first[0] : first[2]);
    }

    private static (byte[] Body, int Consumed)? ReadChunks(ReadOnlySpan<byte> data, int maxBytes)
    {
        int p = 0; using var output = new MemoryStream();
        for (int chunks = 0; chunks < 16384; chunks++)
        {
            int end = data[p..].IndexOf("\r\n"u8);
            if (end < 0) { if (data.Length - p > 1024) throw new InvalidDataException("Invalid HTTP chunk size."); return null; }
            if (end > 1024) throw new InvalidDataException("HTTP chunk extension limit exceeded.");
            var sizeText = Encoding.ASCII.GetString(data.Slice(p, end)).Split(';')[0];
            if (!int.TryParse(sizeText, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out int size) || size < 0 || size > maxBytes - output.Length) throw new InvalidDataException("Invalid HTTP chunk length.");
            p += end + 2;
            if (size == 0)
            {
                if (data.Length - p >= 2 && data.Slice(p, 2).SequenceEqual("\r\n"u8)) return (output.ToArray(), p + 2);
                int trailerEnd = data[p..].IndexOf("\r\n\r\n"u8);
                if (trailerEnd < 0) { if (data.Length - p > MaxHeaderBytes) throw new InvalidDataException("HTTP trailer limit exceeded."); return null; }
                return (output.ToArray(), p + trailerEnd + 4);
            }
            if (data.Length - p < size + 2) return null;
            if (!data.Slice(p + size, 2).SequenceEqual("\r\n"u8)) throw new InvalidDataException("Invalid HTTP chunk terminator.");
            output.Write(data.Slice(p, size)); p += size + 2;
        }
        throw new InvalidDataException("HTTP chunk count limit exceeded.");
    }

    public static string? BodyPreview(byte[] data, Dictionary<string, string> headers, bool retain, int max)
    {
        if (!retain || data.Length == 0) return null;
        if (headers.TryGetValue("content-encoding", out var coding) && !coding.Equals("identity", StringComparison.OrdinalIgnoreCase)) return "[encoded payload; retrieve raw evidence]";
        bool textual = headers.TryGetValue("content-type", out var type) && (type.StartsWith("text/", StringComparison.OrdinalIgnoreCase) || type.Contains("json", StringComparison.OrdinalIgnoreCase) || type.Contains("xml", StringComparison.OrdinalIgnoreCase) || type.Contains("javascript", StringComparison.OrdinalIgnoreCase));
        return textual ? Encoding.UTF8.GetString(data.AsSpan(0, Math.Min(max, data.Length))) : "[binary payload; retrieve raw evidence]";
    }
}
