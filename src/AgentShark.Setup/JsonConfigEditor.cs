using System.Text;
using System.Text.Json;

namespace AgentShark.Setup;

/// <summary>Edits only the selected JSON value and separators, retaining unrelated JSONC text.</summary>
public static class JsonConfigEditor
{
    private sealed record Property(string Name, int Start, Node Value);
    private sealed record Node(int Start, int End, int Close, List<Property>? Properties);
    private static readonly JsonReaderOptions ReaderOptions = new() { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip, MaxDepth = 128 };

    public static string? Entry(string text, string container, string key)
    {
        var bytes = Encoding.UTF8.GetBytes(text); var root = Parse(bytes);
        var parent = root.Properties!.FirstOrDefault(p => p.Name == container)?.Value;
        if (parent == null) return null;
        if (parent.Properties == null) throw new InvalidDataException("MCP configuration container must be an object.");
        var value = parent.Properties.FirstOrDefault(p => p.Name == key)?.Value;
        return value == null ? null : Encoding.UTF8.GetString(bytes.AsSpan(value.Start, value.End - value.Start));
    }

    public static string Set(string text, string container, string key, string? value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(text); var root = Parse(bytes);
        var parent = root.Properties!.FirstOrDefault(p => p.Name == container)?.Value;
        var edits = new List<(int Start, int End, string Value)>();
        if (parent == null)
        {
            if (value == null) return text;
            Add(root, container, "{\n    " + JsonSerializer.Serialize(key) + ": " + value + "\n  }", bytes, edits);
        }
        else
        {
            if (parent.Properties == null) throw new InvalidDataException("MCP configuration container must be an object.");
            var property = parent.Properties.FirstOrDefault(p => p.Name == key);
            if (property == null)
            {
                if (value == null) return text;
                Add(parent, key, value, bytes, edits);
            }
            else if (value != null) edits.Add((property.Value.Start, property.Value.End, value));
            else
            {
                edits.Add((property.Start, property.Value.End, ""));
                int comma = Separator(bytes, property.Value.End, parent.Close);
                if (comma >= 0) edits.Add((comma, comma + 1, ""));
                else
                {
                    int index = parent.Properties.IndexOf(property);
                    if (index > 0)
                    {
                        comma = Separator(bytes, parent.Properties[index - 1].Value.End, property.Start);
                        if (comma >= 0) edits.Add((comma, comma + 1, ""));
                    }
                }
            }
        }
        using var output = new MemoryStream(); int offset = 0;
        foreach (var edit in edits.OrderBy(e => e.Start))
        {
            output.Write(bytes.AsSpan(offset, edit.Start - offset)); output.Write(Encoding.UTF8.GetBytes(edit.Value)); offset = edit.End;
        }
        output.Write(bytes.AsSpan(offset));
        var result = Encoding.UTF8.GetString(output.ToArray()); _ = Parse(Encoding.UTF8.GetBytes(result)); return result;
    }

    private static void Add(Node node, string key, string value, byte[] bytes, List<(int Start, int End, string Value)> edits)
    {
        if (node.Properties!.Count > 0)
        {
            var last = node.Properties[^1];
            if (Separator(bytes, last.Value.End, node.Close) < 0) edits.Add((last.Value.End, last.Value.End, ","));
        }
        edits.Add((node.Close, node.Close, "\n  " + JsonSerializer.Serialize(key) + ": " + value + "\n"));
    }

    private static int Separator(byte[] bytes, int start, int end)
    {
        for (int i = start; i < end; i++)
        {
            if (bytes[i] == ',') return i;
            if (bytes[i] == '/' && i + 1 < end && bytes[i + 1] == '/') { while (i < end && bytes[i] != '\n') i++; }
            else if (bytes[i] == '/' && i + 1 < end && bytes[i + 1] == '*')
            { i += 2; while (i + 1 < end && !(bytes[i] == '*' && bytes[i + 1] == '/')) i++; i++; }
        }
        return -1;
    }

    private static Node Parse(byte[] bytes)
    {
        var reader = new Utf8JsonReader(bytes, ReaderOptions);
        if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject) throw new InvalidDataException("Client configuration must be a JSON object.");
        var result = ReadNode(ref reader);
        if (reader.Read()) throw new InvalidDataException("Unexpected JSON after configuration object.");
        return result;
    }

    private static Node ReadNode(ref Utf8JsonReader reader)
    {
        int start = checked((int)reader.TokenStartIndex);
        if (reader.TokenType != JsonTokenType.StartObject)
        { reader.Skip(); return new(start, checked((int)reader.BytesConsumed), 0, null); }
        var properties = new List<Property>(); var names = new HashSet<string>(StringComparer.Ordinal);
        while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            if (reader.TokenType != JsonTokenType.PropertyName) throw new InvalidDataException("Invalid JSON property.");
            string name = reader.GetString()!; int propertyStart = checked((int)reader.TokenStartIndex);
            if (!names.Add(name)) throw new InvalidDataException("Duplicate JSON properties must be resolved before integration.");
            if (!reader.Read()) throw new InvalidDataException("Missing JSON property value.");
            properties.Add(new(name, propertyStart, ReadNode(ref reader)));
        }
        if (reader.TokenType != JsonTokenType.EndObject) throw new InvalidDataException("Unterminated JSON object.");
        return new(start, checked((int)reader.BytesConsumed), checked((int)reader.TokenStartIndex), properties);
    }
}
