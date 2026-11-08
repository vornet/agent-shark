namespace AgentShark.Core;

public static class Privacy
{
    private static readonly HashSet<string> SafeHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "host", "content-type", "content-length", "content-encoding", "transfer-encoding",
        "accept", "accept-encoding", "connection", "user-agent", "server", "retry-after",
        "grpc-status", "grpc-message", "traceparent"
    };

    public static Dictionary<string, string> Headers(IEnumerable<KeyValuePair<string, string>> headers) =>
        headers.ToDictionary(kv => kv.Key.ToLowerInvariant(), kv => SafeHeaders.Contains(kv.Key) ? Clip(kv.Value, 1024) : "[redacted]", StringComparer.OrdinalIgnoreCase);

    public static string Target(string target)
    {
        // Queries, fragments and userinfo routinely contain credentials; retain only routing context.
        if (Uri.TryCreate(target, UriKind.Absolute, out var uri) && (uri.Scheme == "http" || uri.Scheme == "https"))
            return new UriBuilder(uri) { UserName = "", Password = "", Query = "", Fragment = "" }.Uri.GetLeftPart(UriPartial.Path);
        if (target.Contains("://", StringComparison.Ordinal)) return "[invalid target]";
        var end = target.IndexOfAny(['?', '#']);
        return Clip(end < 0 ? target : target[..end], 2048);
    }

    public static string Clip(string value, int max) => value.Length <= max ? value : value[..max];
}
