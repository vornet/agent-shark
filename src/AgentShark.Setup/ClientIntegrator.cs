using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace AgentShark.Setup;

public sealed record Registration(string Client, string Path, string Fingerprint, string ServerPath, string? Backup);
public sealed record IntegrationResult(string Client, string ConfigPath, string Status, string Message, string? Backup = null);

public sealed class ClientIntegrator(SetupPaths paths)
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    private readonly string _journalPath = Path.Combine(paths.StateDirectory, "registrations.json");

    public IReadOnlyList<IntegrationResult> Integrate(string serverPath, string selection = "detected", bool dryRun = false)
    {
        serverPath = Path.GetFullPath(serverPath);
        if (!File.Exists(serverPath)) throw new FileNotFoundException("AgentShark server executable not found.", serverPath);
        return Apply(selection, serverPath, remove: false, dryRun);
    }

    public IReadOnlyList<IntegrationResult> Remove(string selection = "all", bool dryRun = false) => Apply(selection, null, remove: true, dryRun);

    private IReadOnlyList<IntegrationResult> Apply(string selection, string? serverPath, bool remove, bool dryRun)
    {
        var profiles = paths.Profiles();
        var requested = selection.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (requested.Count == 0 || requested.Any(id => id is not ("all" or "detected") && !profiles.Any(p => p.Id.Equals(id, StringComparison.OrdinalIgnoreCase))))
            throw new ArgumentException("Unknown client selection. Use detected, all, or supported client IDs.");
        CreatePrivateDirectory(paths.StateDirectory);
        // Serializes setup invocations for this user's profile without touching client processes.
        using var lease = new FileStream(Path.Combine(paths.StateDirectory, "integration.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        var journal = File.Exists(_journalPath) ? JsonSerializer.Deserialize<Dictionary<string, Registration>>(Read(_journalPath), Json)! ?? [] : new Dictionary<string, Registration>();
        var results = new List<IntegrationResult>();
        foreach (var profile in profiles)
        {
            bool selected = requested.Contains("all") || requested.Contains(profile.Id) || (requested.Contains("detected") && profile.Detected);
            if (!selected) { results.Add(new(profile.Id, profile.ConfigPath, "skipped", "No detected profile, or client not selected.")); continue; }
            try
            {
                RejectLinks(profile.ConfigPath);
                bool existed = File.Exists(profile.ConfigPath);
                string original = existed ? Read(profile.ConfigPath) : profile.Format == "toml" ? "" : "{}\n";
                string container = profile.Format == "vscode" ? "servers" : "mcpServers";
                string? current = profile.Format == "toml" ? TomlConfigEditor.Entry(original) : JsonConfigEditor.Entry(original, container, "agent-shark");
                journal.TryGetValue(profile.Id, out var registration);
                if (current != null && (registration == null || registration.Path != profile.ConfigPath || registration.Fingerprint != Fingerprint(current, profile.Format)))
                {
                    results.Add(new(profile.Id, profile.ConfigPath, "conflict", "Existing entry is unmanaged or was modified after setup; left unchanged.")); continue;
                }
                if (remove && current == null)
                {
                    if (!dryRun && journal.Remove(profile.Id)) WriteJournal(journal);
                    results.Add(new(profile.Id, profile.ConfigPath, "unchanged", "No AgentShark entry to remove.")); continue;
                }
                string data = Path.Combine(paths.Local, "AgentShark", "clients", profile.Id);
                string? entry = remove ? null : profile.Format == "toml" ? TomlConfigEditor.Block(serverPath!, data) :
                    new JsonObject
                    {
                        ["command"] = serverPath,
                        ["args"] = new JsonArray(),
                        ["env"] = new JsonObject { ["AGENTSHARK_DATA_DIRECTORY"] = data },
                        ["type"] = profile.Format == "vscode" ? "stdio" : null
                    }.ToJsonString(Json);
                // Most clients accept only their documented fields; omit VS Code's type elsewhere.
                if (!remove && profile.Format is "json")
                {
                    var node = JsonNode.Parse(entry!)!.AsObject(); node.Remove("type"); entry = node.ToJsonString(Json);
                }
                if (current != null && entry != null && Fingerprint(current, profile.Format) == Fingerprint(entry, profile.Format))
                { results.Add(new(profile.Id, profile.ConfigPath, "unchanged", "Already registered with this executable.")); continue; }
                string updated = profile.Format == "toml" ? TomlConfigEditor.Set(original, entry) : JsonConfigEditor.Set(original, container, "agent-shark", entry);
                if (dryRun) { results.Add(new(profile.Id, profile.ConfigPath, "planned", remove ? "Would remove the managed entry." : "Would register AgentShark; no client configuration changed.")); continue; }
                string? backup = null;
                if (existed)
                {
                    string backupDirectory = Path.Combine(paths.StateDirectory, "backups"); CreatePrivateDirectory(backupDirectory);
                    backup = Path.Combine(backupDirectory, $"{profile.Id}-{DateTimeOffset.UtcNow:yyyyMMddTHHmmssfff}-{Guid.NewGuid():N}.bak");
                    AtomicWrite(backup, original);
                }
                // Refuse concurrent client/editor changes detected since the initial read.
                if (File.Exists(profile.ConfigPath) != existed || (existed && Read(profile.ConfigPath) != original))
                    throw new IOException("Configuration changed during setup; retry after closing the client.");
                AtomicWrite(profile.ConfigPath, updated);
                if (remove) journal.Remove(profile.Id);
                else journal[profile.Id] = new(profile.Id, profile.ConfigPath, Fingerprint(entry!, profile.Format), serverPath!, backup);
                try { WriteJournal(journal); }
                catch
                {
                    // Roll back our edit if bookkeeping cannot be persisted, but never overwrite a newer edit.
                    if (Read(profile.ConfigPath) == updated)
                    {
                        if (existed) AtomicWrite(profile.ConfigPath, original); else File.Delete(profile.ConfigPath);
                    }
                    throw;
                }
                results.Add(new(profile.Id, profile.ConfigPath, remove ? "removed" : "registered", "Restart the client; its normal trust/approval prompts still apply.", backup));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidDataException or Tomlyn.TomlException)
            {
                results.Add(new(profile.Id, profile.ConfigPath, "error", "Configuration was not integrated: " + ex.GetType().Name + ". Resolve invalid/locked configuration and retry."));
            }
        }
        return results;
    }

    private void WriteJournal(Dictionary<string, Registration> journal) => AtomicWrite(_journalPath, JsonSerializer.Serialize(journal, Json) + "\n");

    private static string Fingerprint(string entry, string format)
    {
        if (format != "toml") entry = JsonNode.Parse(entry, documentOptions: new() { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip })!.ToJsonString();
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(entry.Replace("\r\n", "\n", StringComparison.Ordinal))));
    }

    private static string Read(string path)
    {
        if (new FileInfo(path).Length > 16 * 1024 * 1024) throw new InvalidDataException("Configuration exceeds setup's size limit.");
        return File.ReadAllText(path, new UTF8Encoding(false, true));
    }

    private static void RejectLinks(string path)
    {
        for (FileSystemInfo? item = new FileInfo(path); item != null; item = item is FileInfo file ? file.Directory : ((DirectoryInfo)item).Parent)
            if (item.Exists && (item.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Setup does not edit symbolic-link or reparse-point configuration paths.");
    }

    private static void CreatePrivateDirectory(string path)
    {
        if (OperatingSystem.IsWindows()) Directory.CreateDirectory(path);
        else Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }

    private static void AtomicWrite(string path, string text)
    {
        CreatePrivateDirectory(Path.GetDirectoryName(path)!);
        string temporary = path + ".agent-shark-" + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(temporary, File.Exists(path) ? File.GetUnixFileMode(path) : UnixFileMode.UserRead | UnixFileMode.UserWrite);
                stream.Write(Encoding.UTF8.GetBytes(text)); stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, path, overwrite: true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}
