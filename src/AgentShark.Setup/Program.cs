using System.Text.Json;
using AgentShark.Setup;

try
{
    string command = args.Length == 0 ? "detect" : args[0];
    var values = new Dictionary<string, string>(StringComparer.Ordinal);
    bool dryRun = false;
    for (int i = 1; i < args.Length; i++)
    {
        if (args[i] == "--dry-run") { dryRun = true; continue; }
        if (args[i] is not ("--home" or "--server" or "--clients") || i + 1 >= args.Length) throw new ArgumentException("Unknown or incomplete setup option.");
        string key = args[i++];
        if (!values.TryAdd(key, args[i])) throw new ArgumentException("Duplicate setup option.");
    }
    var paths = SetupPaths.Current(values.GetValueOrDefault("--home"));
    var integration = new ClientIntegrator(paths);
    object result;
    int exit = 0;
    if (command == "detect") result = paths.Profiles();
    else if (command is "integrate" or "remove")
    {
        string server = values.GetValueOrDefault("--server") ?? Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "server", OperatingSystem.IsWindows() ? "AgentShark.Server.exe" : "AgentShark.Server"));
        var results = command == "integrate" ? integration.Integrate(server, values.GetValueOrDefault("--clients") ?? "detected", dryRun) : integration.Remove(values.GetValueOrDefault("--clients") ?? "all", dryRun);
        result = results;
        exit = results.Any(r => r.Status is "error" or "conflict") ? 1 : 0;
        if (!dryRun) File.WriteAllText(Path.Combine(paths.StateDirectory, "last-report.json"), JsonSerializer.Serialize(results, new JsonSerializerOptions(JsonSerializerDefaults.Web) { WriteIndented = true }));
    }
    else throw new ArgumentException("Use detect, integrate or remove. Options: --clients detected|all|client IDs, --server absolute-path, --home profile-home, --dry-run.");
    Console.WriteLine(JsonSerializer.Serialize(result, new JsonSerializerOptions(JsonSerializerDefaults.Web) { WriteIndented = true }));
    return exit;
}
catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or JsonException or Tomlyn.TomlException)
{
    Console.Error.WriteLine(JsonSerializer.Serialize(new { error = ex.GetType().Name, message = "Setup could not complete. Check paths, permissions, client configuration and options. No unrelated settings are intentionally changed." }));
    return 1;
}
