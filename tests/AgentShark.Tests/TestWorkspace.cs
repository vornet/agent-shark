using AgentShark.Core;

namespace AgentShark.Tests;

public sealed class TestWorkspace : IAsyncDisposable
{
    public string DirectoryPath { get; } = Path.Combine(Path.GetTempPath(), "agent-shark-tests", Guid.NewGuid().ToString("N"));
    public EngineOptions Options { get; }
    public EvidenceStore Store { get; }
    public ObservationEngine Engine { get; }

    public TestWorkspace(Func<EngineOptions, EngineOptions>? configure = null)
    {
        Directory.CreateDirectory(DirectoryPath);
        Options = configure?.Invoke(new() { DataDirectory = DirectoryPath, ImportRoots = [DirectoryPath] }) ?? new() { DataDirectory = DirectoryPath, ImportRoots = [DirectoryPath] };
        Store = new(Options); Engine = new(Options, Store);
    }

    public async Task<ObservationInfo> Wait(string id)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        while (Engine.Status(id).State == ObservationState.Running) await Task.Delay(10, timeout.Token);
        return Engine.Status(id);
    }

    public async ValueTask DisposeAsync()
    {
        await Engine.DisposeAsync(); Store.Dispose();
        Directory.Delete(DirectoryPath, recursive: true);
    }
}
