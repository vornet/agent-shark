namespace AgentShark.Core.Proxy;

/// <summary>Preserves read-ahead bytes when switching a CONNECT stream to TLS.</summary>
internal sealed class ReplayStream(Stream inner) : Stream
{
    private ReadOnlyMemory<byte> _prefix;
    public void Prepend(ReadOnlyMemory<byte> bytes) => _prefix = _prefix.IsEmpty ? bytes : bytes.ToArray().Concat(_prefix.ToArray()).ToArray();
    public override bool CanRead => inner.CanRead;
    public override bool CanSeek => false;
    public override bool CanWrite => inner.CanWrite;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() => inner.Flush();
    public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);
    public override int Read(byte[] buffer, int offset, int count)
    {
        if (_prefix.IsEmpty) return inner.Read(buffer, offset, count);
        int n = Math.Min(count, _prefix.Length); _prefix.Span[..n].CopyTo(buffer.AsSpan(offset)); _prefix = _prefix[n..]; return n;
    }
    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (_prefix.IsEmpty) return inner.ReadAsync(buffer, cancellationToken);
        int n = Math.Min(buffer.Length, _prefix.Length); _prefix.Span[..n].CopyTo(buffer.Span); _prefix = _prefix[n..]; return ValueTask.FromResult(n);
    }
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    public override void Write(byte[] buffer, int offset, int count) => inner.Write(buffer, offset, count);
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) => inner.WriteAsync(buffer, cancellationToken);
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) => inner.WriteAsync(buffer, offset, count, cancellationToken);
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    protected override void Dispose(bool disposing) { if (disposing) inner.Dispose(); base.Dispose(disposing); }
}
