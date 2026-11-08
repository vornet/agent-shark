namespace AgentShark.Core.Protocols;

/// <summary>Per-direction sequence tracking with bounded out-of-order buffering and overlap detection.</summary>
public sealed class TcpReassembler(int maxBytes)
{
    private uint? _next;
    private readonly List<(uint Sequence, byte[] Bytes)> _pending = [];
    private int _pendingBytes;
    private byte[] _history = [];
    private int _historyCount;
    private int _historyWrite;
    private uint _historyStart;
    public bool HasGap => _pending.Count != 0;

    public void Start(uint sequence) => _next ??= sequence;

    public byte[] Push(uint sequence, ReadOnlySpan<byte> data, out string? anomaly)
    {
        anomaly = null;
        _next ??= sequence;
        if (data.Length == 0) return [];
        if (_historyCount > 0)
        {
            int historyFirst = (_historyWrite - _historyCount + _history.Length) % _history.Length;
            int firstLength = Math.Min(_historyCount, _history.Length - historyFirst);
            ValidateOverlap(sequence, data, _historyStart, _history.AsSpan(historyFirst, firstLength));
            ValidateOverlap(sequence, data, _historyStart + (uint)firstLength, _history.AsSpan(0, _historyCount - firstLength));
        }
        foreach (var held in _pending) ValidateOverlap(sequence, data, held.Sequence, held.Bytes);
        int delta = unchecked((int)(sequence - _next.Value));
        if (delta < 0)
        {
            int overlap = (int)Math.Min(-(long)delta, data.Length);
            anomaly = "tcp_retransmission_or_overlap";
            data = data[overlap..]; sequence += (uint)overlap;
            if (data.Length == 0) return [];
        }
        if (unchecked((int)(sequence - _next.Value)) > 0)
        {
            int existingIndex = _pending.FindIndex(p => p.Sequence == sequence);
            if (existingIndex >= 0)
            {
                var existing = _pending[existingIndex];
                if (existing.Bytes.Length >= data.Length) { anomaly = "tcp_duplicate_segment"; return []; }
                _pending.RemoveAt(existingIndex); _pendingBytes -= existing.Bytes.Length;
            }
            if (_pending.Count >= 256 || _pendingBytes + data.Length > maxBytes) throw new InvalidDataException("TCP out-of-order buffer limit exceeded.");
            _pending.Add((sequence, data.ToArray())); _pendingBytes += data.Length;
            anomaly = "tcp_out_of_order"; return [];
        }
        using var output = new MemoryStream();
        output.Write(data); _next += (uint)data.Length;
        while (true)
        {
            int index = _pending.FindIndex(p => unchecked((int)(p.Sequence - _next.Value)) <= 0);
            if (index < 0) break;
            var item = _pending[index]; _pending.RemoveAt(index); _pendingBytes -= item.Bytes.Length;
            int skip = (int)Math.Min(unchecked((uint)(_next.Value - item.Sequence)), (uint)item.Bytes.Length);
            var tail = item.Bytes.AsSpan(skip);
            if (output.Length + tail.Length > maxBytes) throw new InvalidDataException("TCP contiguous buffer limit exceeded.");
            output.Write(tail); _next += (uint)tail.Length;
        }
        byte[] result = output.ToArray();
        int desired = Math.Min(Math.Min(maxBytes, 65536), _historyCount + result.Length);
        if (_history.Length < desired)
        {
            int capacity = Math.Min(Math.Min(maxBytes, 65536), Math.Max(desired, Math.Max(1024, _history.Length * 2)));
            var history = new byte[capacity];
            if (_historyCount > 0)
            {
                int first = (_historyWrite - _historyCount + _history.Length) % _history.Length;
                int n = Math.Min(_historyCount, _history.Length - first);
                _history.AsSpan(first, n).CopyTo(history);
                _history.AsSpan(0, _historyCount - n).CopyTo(history.AsSpan(n));
            }
            _history = history; _historyWrite = _historyCount;
        }
        if (result.Length >= _history.Length)
        {
            result.AsSpan(result.Length - _history.Length).CopyTo(_history); _historyWrite = 0; _historyCount = _history.Length;
        }
        else
        {
            int n = Math.Min(result.Length, _history.Length - _historyWrite);
            result.AsSpan(0, n).CopyTo(_history.AsSpan(_historyWrite));
            result.AsSpan(n).CopyTo(_history);
            _historyWrite = (_historyWrite + result.Length) % _history.Length;
            _historyCount = Math.Min(_history.Length, _historyCount + result.Length);
        }
        _historyStart = _next.Value - (uint)_historyCount;
        return result;
    }

    private static void ValidateOverlap(uint sequence, ReadOnlySpan<byte> data, uint otherSequence, ReadOnlySpan<byte> other)
    {
        long delta = unchecked((int)(sequence - otherSequence));
        long start = Math.Max(0, -delta), end = Math.Min(data.Length, other.Length - delta);
        if (end <= start) return;
        if (!data.Slice((int)start, (int)(end - start)).SequenceEqual(other.Slice((int)(start + delta), (int)(end - start))))
            throw new InvalidDataException("Conflicting TCP overlap; application decoding stopped rather than choosing ambiguous bytes.");
    }
}
