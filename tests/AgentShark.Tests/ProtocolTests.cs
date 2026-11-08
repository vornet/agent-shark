using AgentShark.Core.Protocols;

namespace AgentShark.Tests;

public sealed class ProtocolTests
{
    [Fact]
    public void ReordersSegmentsAndSuppressesRetransmittedBytes()
    {
        var tcp = new TcpReassembler(1024); tcp.Start(100);
        Assert.Empty(tcp.Push(105, "world"u8, out var anomaly)); Assert.Equal("tcp_out_of_order", anomaly);
        Assert.Equal("helloworld"u8.ToArray(), tcp.Push(100, "hello"u8, out _));
        Assert.Empty(tcp.Push(100, "hello"u8, out anomaly)); Assert.Equal("tcp_retransmission_or_overlap", anomaly);
        Assert.False(tcp.HasGap);
    }

    [Fact]
    public void HandlesSequenceNumberWraparound()
    {
        var tcp = new TcpReassembler(1024); tcp.Start(uint.MaxValue - 1);
        Assert.Equal("abc"u8.ToArray(), tcp.Push(uint.MaxValue - 1, "abc"u8, out _));
        Assert.Equal("def"u8.ToArray(), tcp.Push(1, "def"u8, out _));
    }

    [Fact]
    public void RejectsConflictingOverlapsRatherThanInventingAnExchange()
    {
        var tcp = new TcpReassembler(1024); tcp.Start(100);
        tcp.Push(100, "hello"u8, out _);
        Assert.Throws<InvalidDataException>(() => tcp.Push(102, "LLo"u8, out _));
        var pending = new TcpReassembler(1024); pending.Start(100);
        pending.Push(105, "world"u8, out _);
        Assert.Throws<InvalidDataException>(() => pending.Push(107, "XXX"u8, out _));
    }

    [Fact]
    public void ValidatesRetransmissionsAcrossHistoryRingWrap()
    {
        var tcp = new TcpReassembler(8); tcp.Start(100);
        tcp.Push(100, "abcdefgh"u8, out _); tcp.Push(108, "ijkl"u8, out _);
        Assert.Empty(tcp.Push(106, "ghijkl"u8, out _));
        Assert.Throws<InvalidDataException>(() => tcp.Push(106, "gXXXXX"u8, out _));
    }

    [Fact]
    public void EnforcesOutOfOrderMemoryBudget()
    {
        var tcp = new TcpReassembler(4); tcp.Start(1);
        Assert.Throws<InvalidDataException>(() => tcp.Push(2, "12345"u8, out _));
    }

    [Theory]
    [InlineData("POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\na")]
    [InlineData("POST / HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\na")]
    [InlineData("POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n")]
    [InlineData("POST / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n")]
    public void RejectsAmbiguousOrInvalidHttpFraming(string text) =>
        Assert.Throws<InvalidDataException>(() => Http1Decoder.TryRead(System.Text.Encoding.ASCII.GetBytes(text), 1024));

    [Fact]
    public void ParsesChunkedResponsesAndTrailers()
    {
        var result = Http1Decoder.TryRead("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\nX-Test: yes\r\n\r\n"u8, 1024);
        Assert.Equal("abcde"u8.ToArray(), result!.Body);
    }

    [Fact]
    public void WaitsForCompleteBody()
    {
        Assert.Null(Http1Decoder.TryRead("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nab"u8, 1024));
        var head = Http1Decoder.TryRead("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"u8, 1024, responseToHead: true);
        Assert.Empty(head!.Body);
    }

    [Fact]
    public void DnsCompressionCyclesAreBounded()
    {
        byte[] message = [0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1];
        Assert.Throws<InvalidDataException>(() => DnsDecoder.Decode(message));
    }

    [Fact]
    public void DecodesDnsQuestionAndResponseCode()
    {
        byte[] message = [0, 1, 0x81, 0x83, 0, 1, 0, 0, 0, 0, 0, 0, 3, (byte)'a', (byte)'p', (byte)'p', 4, (byte)'t', (byte)'e', (byte)'s', (byte)'t', 0, 0, 1, 0, 1];
        var result = DnsDecoder.Decode(message);
        Assert.Equal("app.test", result["question0"]); Assert.Equal("3", result["responseCode"]);
    }

    [Fact]
    public void DecodesCompressedDnsAnswers()
    {
        byte[] message = [0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 3, (byte)'a', (byte)'p', (byte)'p', 4, (byte)'t', (byte)'e', (byte)'s', (byte)'t', 0, 0, 1, 0, 1,
            0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1];
        var fields = DnsDecoder.Decode(message);
        Assert.Equal("192.0.2.1", fields["answer0.value"]); Assert.Equal("60", fields["answer0.ttl"]);
    }

    [Fact]
    public void DecodesTlsServerNameWithoutClaimingDecryption()
    {
        byte[] name = System.Text.Encoding.ASCII.GetBytes("app.test");
        byte[] extension = [0, 0, 0, (byte)(name.Length + 5), 0, (byte)(name.Length + 3), 0, 0, (byte)name.Length, .. name];
        byte[] hello = [3, 3, .. new byte[32], 0, 0, 2, 0x13, 1, 1, 0, 0, (byte)extension.Length, .. extension];
        byte[] record = [22, 3, 3, 0, (byte)(hello.Length + 4), 1, 0, 0, (byte)hello.Length, .. hello];
        var result = TlsDecoder.ClientHello(record)!;
        Assert.Equal("app.test", result["serverName"]); Assert.Equal("unavailable", result["decryption"]);
    }

    [Fact]
    public void MalformedTlsAndHttpInputsDoNotEscapeBoundsChecks()
    {
        var random = new Random(45);
        for (int i = 0; i < 3000; i++)
        {
            var bytes = new byte[random.Next(8, 512)]; random.NextBytes(bytes);
            bytes[0] = 22; bytes[1] = 3;
            try { TlsDecoder.ClientHello(bytes); } catch (InvalidDataException) { }
            try { Http1Decoder.TryRead(bytes, 1024); } catch (InvalidDataException) { }
        }
    }
}
