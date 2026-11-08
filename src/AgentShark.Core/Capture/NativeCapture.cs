using System.Threading.Channels;
using SharpPcap;
using SharpPcap.LibPcap;

namespace AgentShark.Core.Capture;

public sealed class NativeCapture : IDisposable
{
    private readonly LibPcapLiveDevice _device;
    private readonly Channel<CapturedPacket> _packets = Channel.CreateBounded<CapturedPacket>(new BoundedChannelOptions(1024) { SingleReader = true, SingleWriter = true, FullMode = BoundedChannelFullMode.Wait });
    private long _dropped;
    public long Dropped
    {
        get
        {
            try { return Interlocked.Read(ref _dropped) + _device.Statistics.DroppedPackets; }
            catch (PcapException) { return Interlocked.Read(ref _dropped); }
        }
    }

    public static IReadOnlyList<CaptureInterface> Interfaces() => LibPcapLiveDeviceList.Instance.Select(d => new CaptureInterface(d.Name, d.Description ?? d.Name)).ToArray();

    public NativeCapture(string interfaceId, string? filter)
    {
        _device = LibPcapLiveDeviceList.New().FirstOrDefault(d => d.Name == interfaceId) ?? throw new ArgumentException("Capture interface not found. Use get_capabilities to list interfaces.");
        try
        {
            _device.Open(new DeviceConfiguration { Mode = DeviceModes.None, ReadTimeout = 100, Snaplen = 65535 });
            if (!string.IsNullOrWhiteSpace(filter)) _device.Filter = filter;
            _device.OnPacketArrival += OnPacket;
            _device.StartCapture();
        }
        catch { _device.Dispose(); throw; }
    }

    private void OnPacket(object sender, PacketCapture capture)
    {
        var raw = capture.GetPacket();
        var packet = new CapturedPacket(new DateTimeOffset(DateTime.SpecifyKind(raw.Timeval.Date, DateTimeKind.Utc)), (int)raw.LinkLayerType, raw.Data, raw.PacketLength);
        if (!_packets.Writer.TryWrite(packet)) Interlocked.Increment(ref _dropped);
    }

    public IAsyncEnumerable<CapturedPacket> ReadAsync(CancellationToken ct) => _packets.Reader.ReadAllAsync(ct);

    public void Dispose()
    {
        _device.StopCapture();
        _device.OnPacketArrival -= OnPacket;
        _device.Dispose();
        _packets.Writer.TryComplete();
    }
}
