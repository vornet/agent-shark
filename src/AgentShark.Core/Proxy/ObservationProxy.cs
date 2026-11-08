using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using AgentShark.Core.Protocols;

namespace AgentShark.Core.Proxy;

/// <summary>Authenticated loopback HTTP/1 forward proxy with optional explicit TLS interception.</summary>
public sealed class ObservationProxy : IAsyncDisposable
{
    private static readonly HashSet<string> HopHeaders = new(StringComparer.OrdinalIgnoreCase)
    { "connection", "proxy-connection", "proxy-authorization", "proxy-authenticate", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade", "host", "content-length", "expect" };
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly HttpClient _http;
    private readonly string _observation;
    private readonly ObservationRequest _request;
    private readonly EngineOptions _options;
    private readonly EvidenceStore _store;
    private readonly Func<int, bool> _account;
    private readonly Func<bool> _accountRequest;
    private readonly CancellationTokenSource _stopped = new();
    private readonly ConcurrentDictionary<long, Task> _clients = [];
    private readonly SemaphoreSlim _slots = new(16, 16);
    private readonly SessionCertificateAuthority? _ca;
    private long _clientId;
    private readonly byte[] _credentials;
    private readonly X509Certificate2? _upstreamCa;

    public ObservationProxy(string observation, ObservationRequest request, EngineOptions options, EvidenceStore store, Func<int, bool> account, Func<bool> accountRequest)
    {
        _observation = observation; _request = request; _options = options; _store = store; _account = account; _accountRequest = accountRequest;
        string password = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
        _credentials = Encoding.ASCII.GetBytes(Convert.ToBase64String(Encoding.UTF8.GetBytes("agent:" + password)));
        if (request.InterceptTls) _ca = new();
        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            UseCookies = false,
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = TimeSpan.FromSeconds(10),
            MaxConnectionsPerServer = 16,
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            MaxResponseHeadersLength = 32
        };
        if (options.UpstreamCaPem != null)
        {
            _upstreamCa = X509Certificate2.CreateFromPem(options.UpstreamCaPem);
            handler.SslOptions.CertificateChainPolicy = new X509ChainPolicy
            {
                TrustMode = X509ChainTrustMode.CustomRootTrust,
                RevocationMode = X509RevocationMode.NoCheck,
                DisableCertificateDownloads = true,
                CustomTrustStore = { _upstreamCa }
            };
        }
        _http = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
        _listener.Start(32);
        Connection = new($"http://127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}", "agent", password, _ca?.CertificatePem);
    }

    public ProxyConnectionInfo Connection { get; }

    public async Task RunAsync(CancellationToken ct)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, _stopped.Token);
        try
        {
            while (!linked.IsCancellationRequested)
            {
                await _slots.WaitAsync(linked.Token);
                TcpClient client;
                try { client = await _listener.AcceptTcpClientAsync(linked.Token); }
                catch { _slots.Release(); throw; }
                long id = Interlocked.Increment(ref _clientId);
                var task = HandleClient(client, linked.Token);
                _clients[id] = task;
                _ = task.ContinueWith(completed => { _clients.TryRemove(id, out _); _slots.Release(); }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            }
        }
        catch (OperationCanceledException) when (linked.IsCancellationRequested) { }
        finally
        {
            await linked.CancelAsync();
            _listener.Stop();
            await Task.WhenAll(_clients.Values);
        }
    }

    private async Task HandleClient(TcpClient client, CancellationToken lifetime)
    {
        using (client)
        using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(lifetime))
        {
            timeout.CancelAfter(TimeSpan.FromSeconds(30));
            var ct = timeout.Token;
            string connectionId = "proxy_" + Guid.NewGuid().ToString("N");
            Stream stream = new ReplayStream(client.GetStream());
            SslStream? secure = null;
            bool responseStarted = false;
            var started = DateTimeOffset.UtcNow;
            try
            {
                var request = await ReadRequest(stream, ct);
                if (!Authorized(request)) { await Error(stream, 407, "Proxy Authentication Required", ct, true); return; }
                if (request.Method == "CONNECT")
                {
                    if (!Uri.TryCreate("https://" + request.Target, UriKind.Absolute, out var target) || target.AbsolutePath != "/" || target.Query.Length != 0 || target.UserInfo.Length != 0 || !Allowed(target.Host))
                    { await Error(stream, 403, "Host Not Allowed", ct); return; }
                    if (_ca == null)
                    {
                        await Tunnel(stream, target, connectionId, started, ct, () => responseStarted = true);
                        return;
                    }
                    await stream.WriteAsync("HTTP/1.1 200 Connection Established\r\n\r\n"u8.ToArray(), ct);
                    secure = new SslStream(stream, leaveInnerStreamOpen: true);
                    stream = secure;
                    await secure.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                    {
                        ServerCertificate = _ca.ForHost(target.Host),
                        EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                        ApplicationProtocols = [SslApplicationProtocol.Http11]
                    }, ct);
                    request = await ReadRequest(secure, ct);
                    if (request.Method == "CONNECT" || !request.Target.StartsWith('/')) throw new InvalidDataException("Invalid tunneled HTTP target.");
                    var uri = new UriBuilder("https", target.Host, target.Port) { Path = "/" }.Uri;
                    var resolved = new Uri(uri, request.Target);
                    if (!resolved.Host.Equals(target.Host, StringComparison.OrdinalIgnoreCase) || resolved.Port != target.Port) throw new InvalidDataException("Tunneled request changed authority.");
                    await Forward(secure, request, resolved, connectionId, started, ct, () => responseStarted = true);
                }
                else
                {
                    if (!Uri.TryCreate(request.Target, UriKind.Absolute, out var target) || target.Scheme != "http" || target.UserInfo.Length != 0 || !Allowed(target.Host))
                    { await Error(stream, 403, "Host Not Allowed", ct); return; }
                    await Forward(stream, request, target, connectionId, started, ct, () => responseStarted = true);
                }
            }
            catch (Exception ex) when (ex is IOException or SocketException or HttpRequestException or AuthenticationException or OperationCanceledException or InvalidDataException or ArgumentException)
            {
                string category = ex switch { AuthenticationException => "tls_handshake_failed", OperationCanceledException => lifetime.IsCancellationRequested ? "observation_stopped" : "proxy_timeout", InvalidDataException => "invalid_http", HttpRequestException => "upstream_request_failed", _ => "connection_failed" };
                _store.Put(_observation, new EvidenceRecord("error_" + connectionId, connectionId, DateTimeOffset.UtcNow, category, "warning", "Proxy operation did not complete.", new() { ["errorType"] = ex.GetType().Name, ["detail"] = ex is AuthenticationException ? Privacy.Clip(ex.Message, 512) : category }));
                try
                {
                    if (!responseStarted && !ct.IsCancellationRequested && (secure == null || secure.IsAuthenticated)) await Error(stream, 502, "Upstream Failure", ct);
                }
                catch (Exception writeError) when (writeError is IOException or ObjectDisposedException or InvalidOperationException) { }
            }
            finally { secure?.Dispose(); }
        }
    }

    private bool Allowed(string host) => _request.AllowedHosts.Contains(host, StringComparer.OrdinalIgnoreCase);
    private bool Authorized(HttpMessage request)
    {
        if (!request.Headers.TryGetValue("proxy-authorization", out var value) || !value.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase)) return false;
        var supplied = Encoding.ASCII.GetBytes(value[6..]);
        return CryptographicOperations.FixedTimeEquals(supplied, _credentials);
    }

    private async Task<HttpMessage> ReadRequest(Stream stream, CancellationToken ct)
    {
        using var data = new MemoryStream();
        var buffer = new byte[8192];
        while (true)
        {
            int headerEnd = data.GetBuffer().AsSpan(0, (int)data.Length).IndexOf("\r\n\r\n"u8);
            if (headerEnd >= 0)
            {
                string headerText = Encoding.Latin1.GetString(data.GetBuffer(), 0, headerEnd);
                if (headerText.Split("\r\n").Any(line => line.StartsWith("Expect:", StringComparison.OrdinalIgnoreCase)))
                    throw new InvalidDataException("Expect requests are not supported by the observation proxy.");
            }
            var parsed = Http1Decoder.TryRead(data.GetBuffer().AsSpan(0, (int)data.Length), _options.MaxStreamBytes);
            if (parsed != null)
            {
                if (parsed.Status != null) throw new InvalidDataException("Expected HTTP request.");
                if (data.Length > parsed.Consumed && stream is ReplayStream replay) replay.Prepend(data.ToArray().AsMemory(parsed.Consumed));
                return parsed;
            }
            if (data.Length > _options.MaxStreamBytes + Http1Decoder.MaxHeaderBytes) throw new InvalidDataException("Request body limit exceeded.");
            int n = await stream.ReadAsync(buffer, ct);
            if (n == 0) throw new IOException("Client closed before complete request.");
            data.Write(buffer, 0, n); Account(n);
        }
    }

    private void Account(int bytes) { if (!_account(bytes)) throw new OperationCanceledException("Observation byte budget exceeded."); }

    private async Task Forward(Stream output, HttpMessage message, Uri target, string connectionId, DateTimeOffset started, CancellationToken ct, Action responseStarted)
    {
        if (!Allowed(target.Host)) throw new InvalidDataException("Host not allowed.");
        if (!_accountRequest()) throw new OperationCanceledException();
        started = DateTimeOffset.UtcNow;
        var stopwatch = Stopwatch.StartNew();
        long observedBytes = message.Consumed;
        var connection = new ConnectionRecord(connectionId, "tcp", new("127.0.0.1", 0), new(target.Host, target.Port), started, started, 0, observedBytes, null, "explicit_proxy", target.Scheme == "https", ["exchange_" + connectionId]);
        _store.Put(_observation, connection);
        using var request = new HttpRequestMessage(new HttpMethod(message.Method), target) { Version = HttpVersion.Version11, VersionPolicy = HttpVersionPolicy.RequestVersionExact };
        if (message.Body.Length > 0 || message.Headers.ContainsKey("content-length") || message.Headers.ContainsKey("transfer-encoding")) request.Content = new ByteArrayContent(message.Body);
        var connectionTokens = message.Headers.GetValueOrDefault("connection", "").Split(',').Select(s => s.Trim()).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var (key, value) in message.Headers)
        {
            if (HopHeaders.Contains(key) || connectionTokens.Contains(key)) continue;
            if (!request.Headers.TryAddWithoutValidation(key, value)) request.Content?.Headers.TryAddWithoutValidation(key, value);
        }
        var evidenceId = "exchange_" + connectionId;
        _store.Put(_observation, new EvidenceRecord(evidenceId, connectionId, started, "proxy_request", "info", "Application request observed by explicit proxy.", new() { ["method"] = message.Method, ["target"] = Privacy.Target(target.AbsoluteUri), ["tlsIntercepted"] = (target.Scheme == "https").ToString() }));
        var exchange = new ExchangeRecord(evidenceId, connectionId, "http", message.Method, Privacy.Target(target.AbsoluteUri), null, started, null,
            Privacy.Headers(message.Headers.Where(h => !h.Key.Equals("proxy-authorization", StringComparison.OrdinalIgnoreCase))), [],
            Http1Decoder.BodyPreview(message.Body, message.Headers, _request.RetainPayloads, _options.MaxBodyBytes), null, "awaiting_response", [evidenceId]);
        _store.Put(_observation, exchange);
        try
        {
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            var headers = response.Headers.Concat(response.Content.Headers).ToDictionary(h => h.Key, h => string.Join(", ", h.Value), StringComparer.OrdinalIgnoreCase);
            var responseTokens = headers.GetValueOrDefault("connection", "").Split(',').Select(s => s.Trim()).ToHashSet(StringComparer.OrdinalIgnoreCase);
            bool bodyAllowed = message.Method != "HEAD" && (int)response.StatusCode is not (>= 100 and < 200 or 204 or 304);
            bool chunked = bodyAllowed && response.Content.Headers.ContentLength == null && message.Version == "HTTP/1.1";
            var header = new StringBuilder($"{message.Version} {(int)response.StatusCode} {response.StatusCode}\r\n");
            foreach (var (key, values) in response.Headers.Concat(response.Content.Headers))
            {
                if (HopHeaders.Contains(key) || responseTokens.Contains(key)) continue;
                foreach (var value in values) header.Append(key).Append(": ").Append(value.Replace("\r", "").Replace("\n", "")).Append("\r\n");
            }
            if (response.Content.Headers.ContentLength is long contentLength) header.Append("Content-Length: ").Append(contentLength).Append("\r\n");
            else if (chunked) header.Append("Transfer-Encoding: chunked\r\n");
            header.Append("Connection: close\r\n\r\n");
            exchange = exchange with { StatusCode = (int)response.StatusCode, ResponseHeaders = Privacy.Headers(headers), Completeness = "receiving_response" };
            _store.Put(_observation, exchange);
            var headerBytes = Encoding.Latin1.GetBytes(header.ToString()); Account(headerBytes.Length); observedBytes += headerBytes.Length;
            responseStarted(); await output.WriteAsync(headerBytes, ct);
            using var preview = new MemoryStream();
            await using var input = await response.Content.ReadAsStreamAsync(ct);
            var buffer = new byte[16384];
            while (true)
            {
                int length = await input.ReadAsync(buffer, ct);
                if (length == 0) break;
                Account(length); observedBytes += length;
                if (chunked)
                {
                    var prefix = Encoding.ASCII.GetBytes(length.ToString("X", System.Globalization.CultureInfo.InvariantCulture) + "\r\n");
                    Account(prefix.Length + 2); observedBytes += prefix.Length + 2;
                    await output.WriteAsync(prefix, ct);
                }
                await output.WriteAsync(buffer.AsMemory(0, length), ct);
                if (chunked) await output.WriteAsync("\r\n"u8.ToArray(), ct);
                if (preview.Length < _options.MaxBodyBytes) preview.Write(buffer, 0, (int)Math.Min(length, _options.MaxBodyBytes - preview.Length));
            }
            if (chunked) { Account(5); observedBytes += 5; await output.WriteAsync("0\r\n\r\n"u8.ToArray(), ct); }
            _store.Put(_observation, exchange with
            {
                StatusCode = (int)response.StatusCode,
                DurationMs = stopwatch.Elapsed.TotalMilliseconds,
                ResponseHeaders = Privacy.Headers(headers),
                ResponseBody = Http1Decoder.BodyPreview(preview.ToArray(), headers, _request.RetainPayloads, _options.MaxBodyBytes),
                Completeness = "complete"
            });
        }
        catch
        {
            _store.Put(_observation, exchange with { DurationMs = stopwatch.Elapsed.TotalMilliseconds, Completeness = "failed_or_interrupted" });
            throw;
        }
        finally { _store.Put(_observation, connection with { LastSeen = DateTimeOffset.UtcNow, Bytes = observedBytes }); }
    }

    private async Task Tunnel(Stream client, Uri target, string connectionId, DateTimeOffset started, CancellationToken ct, Action responseStarted)
    {
        if (!_accountRequest()) throw new OperationCanceledException();
        using var upstream = new TcpClient();
        await upstream.ConnectAsync(target.Host, target.Port, ct);
        responseStarted(); await client.WriteAsync("HTTP/1.1 200 Connection Established\r\n\r\n"u8.ToArray(), ct);
        string evidence = "tunnel_" + connectionId;
        _store.Put(_observation, new EvidenceRecord(evidence, connectionId, started, "encrypted_tunnel", "info", "CONNECT tunnel observed; application payload is not decrypted.", new() { ["host"] = target.Host, ["port"] = target.Port.ToString() }));
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        async Task Copy(Stream from, Stream to)
        {
            var buffer = new byte[16384];
            while (true)
            {
                int n = await from.ReadAsync(buffer, linked.Token);
                if (n == 0) return;
                Account(n); await to.WriteAsync(buffer.AsMemory(0, n), linked.Token);
            }
        }
        var a = Copy(client, upstream.GetStream()); var b = Copy(upstream.GetStream(), client);
        await Task.WhenAny(a, b);
        await linked.CancelAsync();
        try { await Task.WhenAll(a, b); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { }
        finally { _store.Put(_observation, new ConnectionRecord(connectionId, "tcp", new("127.0.0.1", 0), new(target.Host, target.Port), started, DateTimeOffset.UtcNow, 0, 0, null, "explicit_proxy", true, [evidence])); }
    }

    private static Task Error(Stream stream, int status, string reason, CancellationToken ct, bool authenticate = false) => stream.WriteAsync(Encoding.ASCII.GetBytes(
        $"HTTP/1.1 {status} {reason}\r\nConnection: close\r\nContent-Length: 0\r\n{(authenticate ? "Proxy-Authenticate: Basic realm=\"AgentShark\"\r\n" : "")}\r\n"), ct).AsTask();

    public async ValueTask DisposeAsync()
    {
        await _stopped.CancelAsync(); _listener.Stop();
        await Task.WhenAll(_clients.Values);
        _http.Dispose(); _upstreamCa?.Dispose(); _ca?.Dispose(); _stopped.Dispose(); _slots.Dispose();
    }
}
