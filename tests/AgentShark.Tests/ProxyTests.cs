using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using AgentShark.Core;
using AgentShark.Core.Proxy;

namespace AgentShark.Tests;

public sealed class ProxyTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(true, true)]
    [InlineData(true, false)]
    public async Task ForwardsHttpAndTlsWithEvidenceAndScopedTrust(bool tls, bool intercept)
    {
        using var authority = new SessionCertificateAuthority();
        await using var workspace = new TestWorkspace(o => o with { UpstreamCaPem = authority.CertificatePem });
        using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var origin = Task.Run(async () =>
        {
            using var socket = await listener.AcceptTcpClientAsync(deadline.Token);
            Stream stream = socket.GetStream();
            if (tls)
            {
                var secure = new SslStream(stream);
                await secure.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate = authority.ForHost("localhost"), EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13 }, deadline.Token);
                stream = secure;
            }
            await using (stream)
            {
                var buffer = new byte[32768]; int used = 0;
                while (buffer.AsSpan(0, used).IndexOf("\r\n\r\n"u8) < 0)
                {
                    int n = await stream.ReadAsync(buffer.AsMemory(used), deadline.Token); if (n == 0) throw new IOException(); used += n;
                }
                string request = Encoding.ASCII.GetString(buffer, 0, used);
                Assert.DoesNotContain("Proxy-Authorization", request, StringComparison.OrdinalIgnoreCase);
                await stream.WriteAsync("HTTP/1.1 201 Created\r\nContent-Type: text/plain\r\nContent-Length: 7\r\nSet-Cookie: secret\r\nConnection: close\r\n\r\nsuccess"u8.ToArray(), deadline.Token);
            }
        }, deadline.Token);
        var observation = await workspace.Engine.StartAsync(new() { Mode = ObservationMode.Proxy, AllowedHosts = ["localhost"], RetainPayloads = true, InterceptTls = intercept });
        var proxy = observation.Proxy!;
        var handler = new HttpClientHandler { Proxy = new WebProxy(proxy.Url) { Credentials = new NetworkCredential(proxy.Username, proxy.Password) }, UseProxy = true };
        if (tls)
        {
            using var root = X509Certificate2.CreateFromPem(proxy.CaCertificatePem ?? authority.CertificatePem);
            handler.ServerCertificateCustomValidationCallback = (_, certificate, _, errors) =>
            {
                if ((errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0 || certificate == null) return false;
                using var chain = new X509Chain(); chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.Add(root); chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                return chain.Build(certificate);
            };
            using var client = new HttpClient(handler);
            HttpResponseMessage result;
            try { result = await client.GetAsync($"https://localhost:{port}/check?secret=hidden", deadline.Token); }
            catch (Exception ex) { throw new InvalidOperationException(System.Text.Json.JsonSerializer.Serialize(workspace.Engine.Events(observation.Observation.Id, new()).Items), ex); }
            using var response = result;
            Assert.Equal(HttpStatusCode.Created, response.StatusCode); Assert.Equal("success", await response.Content.ReadAsStringAsync(deadline.Token));
        }
        else
        {
            using var client = new HttpClient(handler);
            using var response = await client.GetAsync($"http://localhost:{port}/check?secret=hidden", deadline.Token);
            Assert.Equal(HttpStatusCode.Created, response.StatusCode); Assert.Equal("success", await response.Content.ReadAsStringAsync(deadline.Token));
        }
        await origin;
        await workspace.Engine.StopAsync(observation.Observation.Id, deadline.Token);
        if (tls && !intercept)
        {
            Assert.Empty(workspace.Engine.Exchanges(observation.Observation.Id, new()).Items);
            Assert.Contains(workspace.Engine.Events(observation.Observation.Id, new()).Items, e => e.Kind == "encrypted_tunnel");
            return;
        }
        var exchange = Assert.Single(workspace.Engine.Exchanges(observation.Observation.Id, new(), true).Items);
        Assert.Equal(201, exchange.StatusCode); Assert.Equal("success", exchange.ResponseBody);
        Assert.DoesNotContain("secret", exchange.Target); Assert.Equal("[redacted]", exchange.ResponseHeaders["set-cookie"]);
        Assert.DoesNotContain(exchange.RequestHeaders.Keys, k => k.Equals("proxy-authorization", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(1, workspace.Engine.Status(observation.Observation.Id).ProxyRequests);
    }

    [Fact]
    public async Task RequiresAuthenticationAndEnforcesHostAllowlist()
    {
        await using var workspace = new TestWorkspace();
        var observation = await workspace.Engine.StartAsync(new() { Mode = ObservationMode.Proxy, AllowedHosts = ["allowed.test"] });
        var proxy = observation.Proxy!; var uri = new Uri(proxy.Url);
        async Task<string> Request(bool authenticate)
        {
            using var socket = new TcpClient(); await socket.ConnectAsync(uri.Host, uri.Port);
            var stream = socket.GetStream();
            string auth = authenticate ? "Proxy-Authorization: Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(proxy.Username + ":" + proxy.Password)) + "\r\n" : "";
            await stream.WriteAsync(Encoding.ASCII.GetBytes("GET http://blocked.test/ HTTP/1.1\r\nHost: blocked.test\r\n" + auth + "\r\n"));
            using var reader = new StreamReader(stream); return (await reader.ReadLineAsync())!;
        }
        Assert.Contains("407", await Request(false)); Assert.Contains("403", await Request(true));
        await workspace.Engine.StopAsync(observation.Observation.Id);
        Assert.Empty(workspace.Engine.Exchanges(observation.Observation.Id, new()).Items);
    }

    [Fact]
    public async Task StopsAtDurationLimit()
    {
        await using var workspace = new TestWorkspace();
        var observation = await workspace.Engine.StartAsync(new() { Mode = ObservationMode.Proxy, AllowedHosts = ["localhost"], DurationSeconds = 1 });
        var status = await workspace.Wait(observation.Observation.Id);
        Assert.Equal(ObservationState.Completed, status.State); Assert.Equal("duration_limit", status.StopReason);
        using var socket = new TcpClient(); var uri = new Uri(observation.Proxy!.Url);
        await Assert.ThrowsAsync<SocketException>(() => socket.ConnectAsync(uri.Host, uri.Port));
    }

    [Fact]
    public async Task DoesNotReplayCookiesAcrossClientsAndPreservesSeparateSetCookieHeaders()
    {
        await using var workspace = new TestWorkspace();
        using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var origin = Task.Run(async () =>
        {
            for (int i = 0; i < 2; i++)
            {
                using var socket = await listener.AcceptTcpClientAsync(deadline.Token);
                var stream = socket.GetStream();
                using var reader = new StreamReader(stream, leaveOpen: true);
                var lines = new List<string>();
                while (await reader.ReadLineAsync(deadline.Token) is string line && line.Length > 0) lines.Add(line);
                Assert.DoesNotContain(lines, line => line.StartsWith("Cookie:", StringComparison.OrdinalIgnoreCase));
                await stream.WriteAsync("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nSet-Cookie: a=secret; Path=/\r\nSet-Cookie: b=secret; Path=/\r\nConnection: close\r\n\r\n"u8.ToArray(), deadline.Token);
            }
        }, deadline.Token);
        var observation = await workspace.Engine.StartAsync(new() { Mode = ObservationMode.Proxy, AllowedHosts = ["localhost"] });
        var proxy = observation.Proxy!;
        for (int i = 0; i < 2; i++)
        {
            using var client = new HttpClient(new HttpClientHandler { UseCookies = false, Proxy = new WebProxy(proxy.Url) { Credentials = new NetworkCredential(proxy.Username, proxy.Password) } });
            using var response = await client.GetAsync($"http://localhost:{port}/", deadline.Token);
            Assert.Equal(2, response.Headers.GetValues("Set-Cookie").Count());
        }
        await origin;
        await workspace.Engine.StopAsync(observation.Observation.Id);
    }

    [Fact]
    public async Task RejectsUntrustedUpstreamCertificateAndReturnsTlsProtectedFailure()
    {
        using var originCa = new SessionCertificateAuthority();
        await using var workspace = new TestWorkspace();
        using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var origin = Task.Run(async () =>
        {
            using var socket = await listener.AcceptTcpClientAsync(deadline.Token);
            using var stream = new SslStream(socket.GetStream());
            try
            {
                await stream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate = originCa.ForHost("localhost") }, deadline.Token);
                _ = await stream.ReadAsync(new byte[1], deadline.Token);
            }
            catch (Exception ex) when (ex is IOException or AuthenticationException) { }
        }, deadline.Token);
        var observation = await workspace.Engine.StartAsync(new() { Mode = ObservationMode.Proxy, AllowedHosts = ["localhost"], InterceptTls = true });
        var proxy = observation.Proxy!;
        using var root = X509Certificate2.CreateFromPem(proxy.CaCertificatePem!);
        var handler = new HttpClientHandler { Proxy = new WebProxy(proxy.Url) { Credentials = new NetworkCredential(proxy.Username, proxy.Password) } };
        handler.ServerCertificateCustomValidationCallback = (_, certificate, _, errors) =>
        {
            if (certificate == null || (errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0) return false;
            using var chain = new X509Chain(); chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(root); chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            return chain.Build(certificate);
        };
        using var client = new HttpClient(handler);
        using var response = await client.GetAsync($"https://localhost:{port}/", deadline.Token);
        Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);
        await origin;
        await workspace.Engine.StopAsync(observation.Observation.Id);
        var exchange = Assert.Single(workspace.Engine.Exchanges(observation.Observation.Id, new()).Items);
        Assert.Equal("failed_or_interrupted", exchange.Completeness);
        Assert.Contains(workspace.Engine.Events(observation.Observation.Id, new()).Items, e => e.Kind == "upstream_request_failed");
    }

    [Fact]
    public async Task EnforcesProxyRequestBudget()
    {
        await using var workspace = new TestWorkspace();
        using var reserved = new TcpListener(IPAddress.Loopback, 0); reserved.Start();
        int unusedPort = ((IPEndPoint)reserved.LocalEndpoint).Port; reserved.Stop();
        var observation = await workspace.Engine.StartAsync(new() { Mode = ObservationMode.Proxy, AllowedHosts = ["localhost"], MaxProxyRequests = 1 });
        var proxy = observation.Proxy!;
        using var http = new HttpClient(new HttpClientHandler { Proxy = new WebProxy(proxy.Url) { Credentials = new NetworkCredential(proxy.Username, proxy.Password) } });
        using var first = await http.GetAsync($"http://localhost:{unusedPort}/");
        Assert.Equal(HttpStatusCode.BadGateway, first.StatusCode);
        try { using var second = await http.GetAsync($"http://localhost:{unusedPort}/"); }
        catch (HttpRequestException) { }
        var status = await workspace.Wait(observation.Observation.Id);
        Assert.Equal("proxy_request_limit", status.StopReason); Assert.Equal(1, status.ProxyRequests);
        Assert.Single(workspace.Engine.Connections(status.Id, new()).Items);
    }

    [Fact]
    public async Task PropagatesIncompleteUpstreamBodyAsFailureInsteadOfSuccess()
    {
        await using var workspace = new TestWorkspace();
        using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var origin = Task.Run(async () =>
        {
            using var socket = await listener.AcceptTcpClientAsync(timeout.Token);
            var stream = socket.GetStream(); using var reader = new StreamReader(stream, leaveOpen: true);
            while (await reader.ReadLineAsync(timeout.Token) is string line && line.Length > 0) { }
            await stream.WriteAsync("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 10\r\nConnection: close\r\n\r\nabc"u8.ToArray(), timeout.Token);
        }, timeout.Token);
        var observation = await workspace.Engine.StartAsync(new() { Mode = ObservationMode.Proxy, AllowedHosts = ["localhost"] });
        var proxy = observation.Proxy!;
        using var client = new HttpClient(new HttpClientHandler { Proxy = new WebProxy(proxy.Url) { Credentials = new NetworkCredential(proxy.Username, proxy.Password) } });
        await Assert.ThrowsAsync<HttpRequestException>(() => client.GetAsync($"http://localhost:{port}/", timeout.Token));
        await origin; await workspace.Engine.StopAsync(observation.Observation.Id);
        var exchange = Assert.Single(workspace.Engine.Exchanges(observation.Observation.Id, new()).Items);
        Assert.Equal(200, exchange.StatusCode); Assert.Equal("failed_or_interrupted", exchange.Completeness);
    }
}
