using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AgentShark.Core.Proxy;

/// <summary>Session-scoped CA. No trust store is modified. Windows TLS uses transient OS-managed user key containers.</summary>
public sealed class SessionCertificateAuthority : IDisposable
{
    private readonly X509Certificate2 _root;
    private readonly ConcurrentDictionary<string, X509Certificate2> _leaves = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    public SessionCertificateAuthority()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=AgentShark temporary observation CA", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        _root = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(24));
    }

    public string CertificatePem => _root.ExportCertificatePem();

    public X509Certificate2 ForHost(string hostname)
    {
        lock (_gate)
        {
            if (_leaves.TryGetValue(hostname, out var existing)) return existing;
            if (_leaves.Count >= 100) throw new InvalidOperationException("Certificate cache limit exceeded.");
            using var key = RSA.Create(2048);
            var request = new CertificateRequest("CN=AgentShark observed endpoint", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var names = new SubjectAlternativeNameBuilder();
            if (IPAddress.TryParse(hostname, out var ip)) names.AddIpAddress(ip); else names.AddDnsName(hostname);
            request.CertificateExtensions.Add(names.Build());
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, false));
            using var certificate = request.Create(_root, DateTimeOffset.UtcNow.AddMinutes(-2), DateTimeOffset.UtcNow.AddHours(12), RandomNumberGenerator.GetBytes(16));
            var leaf = certificate.CopyWithPrivateKey(key);
            if (OperatingSystem.IsWindows())
            {
                // Schannel server credentials cannot use ephemeral imported keys. Without PersistKeySet,
                // the imported user key container is released when the certificate is disposed.
                byte[] pfx = leaf.Export(X509ContentType.Pkcs12);
                try
                {
                    var compatible = X509CertificateLoader.LoadPkcs12(pfx, null, X509KeyStorageFlags.UserKeySet);
                    leaf.Dispose(); leaf = compatible;
                }
                finally { CryptographicOperations.ZeroMemory(pfx); }
            }
            _leaves[hostname] = leaf;
            return leaf;
        }
    }

    public void Dispose()
    {
        lock (_gate) { foreach (var certificate in _leaves.Values) certificate.Dispose(); _root.Dispose(); }
    }
}
