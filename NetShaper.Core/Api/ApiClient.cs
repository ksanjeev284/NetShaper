using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace NetShaper.Core.Api;

/// <summary>HTTP client for local (API key) or remote (mTLS + API key) NetShaper API.</summary>
public sealed class ApiClient : IDisposable
{
    private readonly HttpClient _http;

    /// <summary>Local HTTP (loopback) with API key only.</summary>
    public ApiClient(string baseUrl, string apiKey)
    {
        _http = new HttpClient
        {
            BaseAddress = new Uri(baseUrl.TrimEnd('/') + "/"),
            Timeout = TimeSpan.FromSeconds(60),
        };
        _http.DefaultRequestHeaders.Add("X-NetShaper-Key", apiKey);
    }

    /// <summary>Remote HTTPS with client certificate (mTLS) + API key.</summary>
    public ApiClient(string baseUrl, string apiKey, X509Certificate2 clientCert, X509Certificate2? caCert = null)
    {
        var handler = new HttpClientHandler
        {
            ClientCertificateOptions = ClientCertificateOption.Manual,
            CheckCertificateRevocationList = false,
        };
        handler.ClientCertificates.Add(clientCert);
        handler.ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) =>
        {
            if (cert is null) return false;
            if (caCert is null)
                return errors == SslPolicyErrors.None || errors == SslPolicyErrors.RemoteCertificateNameMismatch;
            try
            {
                using var ch = new X509Chain();
                ch.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                ch.ChainPolicy.CustomTrustStore.Add(caCert);
                ch.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                using var server = new X509Certificate2(cert);
                return ch.Build(server);
            }
            catch { return false; }
        };

        _http = new HttpClient(handler)
        {
            BaseAddress = new Uri(baseUrl.TrimEnd('/') + "/"),
            Timeout = TimeSpan.FromSeconds(60),
        };
        _http.DefaultRequestHeaders.Add("X-NetShaper-Key", apiKey);
    }

    public static ApiClient CreateRemote(string host, int port, string apiKey, string clientPfxPath,
        string? pfxPassword = null)
    {
        pfxPassword ??= CertificateManager.PfxPassword;
        var client = new X509Certificate2(clientPfxPath, pfxPassword,
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);
        X509Certificate2? ca = null;
        if (File.Exists(CertificateManager.CaPfxPath))
            ca = CertificateManager.LoadCaCertificate();
        var url = $"https://{host}:{port}";
        return new ApiClient(url, apiKey, client, ca);
    }

    public async Task<string> GetAsync(string path, CancellationToken ct = default)
    {
        using var res = await _http.GetAsync(path.TrimStart('/'), ct).ConfigureAwait(false);
        var body = await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (!res.IsSuccessStatusCode)
            throw new HttpRequestException($"{(int)res.StatusCode}: {body}");
        return body;
    }

    public async Task<string> PostAsync(string path, object? jsonBody = null, CancellationToken ct = default)
    {
        HttpContent content;
        if (jsonBody != null)
        {
            var json = JsonSerializer.Serialize(jsonBody);
            content = new StringContent(json, Encoding.UTF8, "application/json");
        }
        else content = new StringContent("");
        using var res = await _http.PostAsync(path.TrimStart('/'), content, ct).ConfigureAwait(false);
        var body = await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (!res.IsSuccessStatusCode)
            throw new HttpRequestException($"{(int)res.StatusCode}: {body}");
        return body;
    }

    public async Task<string> DeleteAsync(string path, CancellationToken ct = default)
    {
        using var res = await _http.DeleteAsync(path.TrimStart('/'), ct).ConfigureAwait(false);
        var body = await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (!res.IsSuccessStatusCode)
            throw new HttpRequestException($"{(int)res.StatusCode}: {body}");
        return body;
    }

    public void Dispose() => _http.Dispose();
}
