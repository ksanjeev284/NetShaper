using System.Security.Cryptography;
using System.Text.Json;

namespace NetShaper.Core.Api;

/// <summary>Local HTTP + remote mTLS API configuration.</summary>
public sealed class ApiSettings
{
    public bool Enabled { get; set; }
    public string Host { get; set; } = "127.0.0.1";
    public int Port { get; set; } = 8741;
    public string ApiKey { get; set; } = "";
    /// <summary>Allow binding beyond loopback for local HTTP and remote TLS. Default false.</summary>
    public bool AllowNonLocal { get; set; }

    // Remote mTLS
    public bool RemoteEnabled { get; set; }
    public int RemotePort { get; set; } = 8742;
    public string RemoteHostName { get; set; } = Environment.MachineName;

    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };
    public static string FilePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "NetShaper", "api-settings.json");

    public static ApiSettings Load()
    {
        try
        {
            if (File.Exists(FilePath))
            {
                var s = JsonSerializer.Deserialize<ApiSettings>(File.ReadAllText(FilePath), JsonOpts);
                if (s != null)
                {
                    if (string.IsNullOrWhiteSpace(s.ApiKey))
                        s.ApiKey = GenerateKey();
                    if (string.IsNullOrWhiteSpace(s.RemoteHostName))
                        s.RemoteHostName = Environment.MachineName;
                    if (s.RemotePort <= 0) s.RemotePort = 8742;
                    return s;
                }
            }
        }
        catch { /* ignore */ }

        var fresh = new ApiSettings { ApiKey = GenerateKey(), Enabled = false };
        fresh.Save();
        return fresh;
    }

    public void Save()
    {
        try
        {
            var dir = Path.GetDirectoryName(FilePath)!;
            Directory.CreateDirectory(dir);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(this, JsonOpts));
        }
        catch { /* ignore */ }
    }

    public string BaseUrl => $"http://{Host}:{Port}";
    public string RemoteBaseUrl => $"https://{RemoteHostName}:{RemotePort}";

    public static string GenerateKey()
    {
        var bytes = RandomNumberGenerator.GetBytes(24);
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', 'x').Replace('/', 'y');
    }

    public void EnsureKey()
    {
        if (string.IsNullOrWhiteSpace(ApiKey))
            ApiKey = GenerateKey();
    }
}
