using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace NetShaper.Core.Api;

/// <summary>
/// Self-hosted PKI for NetShaper remote API (mTLS).
/// Prefers %ProgramData%\NetShaper\certs\; falls back to LocalAppData when not writable.
/// PFX password: env NETSHAPER_PFX_PASSWORD → pki-password.txt → auto-generated secret.
/// </summary>
public static class CertificateManager
{
    private static string? _resolvedCertsDir;

    public static string CertsDir => _resolvedCertsDir ??= ResolveWritableCertsDir();

    public static string CaPfxPath => Path.Combine(CertsDir, "netshaper-ca.pfx");
    public static string ServerPfxPath => Path.Combine(CertsDir, "netshaper-server.pfx");
    public static string ClientsDir => Path.Combine(CertsDir, "clients");
    public static string ManifestPath => Path.Combine(CertsDir, "clients.json");
    public static string PasswordFilePath => Path.Combine(CertsDir, "pki-password.txt");

    private static string ResolveWritableCertsDir()
    {
        var candidates = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "NetShaper", "certs"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetShaper", "certs"),
        };
        // Prefer a path that already has a CA (upgrade / prior install)
        foreach (var d in candidates)
        {
            if (File.Exists(Path.Combine(d, "netshaper-ca.pfx")))
                return d;
        }
        foreach (var d in candidates)
        {
            try
            {
                Directory.CreateDirectory(d);
                Directory.CreateDirectory(Path.Combine(d, "clients"));
                var probe = Path.Combine(d, ".write-probe");
                File.WriteAllText(probe, "ok");
                File.Delete(probe);
                return d;
            }
            catch { /* try next */ }
        }
        return candidates[0];
    }

    /// <summary>Legacy default used only to open old installs that never rotated.</summary>
    public const string LegacyDevPassword = "NetShaper-Dev-ChangeMe";

    public const string PasswordEnvVar = "NETSHAPER_PFX_PASSWORD";

    public sealed class ClientRecord
    {
        public string Name { get; set; } = "";
        public string Thumbprint { get; set; } = "";
        public string Subject { get; set; } = "";
        public DateTimeOffset CreatedUtc { get; set; } = DateTimeOffset.UtcNow;
        public bool Revoked { get; set; }
        public string? Note { get; set; }
    }

    public static bool HasPki => File.Exists(CaPfxPath) && File.Exists(ServerPfxPath);

    /// <summary>
    /// Active PFX password. Never hard-codes a production secret: prefers env, then file,
    /// then generates a strong password on first use.
    /// </summary>
    public static string PfxPassword
    {
        get => ResolvePassword(createIfMissing: true);
        set => SavePassword(value);
    }

    /// <summary>True when password is still the old built-in dev default (should rotate).</summary>
    public static bool IsUsingLegacyDevPassword
    {
        get
        {
            try
            {
                var p = ResolvePassword(createIfMissing: false);
                return string.Equals(p, LegacyDevPassword, StringComparison.Ordinal);
            }
            catch { return false; }
        }
    }

    public static string PasswordSource
    {
        get
        {
            var env = Environment.GetEnvironmentVariable(PasswordEnvVar);
            if (!string.IsNullOrEmpty(env)) return "environment:" + PasswordEnvVar;
            if (File.Exists(PasswordFilePath)) return "file:" + PasswordFilePath;
            if (HasPki) return "legacy-or-unset";
            return "will-generate-on-ensure";
        }
    }

    public static void EnsurePki(string? serverDnsName = null)
    {
        Directory.CreateDirectory(CertsDir);
        Directory.CreateDirectory(ClientsDir);
        serverDnsName ??= Environment.MachineName;

        // Ensure password exists before creating any PFX
        var pwd = ResolvePassword(createIfMissing: true);

        if (!File.Exists(CaPfxPath))
        {
            using var caKey = RSA.Create(4096);
            var caReq = new CertificateRequest(
                "CN=NetShaper Local CA, O=NetShaper",
                caKey,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            caReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            caReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(caReq.PublicKey, false));
            caReq.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            using var ca = caReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(10));
            File.WriteAllBytes(CaPfxPath, ca.Export(X509ContentType.Pfx, pwd));
            WriteCer(Path.Combine(CertsDir, "netshaper-ca.cer"), ca);
        }

        if (!File.Exists(ServerPfxPath))
        {
            using var ca = LoadPfx(CaPfxPath);
            using var serverKey = RSA.Create(2048);
            var req = new CertificateRequest(
                $"CN={serverDnsName}, O=NetShaper Server",
                serverKey,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
            req.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
            req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, true)); // serverAuth
            var san = new SubjectAlternativeNameBuilder();
            san.AddDnsName(serverDnsName);
            san.AddDnsName("localhost");
            san.AddIpAddress(System.Net.IPAddress.Loopback);
            try { san.AddIpAddress(System.Net.IPAddress.IPv6Loopback); } catch { /* ignore */ }
            req.CertificateExtensions.Add(san.Build());
            req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));

            var serial = RandomNumberGenerator.GetBytes(16);
            serial[0] &= 0x7F;
            using var server = req.Create(ca, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(3), serial);
            using var serverWithKey = server.CopyWithPrivateKey(serverKey);
            var export = new X509Certificate2Collection { serverWithKey, ca };
            File.WriteAllBytes(ServerPfxPath, export.Export(X509ContentType.Pfx, pwd)!);
        }

        if (!File.Exists(ManifestPath))
            SaveClients(new List<ClientRecord>());

        WritePasswordReadme();
    }

    public static X509Certificate2 LoadServerCertificate()
    {
        EnsurePki();
        return LoadPfx(ServerPfxPath);
    }

    public static X509Certificate2 LoadCaCertificate()
    {
        EnsurePki();
        return LoadPfx(CaPfxPath);
    }

    public static (X509Certificate2 client, string pfxPath) IssueClientCertificate(string clientName, string? note = null)
    {
        if (string.IsNullOrWhiteSpace(clientName))
            throw new ArgumentException("clientName required");
        clientName = Sanitize(clientName);
        EnsurePki();
        var pwd = ResolvePassword(createIfMissing: true);

        using var ca = LoadPfx(CaPfxPath);
        using var key = RSA.Create(2048);
        var req = new CertificateRequest(
            $"CN={clientName}, O=NetShaper Client",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") }, true)); // clientAuth
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));

        var serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7F;
        using var cert = req.Create(ca, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(2), serial);
        using var withKey = cert.CopyWithPrivateKey(key);
        var pfxPath = Path.Combine(ClientsDir, clientName + ".pfx");
        File.WriteAllBytes(pfxPath, withKey.Export(X509ContentType.Pfx, pwd));
        WriteCer(Path.Combine(ClientsDir, clientName + ".cer"), withKey);

        var list = LoadClients();
        list.RemoveAll(c => c.Name.Equals(clientName, StringComparison.OrdinalIgnoreCase));
        list.Add(new ClientRecord
        {
            Name = clientName,
            Thumbprint = withKey.Thumbprint ?? "",
            Subject = withKey.Subject,
            Note = note,
        });
        SaveClients(list);

        return (LoadPfx(pfxPath), pfxPath);
    }

    /// <summary>
    /// Export a client PFX with a one-time password for hand-off (does not change PKI password).
    /// </summary>
    public static string ExportClientWithPassword(string clientName, string destPfxPath, string exportPassword)
    {
        clientName = Sanitize(clientName);
        var src = Path.Combine(ClientsDir, clientName + ".pfx");
        if (!File.Exists(src))
            throw new FileNotFoundException("Client PFX not found", src);
        if (string.IsNullOrEmpty(exportPassword) || exportPassword.Length < 8)
            throw new ArgumentException("export password must be at least 8 characters");

        using var cert = LoadPfx(src);
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(destPfxPath))!);
        File.WriteAllBytes(destPfxPath, cert.Export(X509ContentType.Pfx, exportPassword));
        return destPfxPath;
    }

    /// <summary>
    /// Re-export CA, server, and all client PFXes under a new password. Updates password store.
    /// </summary>
    public static int RotatePassword(string newPassword, string? oldPassword = null)
    {
        if (string.IsNullOrEmpty(newPassword) || newPassword.Length < 12)
            throw new ArgumentException("new password must be at least 12 characters");

        oldPassword ??= ResolvePassword(createIfMissing: false);
        // Probe which password opens CA
        if (!TryOpenPfx(CaPfxPath, oldPassword, out _) &&
            !TryOpenPfx(CaPfxPath, LegacyDevPassword, out _))
        {
            throw new InvalidOperationException(
                "Cannot open CA PFX with current or legacy password. Set " + PasswordEnvVar + " to the real password.");
        }

        string workingOld = oldPassword;
        if (!TryOpenPfx(CaPfxPath, workingOld, out _))
            workingOld = LegacyDevPassword;

        int count = 0;
        void Reexport(string path)
        {
            if (!File.Exists(path)) return;
            using var c = new X509Certificate2(path, workingOld,
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);
            // Prefer collection export for chain PFXes
            try
            {
                var col = new X509Certificate2Collection();
                col.Import(path, workingOld, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);
                File.WriteAllBytes(path, col.Export(X509ContentType.Pfx, newPassword)!);
            }
            catch
            {
                File.WriteAllBytes(path, c.Export(X509ContentType.Pfx, newPassword));
            }
            count++;
        }

        Reexport(CaPfxPath);
        Reexport(ServerPfxPath);
        if (Directory.Exists(ClientsDir))
        {
            foreach (var pfx in Directory.GetFiles(ClientsDir, "*.pfx"))
                Reexport(pfx);
        }

        SavePassword(newPassword);
        return count;
    }

    /// <summary>
    /// Wipe PKI and recreate with current password policy (new random password if none set).
    /// </summary>
    public static void ResetPki(string? serverDnsName = null, bool generateNewPassword = true)
    {
        if (generateNewPassword)
            SavePassword(GeneratePassword(28));

        foreach (var f in new[] { CaPfxPath, ServerPfxPath, ManifestPath })
        {
            try { if (File.Exists(f)) File.Delete(f); } catch { /* ignore */ }
        }
        if (Directory.Exists(ClientsDir))
        {
            try { Directory.Delete(ClientsDir, true); } catch { /* ignore */ }
        }
        EnsurePki(serverDnsName);
    }

    public static List<ClientRecord> LoadClients()
    {
        try
        {
            if (File.Exists(ManifestPath))
                return JsonSerializer.Deserialize<List<ClientRecord>>(File.ReadAllText(ManifestPath))
                       ?? new List<ClientRecord>();
        }
        catch { /* ignore */ }
        return new List<ClientRecord>();
    }

    public static void SaveClients(List<ClientRecord> list)
    {
        Directory.CreateDirectory(CertsDir);
        File.WriteAllText(ManifestPath, JsonSerializer.Serialize(list, new JsonSerializerOptions { WriteIndented = true }));
    }

    public static bool IsClientAuthorized(X509Certificate2? clientCert)
    {
        if (clientCert is null) return false;
        var tp = clientCert.Thumbprint ?? "";
        var list = LoadClients();
        return list.Any(c => !c.Revoked &&
            c.Thumbprint.Equals(tp, StringComparison.OrdinalIgnoreCase));
    }

    public static void RevokeClient(string nameOrThumbprint)
    {
        var list = LoadClients();
        foreach (var c in list)
        {
            if (c.Name.Equals(nameOrThumbprint, StringComparison.OrdinalIgnoreCase) ||
                c.Thumbprint.Equals(nameOrThumbprint, StringComparison.OrdinalIgnoreCase))
                c.Revoked = true;
        }
        SaveClients(list);
    }

    // ── password helpers ──────────────────────────────────────────────

    private static string ResolvePassword(bool createIfMissing)
    {
        var env = Environment.GetEnvironmentVariable(PasswordEnvVar);
        if (!string.IsNullOrEmpty(env))
            return env;

        if (File.Exists(PasswordFilePath))
        {
            var line = File.ReadAllText(PasswordFilePath)
                .Split('\n', '\r')
                .Select(s => s.Trim())
                .FirstOrDefault(s => s.Length > 0 && !s.StartsWith('#'));
            if (!string.IsNullOrEmpty(line))
                return line;
        }

        // Existing PKI without password file → legacy default (migrate with certs rotate)
        if (HasPki)
            return LegacyDevPassword;

        if (!createIfMissing)
            throw new InvalidOperationException("No PFX password configured.");

        var generated = GeneratePassword(28);
        SavePassword(generated);
        return generated;
    }

    private static void SavePassword(string password)
    {
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("password required");
        Directory.CreateDirectory(CertsDir);
        var body =
            "# NetShaper mTLS PFX password — protect this file (Administrators only).\n" +
            "# Override with environment variable " + PasswordEnvVar + "\n" +
            "# Rotate: NetShaper.Cli certs rotate <newPassword>\n" +
            password + "\n";
        File.WriteAllText(PasswordFilePath, body, Encoding.UTF8);
        TryRestrictAcl(PasswordFilePath);
        TryRestrictAcl(CertsDir);
    }

    private static void WritePasswordReadme()
    {
        var path = Path.Combine(CertsDir, "README-PKI.txt");
        if (File.Exists(path)) return;
        File.WriteAllText(path,
            "NetShaper mTLS PKI\n" +
            "=================\n" +
            "netshaper-ca.pfx / .cer     Local certificate authority\n" +
            "netshaper-server.pfx       HTTPS server (remote API)\n" +
            "clients\\*.pfx              Client certs for mTLS\n" +
            "pki-password.txt           PFX password (keep secret)\n" +
            "\n" +
            "Env override: " + PasswordEnvVar + "\n" +
            "Rotate:  NetShaper.Cli certs rotate <newPassword>\n" +
            "Issue:   NetShaper.Cli certs issue <clientName>\n" +
            "Export:  NetShaper.Cli certs export <name> <out.pfx> <oneTimePassword>\n");
    }

    private static string GeneratePassword(int length)
    {
        // Avoid ambiguous chars; URL/path safe subset
        const string alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%_-";
        var bytes = RandomNumberGenerator.GetBytes(length);
        var chars = new char[length];
        for (int i = 0; i < length; i++)
            chars[i] = alphabet[bytes[i] % alphabet.Length];
        return new string(chars);
    }

    private static void TryRestrictAcl(string path)
    {
        try
        {
            // icacls: Administrators + SYSTEM only
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "icacls",
                Arguments = $"\"{path}\" /inheritance:r /grant:r *S-1-5-32-544:(F) /grant:r *S-1-5-18:(F)",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var p = System.Diagnostics.Process.Start(psi);
            p?.WaitForExit(5000);
        }
        catch { /* non-fatal if not elevated */ }
    }

    private static bool TryOpenPfx(string path, string password, out X509Certificate2? cert)
    {
        cert = null;
        if (!File.Exists(path)) return false;
        try
        {
            cert = new X509Certificate2(path, password,
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static X509Certificate2 LoadPfx(string path)
    {
        var pwd = ResolvePassword(createIfMissing: true);
        if (TryOpenPfx(path, pwd, out var c) && c != null)
            return c;
        // Migrate legacy installs transparently once
        if (!string.Equals(pwd, LegacyDevPassword, StringComparison.Ordinal) &&
            TryOpenPfx(path, LegacyDevPassword, out c) && c != null)
            return c;
        throw new CryptographicException(
            $"Cannot open PFX '{path}'. Check {PasswordEnvVar} or {PasswordFilePath}.");
    }

    private static void WriteCer(string path, X509Certificate2 cert)
    {
        File.WriteAllText(path,
            "-----BEGIN CERTIFICATE-----\n" +
            Convert.ToBase64String(cert.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks) +
            "\n-----END CERTIFICATE-----\n");
    }

    private static string Sanitize(string name)
    {
        foreach (var c in Path.GetInvalidFileNameChars())
            name = name.Replace(c, '_');
        return name.Trim();
    }
}
