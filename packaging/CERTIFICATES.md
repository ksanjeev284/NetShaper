# Certificates & signing

NetShaper uses **three separate credential systems**. They are not interchangeable.

| System | Purpose | Cost | In-repo |
|--------|---------|------|---------|
| **mTLS PKI** | Remote HTTPS API (client + server certs) | Free | Full automation |
| **Code-sign (dev)** | Sign MSIX / EXE / test-signed `.sys` | Free self-signed | Scripts |
| **Code-sign (production)** | Public trust for driver + packages | Buy EV / org cert | Env hooks only |
| **Microsoft attestation** | Load kernel driver without testsigning | Partner Center / HLK | Manual |

---

## 1. mTLS remote API (done — use it)

```powershell
# First time on the host (admin recommended)
powershell -File scripts\generate-certs.ps1 -ClientName laptop1 -ServerName YOURPC
# or:
dotnet run --project NetShaper.Cli -- certs ensure --server YOURPC
dotnet run --project NetShaper.Cli -- certs issue laptop1
dotnet run --project NetShaper.Cli -- certs status --show-password
```

| Path | Content |
|------|---------|
| `%ProgramData%\NetShaper\certs\netshaper-ca.pfx` | Local CA |
| `netshaper-server.pfx` | API TLS server |
| `clients\<name>.pfx` | mTLS client |
| `pki-password.txt` | PFX password (Admins-only ACL) |

**Password resolution**

1. Environment `NETSHAPER_PFX_PASSWORD`
2. File `pki-password.txt`
3. First run: **auto-generate** strong password (no shared default)
4. Old installs still on `NetShaper-Dev-ChangeMe` → **rotate**

```powershell
# Rotate all PFX files to a new password
dotnet run --project NetShaper.Cli -- certs rotate "YourLongNewPassword!"

# Hand a client a one-time export password (does not change PKI password)
dotnet run --project NetShaper.Cli -- certs export laptop1 D:\laptop1.pfx "TempHandOffPass1"

# Nuclear: new CA + new random password (clients must be re-issued)
dotnet run --project NetShaper.Cli -- certs reset --yes --server YOURPC
```

---

## 2. Dev code-signing cert (MSIX + test driver)

Creates a **persistent** self-signed cert with subject **`CN=NetShaper`** (matches `AppxManifest.xml` Publisher).

```powershell
# Once per machine
powershell -File scripts\ensure-codesign-cert.ps1
powershell -File scripts\trust-codesign-cert.ps1          # TrustedPublisher
# optional (dev box only):
powershell -File scripts\trust-codesign-cert.ps1 -IncludeRoot
```

Stored under `%ProgramData%\NetShaper\signing\`:

- `NetShaper-CodeSign.pfx` / `.cer`
- `codesign-password.txt`

### Sign anything

```powershell
powershell -File scripts\sign-file.ps1 -Path dist\NetShaper-0.2.0-x64.msix
powershell -File scripts\sign-driver.ps1
```

### MSIX sideload

```powershell
powershell -File scripts\build-msix.ps1 -SelfSign
powershell -File scripts\trust-codesign-cert.ps1
Add-AppxPackage -Path dist\NetShaper-0.2.0-x64.msix
```

Enable **Developer Mode** or “install apps from any source” for sideload.

### Test-signed kernel driver

Self-signed `.sys` requires **testsigning**:

```powershell
powershell -File scripts\enable-testsigning.ps1   # reboot once
# after WDK build:
powershell -File scripts\sign-driver.ps1
powershell -File scripts\install-driver-testsign.ps1
```

---

## 3. Production signing (your commercial cert)

You must purchase credentials; the repo only wires them in.

| Artifact | Typical cert | Extra |
|----------|--------------|--------|
| EXE / MSI / MSIX | Standard or EV Authenticode | Publisher CN must match MSIX identity |
| `NetShaperCallout.sys` | **EV** code-signing | **Microsoft attestation** or HLK for target OS |

### Environment variables (preferred)

```powershell
# Option A: cert already in LocalMachine\My (EV token / smartcard)
$env:NETSHAPER_SIGN_THUMBPRINT = "YOURTHUMBPRINTHEX"

# Option B: PFX on disk
$env:NETSHAPER_SIGN_PFX = "D:\secrets\ev.pfx"
$env:NETSHAPER_SIGN_PFX_PASSWORD = "..."

powershell -File scripts\sign-file.ps1 -Path path\to\NetShaperCallout.sys
powershell -File scripts\sign-driver.ps1
powershell -File scripts\build-msix.ps1 -Sign
```

`sign-file.ps1` resolution order:

1. `-Thumbprint` / `NETSHAPER_SIGN_THUMBPRINT`
2. `-PfxPath` / `NETSHAPER_SIGN_PFX`
3. Dev `ProgramData\NetShaper\signing\NetShaper-CodeSign.pfx`

### MSIX Publisher match

`packaging\msix\AppxManifest.xml` has:

```xml
Publisher="CN=NetShaper"
```

For a real org cert, change Publisher to that cert’s subject (e.g. `CN=Your Company, O=...`) **and** sign with that cert.

### Kernel attestation (cannot be fully automated)

1. EV-sign the `.sys` (and usually the catalog/INF).
2. Submit for [Windows Hardware Dev Center](https://partner.microsoft.com/dashboard) attestation signing, **or** run HLK.
3. Ship the Microsoft-signed package; users do **not** need testsigning.

Until then, document “enable testsigning” for beta testers only.

---

## 4. Security checklist before real remote use

- [ ] `certs rotate` off any legacy default password  
- [ ] Restrict access to `%ProgramData%\NetShaper\certs\` (scripts apply Admin/SYSTEM ACL)  
- [ ] Prefer `certs export` one-time passwords when mailing client PFX  
- [ ] Do not commit `*.pfx`, `pki-password.txt`, or `codesign-password.txt`  
- [ ] Production packages: real Authenticode, not the dev self-signed cert  
- [ ] Production driver: EV + attestation  

---

## Quick map

```text
Remote API trust  →  mTLS PKI (CertificateManager / certs CLI)
Package trust     →  ensure-codesign-cert + sign-file / EV env
Driver load dev   →  sign-driver + testsigning
Driver load prod  →  EV env + Microsoft attestation (outside repo)
```
