# Packaging

Ways to ship NetShaper to end users.

## 1. Portable ZIP (default)

```powershell
powershell -ExecutionPolicy Bypass -File scripts\publish.ps1
# → dist\NetShaper-0.2.0-win-x64.zip
# → dist\NetShaper-win-x64\
```

Install from the zip folder (admin):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install-app.ps1
```

## 2. Inno Setup installer

Requires [Inno Setup 6](https://jrsoftware.org/isinfo.php).

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build-installer.ps1
```

Script: `scripts\NetShaper.iss`.

## 3. MSIX (sideload)

Requires **Windows SDK** (`makeappx.exe`, optionally `signtool.exe`).

```powershell
# Stage + pack; -SelfSign creates a temp CN=NetShaper cert for local test
powershell -ExecutionPolicy Bypass -File scripts\build-msix.ps1 -SelfSign

Add-AppxPackage -Path dist\NetShaper-0.2.0-x64.msix
```

| Item | Path |
|------|------|
| Manifest | `packaging\msix\AppxManifest.xml` |
| Build script | `scripts\build-msix.ps1` |
| Identity | `NetShaper.TrafficControl` / `CN=NetShaper` / `0.2.0.0` |
| Capability | `runFullTrust` (desktop bridge style) |

If `makeappx` is missing, the script still stages `dist\msix-stage\` so you can pack later.

**Notes**

- MSIX is **full-trust**; WFP / driver still need elevation / separate kernel install.
- Dev signing uses persistent `CN=NetShaper` cert (`scripts\ensure-codesign-cert.ps1`).
- Production: set `NETSHAPER_SIGN_THUMBPRINT` / `NETSHAPER_SIGN_PFX` and match `AppxManifest` Publisher.
- Kernel driver (`.sys`) is **not** bundled in MSIX — see `driver\README.md`.

## 4. Kernel callout driver

See `driver\README.md`. Not included in portable/MSIX packages by default.

## 5. Certificates (mTLS + code signing)

See **[CERTIFICATES.md](CERTIFICATES.md)** for mTLS PKI, password rotation, dev code-sign, and production EV/attestation.
