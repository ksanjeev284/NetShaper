# NetShaper Callout Driver

First-party **WFP callout** for process-aware outbound rate limiting.

## What v2 implements

| Component | Status |
|-----------|--------|
| KMDF device + symbolic link | ✅ |
| IOCTL version / stats / enable / clear | ✅ |
| Path limit table (diagnostic) | ✅ |
| **PID limit table** (fast path) | ✅ |
| **WFP callout** OUTBOUND_TRANSPORT V4/V6 | ✅ |
| **Classify** token-bucket PERMIT/BLOCK | ✅ |
| Stream inject soft-delay | ⏳ future |
| Dev Authenticode (self-sign + testsigning) | ✅ `scripts\sign-driver.ps1` |
| Production EV / attestation signing | ⚙️ your cert via `NETSHAPER_SIGN_*` env — see `packaging\CERTIFICATES.md` |

### Classify behaviour

1. Outbound transport packet arrives  
2. Process ID from WFP metadata  
3. Lookup PID in table pushed by usermode (`IOCTL_NS_SET_PID_LIMITS`)  
4. Token bucket debit packet length  
5. **Under budget** → `FWP_ACTION_PERMIT`  
6. **Over budget** → `FWP_ACTION_BLOCK` (TCP backs off — rate limit effect)

Usermode (`NetShaperDriverClient.PushLimitsFromPolicy`) resolves filter → running PIDs every few seconds.

## Build (WDK)

1. Visual Studio 2022 + **Windows 11 WDK**  
2. Open **x64 Native Tools / WDK** prompt:

```bat
cd driver\NetShaperCallout
msbuild NetShaperCallout.vcxproj /p:Configuration=Release /p:Platform=x64
```

Output: `x64\Release\NetShaperCallout.sys`

## Install (test signing)

```powershell
# Once — reboot required
powershell -ExecutionPolicy Bypass -File scripts\enable-testsigning.ps1

# After reboot + successful WDK build
powershell -ExecutionPolicy Bypass -File scripts\install-driver-testsign.ps1

dotnet run --project NetShaper.Cli -- driver status
dotnet run --project NetShaper.Cli -- driver push
dotnet run --project NetShaper.Cli -- driver clear
dotnet run --project NetShaper.Cli -- driver disable
```

Optional INF: `NetShaperCallout\NetShaperCallout.inf` (catalog signing for production). Dev installs use `sc create` via the script above.


## Signing

### Dev (self-signed)

```powershell
powershell -File scripts\ensure-codesign-cert.ps1
powershell -File scripts\sign-driver.ps1
# requires: scripts\enable-testsigning.ps1 + reboot
```

### Production (your EV cert)

```powershell
$env:NETSHAPER_SIGN_THUMBPRINT = "<ev-cert-thumbprint>"
# or: $env:NETSHAPER_SIGN_PFX / NETSHAPER_SIGN_PFX_PASSWORD
powershell -File scripts\sign-driver.ps1
```

Then Microsoft **attestation** or HLK so machines without testsigning accept the driver.  
Details: [`packaging/CERTIFICATES.md`](../packaging/CERTIFICATES.md).

This repo does **not** ship a pre-signed `.sys`.

## IOCTL map

| Code | Purpose |
|------|---------|
| `GET_VERSION` | Version + callout flags |
| `GET_STATS` | Packets / blocked / bytes |
| `SET_LIMITS` | Path-contains table |
| `SET_PID_LIMITS` | **Active classify table** |
| `CLEAR_LIMITS` | Clear all |
| `SET_ENABLED` | Global on/off |
