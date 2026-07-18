# NetShaper

**Free open-source bandwidth limiter and traffic control for Windows**

Limit app download/upload speed · block or allow network access · live rates · DNS filters · quotas · MIT license · no paywall

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-lightgrey.svg)](#)
[![.NET](https://img.shields.io/badge/.NET-8-purple.svg)](#)

---

## What is NetShaper?

**NetShaper** is a free Windows **bandwidth limiter** and **network traffic controller**. Limit how fast individual apps use the internet, block or allow connections, set data quotas, apply DNS domain filters, and watch live download/upload rates — all from a modern desktop app.

Built with **public Microsoft Windows APIs** (IP Helper, Windows Filtering Platform, Policy-based QoS) and optional [WinDivert](https://reqrypt.org/windivert.html) for packet-level shaping. Fully **open source under the MIT License**.

### Keywords

`bandwidth limiter` · `traffic shaper` · `per-app speed limit` · `Windows firewall rules` · `QoS` · `network monitor` · `download limiter` · `upload limiter` · `open source` · `free software`

---

## Features

| Area | Capabilities |
|------|----------------|
| **Live traffic** | Per-process rates & data, service names, connections, sparklines |
| **Limits** | Soft / Aggressive / QoS / Packet (WinDivert) modes |
| **Firewall** | Block / Allow rules, lockdown mode, interactive Ask prompts |
| **Priority** | DSCP / NetQos priority bands |
| **Quotas** | Data caps with auto-block |
| **DNS** | Domain block/allow via Windows DNS cache + resolve |
| **Stats** | SQLite history, charts, CSV export |
| **Automation** | Local HTTP API, mTLS remote API, CLI |
| **Security** | Per-user ACL, optional code-sign / PKI scripts |
| **Packaging** | Self-contained zip, Inno Setup, MSIX scripts |

---

## Screenshots / UI

- Dark & light themes (high-contrast)
- Dashboard with top talkers and rate chart
- Live process / connection grids
- Rules, limits, quotas, history, settings

---

## Requirements

- **Windows 10 or 11** (x64)
- **.NET 8** (for building from source; release builds are self-contained)
- **Administrator** recommended for Apply WFP, QoS, Packet mode, and precise per-app rates

---

## Install (easiest)

### GUI installer (easiest)

1. Download **NetShaper-Setup-*.exe** from [Releases](https://github.com/ksanjeev284/NetShaper/releases)
2. Double-click the installer and accept UAC
3. Follow the wizard (optional: desktop icon, CLI on PATH)
4. Launch **NetShaper** from the Finish page or Start Menu

### Portable zip (no installer)

1. Download **NetShaper-*-win-x64.zip** from [Releases](https://github.com/ksanjeev284/NetShaper/releases)
2. Unzip anywhere
3. Right-click **`Setup.cmd`** → **Run as administrator**
4. Choose **[1] Install app** (or **[4]** for PATH + WinDivert + start)
5. Start **NetShaper** from the Desktop / Start Menu and accept UAC

See `GETTING-STARTED.txt` inside the zip.

### Your first limit

1. **Live traffic** — wait 1–2 seconds for rates to appear  
2. Right-click an app → **Limit…** (or use Rules / Limits)  
3. Click **Apply all** (Administrator)  
4. Default shaper mode is **Soft** (QoS + soft pulse). Modes: Soft · QoS · Aggressive · Packet (WinDivert)

Without admin you can still store rules and watch traffic; WFP/QoS enforcement needs elevation.

### From source (developers)

```powershell
git clone https://github.com/ksanjeev284/NetShaper.git
cd NetShaper
dotnet build
dotnet run --project NetShaper.Gui
```

Or build + install system-wide:

```powershell
# Admin PowerShell
powershell -ExecutionPolicy Bypass -File scripts\install-app.ps1 -AddToPath
# options: -WinDivert  -InstallService  -StartApp
```

### CLI examples

```powershell
# After install with PATH, or use full path to cli\NetShaper.Cli.exe
NetShaper.Cli.exe sample 2
NetShaper.Cli.exe limit chrome 500
NetShaper.Cli.exe priority chrome high
NetShaper.Cli.exe quota steam 2048
NetShaper.Cli.exe lockdown on
NetShaper.Cli.exe profile list
NetShaper.Cli.exe apply-all --persist   # ADMIN
```

Policy lives in the **active profile** under `%ProgramData%\NetShaper\profiles\` (mirrored to `policy.json` for the service/CLI).

### Maintainers: GUI installer + zip + GitHub release

```powershell
# GUI Setup.exe only (Inno Setup 6 required)
powershell -ExecutionPolicy Bypass -File scripts\build-installer.ps1

# Full pipeline: tests, zip, Setup.exe, git push, GitHub release
powershell -ExecutionPolicy Bypass -File scripts\release.ps1
```

---

## Optional components

| Component | Purpose |
|-----------|---------|
| **WinDivert** | Packet-mode smooth rate limiting — `scripts\install-windivert.ps1` |
| **Windows Service** | Background host — `scripts\install-service.ps1` |
| **WFP callout driver** | Optional kernel path — see `driver\README.md` (WDK required) |
| **mTLS remote API** | Multi-client HTTPS — `scripts\generate-certs.ps1` |

---

## Architecture (high level)

```
NetShaper.Gui      → WPF desktop app
NetShaper.Core     → Policy, WFP, QoS, stats, traffic sampling, API
NetShaper.Cli      → Command-line automation
NetShaper.Service  → Windows Service host
driver/            → Optional KMDF WFP callout (sources only)
```

Traffic sampling uses IP Helper tables, TCP EStats (when elevated), and NIC-share attribution so rates remain useful without a third-party kernel driver.

---

## Privacy & security

- Policy and stats live under `%ProgramData%\NetShaper\` on your machine  
- Local API binds to loopback with an API key by default  
- No telemetry built into NetShaper  
- Optional remote API uses mutual TLS (see `packaging/CERTIFICATES.md`)

---

## Contributing

Issues and pull requests are welcome. Please keep changes focused and test with `scripts\feature-smoke-test.ps1` when possible.

---

## License

**MIT** — see [LICENSE](LICENSE).

Optional Packet mode depends on **WinDivert** (LGPL v3). Install separately; NetShaper does not redistribute WinDivert binaries in the default repo layout.

---

## Support

- Open a GitHub Issue for bugs and feature requests  
- Run elevated for WFP / QoS / full rate accuracy  

**NetShaper** — free Windows bandwidth limiter and traffic control. Shape your network.
