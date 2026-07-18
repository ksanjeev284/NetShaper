# Releasing NetShaper

One-command releases after a version bump. All version numbers come from
`Directory.Build.props`.

## Prerequisites (build machine)

| Tool | Why |
|------|-----|
| .NET 8 SDK | build / publish |
| Git + GitHub CLI (`gh auth login`) | push + release |
| [Inno Setup 6](https://jrsoftware.org/isinfo.php) | GUI `Setup.exe` (`winget install JRSoftware.InnoSetup`) |

## Every release

```powershell
cd NetShaper

# 1) Bump version (pick one)
powershell -ExecutionPolicy Bypass -File scripts\bump-version.ps1 -Patch   # 0.4.2 -> 0.4.3
# powershell -File scripts\bump-version.ps1 -Minor
# powershell -File scripts\bump-version.ps1 -Version 1.0.0

# 2) Preflight: scrub, build, CLI, feature smoke, zip, Setup.exe
powershell -ExecutionPolicy Bypass -File scripts\preflight.ps1

# 3) Full release: re-test, publish, commit, push, GitHub release (zip + Setup.exe)
powershell -ExecutionPolicy Bypass -File scripts\release.ps1
```

### Dry run (no git / no GitHub)

```powershell
powershell -ExecutionPolicy Bypass -File scripts\release.ps1 -SkipPush
```

### Skip tests (emergency only)

```powershell
powershell -ExecutionPolicy Bypass -File scripts\release.ps1 -SkipTests
```

## What `release.ps1` does

1. Scrub forbidden branding terms  
2. Ensure GUI `requireAdministrator` + version in manifest  
3. `dotnet build` + CLI smoke + `feature-smoke-test.ps1`  
4. `publish.ps1` → `dist\NetShaper-<ver>-win-x64.zip`  
5. `build-installer.ps1` → `dist\NetShaper-Setup-<ver>.exe`  
6. Smoke published CLI  
7. `git commit` + `push` + `gh release create` with **both** zip and Setup.exe  

## Artifacts users download

| File | Audience |
|------|----------|
| `NetShaper-Setup-<ver>.exe` | Most users (wizard) |
| `NetShaper-<ver>-win-x64.zip` | Portable / power users |

## Individual scripts

| Script | Purpose |
|--------|---------|
| `bump-version.ps1` | Edit Directory.Build.props (+ MSIX / ISS defaults) |
| `preflight.ps1` | Full validation without publishing to GitHub |
| `publish.ps1` | Self-contained win-x64 zip only |
| `build-installer.ps1` | Inno GUI installer |
| `feature-smoke-test.ps1` | Feature matrix → `dist\FEATURE-TEST-REPORT.md` |
| `release.ps1` | End-to-end release |

## After release

Confirm: https://github.com/ksanjeev284/NetShaper/releases

Checklist:

- [ ] Setup.exe downloads and runs (UAC → wizard → install)  
- [ ] Zip has Setup.cmd / Install.ps1  
- [ ] App version in About / file properties matches tag  
