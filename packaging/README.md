# Packaging

Ways to ship NetShaper to end users. Version always comes from `Directory.Build.props`
via `scripts\Get-Version.ps1`.

## 1. Portable ZIP (default / recommended)

```powershell
powershell -ExecutionPolicy Bypass -File scripts\publish.ps1
# → dist\NetShaper-<version>-win-x64.zip
# → dist\NetShaper-win-x64\   (includes Setup.cmd, Install.ps1, GETTING-STARTED.txt)
```

End users: unzip → right-click **Setup.cmd** → Run as administrator → **[1] Install app**.

Dev install from published folder (admin):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install-app.ps1 -SkipPublish
```

## 2. GUI installer (Inno Setup) — recommended for users

Requires [Inno Setup 6](https://jrsoftware.org/isinfo.php) on the **build machine** only.

```powershell
winget install --id JRSoftware.InnoSetup -e   # once
powershell -ExecutionPolicy Bypass -File scripts\build-installer.ps1
# → dist\NetShaper-Setup-<version>.exe   (single wizard EXE with all files inside)
```

Script: `scripts\NetShaper.iss` (version from Directory.Build.props via `/DMyAppVersion=`).

End users only need the Setup.exe — double-click, Next, Finish.

## 3. MSIX (sideload)

Requires **Windows SDK** (`makeappx.exe`, optionally `signtool.exe`).

```powershell
# Stage + pack; -SelfSign uses ensure-codesign-cert.ps1 for local test
powershell -ExecutionPolicy Bypass -File scripts\build-msix.ps1 -SelfSign
# → dist\NetShaper-<version>-x64.msix
```

## 4. Full test + GitHub release

```powershell
powershell -ExecutionPolicy Bypass -File scripts\release.ps1
```

Runs scrub, build, CLI smoke, feature smoke, publish, zip checks, git push, `gh release`.

## Certificates / signing

See `CERTIFICATES.md` in this folder.
