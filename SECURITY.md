# Security Policy

## Supported versions

Use the latest release from this repository when possible.

## Reporting a vulnerability

Please open a **private** security advisory on GitHub, or contact the maintainers via a confidential channel. Do not file public issues for unpatched remote-code or privilege-escalation bugs.

## Scope notes

- NetShaper requires elevated privileges for WFP filters, QoS, and some rate measurements. That is by design for traffic control on Windows.
- Treat API keys and certificate PFX files as secrets. Rotate them if exposed.
- Optional third-party components (e.g. WinDivert) have their own licenses and security models.
