# Proton WireGuard Rotator

Script to automate the process of generating ProtonVPN WireGuard configs and rotating them

## Overview

- Logs into ProtonVPN with Selenium only and stores the Proton web session in `.pvpn_session.json`.
- Caches Proton server metadata in `.logicals.json`.
- Writes WireGuard configs to `configs/`.
- Writes `wireproxy` configs and port maps to `proxies/`.
- Rotates active proxy processes with `rotate-proxies`.

## Modes

`get` creates one Proton WireGuard certificate per requested server.

```powershell
.\.venv\Scripts\python.exe .\proton_wg.py get SG#20 SE-JP#1
```

`bulk` creates many per-server certificates from filters. This can hit Proton
rate limits.

```powershell
.\.venv\Scripts\python.exe .\proton_wg.py bulk --tier 2 --feature P2P --max 20
```

`roam` creates one master certificate, then builds configs locally for many
servers by changing only the WireGuard peer public key and endpoint.

```powershell
.\.venv\Scripts\python.exe .\proton_wg.py roam --all --tier 2 --feature P2P
```

`roam --socks` emits `wireproxy` configs with local SOCKS5/HTTP ports.

```powershell
.\.venv\Scripts\python.exe .\proton_wg.py roam --all --tier 2 --feature P2P --socks
```

`rotate-proxies` keeps only a batch of `wireproxy.exe` processes running and
cycles through `proxies/ports.json`.

```powershell
.\.venv\Scripts\python.exe .\proton_wg.py rotate-proxies --batch-size 20
.\.venv\Scripts\python.exe .\proton_wg.py rotate-proxies --loop --batch-size 20 --interval 900
.\.venv\Scripts\python.exe .\proton_wg.py rotate-proxies --stop
```

## Required Environment

```powershell
$env:PVPN_USER = "you@example.com"
$env:PVPN_PASS = "your-password"
$env:PYTHONWARNINGS = "ignore"
```