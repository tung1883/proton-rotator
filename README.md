# proton_wg.py - on-demand ProtonVPN WireGuard configs

Creates a WireGuard certificate for a server **only the first time you ask for it**,
caches `configs/wg-<SERVER>.conf` locally, and reuses that file forever after.
The Proton web session is cached too (`.pvpn_session.json`), so repeat calls skip
the browser login entirely (~0.1s for an all-cached request).

Adapted from https://doncharisma.org/2025/04/03/batch-download-protonvpn-wireguard-configs-python/
(FuseTim / DonCharisma). **Tested working 2026-09-04** on a paid account.

## Setup (done)

- Python 3.12 venv at `.venv`, deps in `requirements.txt`
- Firefox 154, geckodriver auto-managed
- non-obvious dep pins that were required: `blinker==1.7.0`, `setuptools<81`,
  `packaging`, `pyopenssl==22.1.0`, `cryptography==38.0.4`
  (newer pyopenssl/cryptography break selenium-wire's TLS interception)

## Use

```powershell
cd C:\Users\Tung\Documents\work\proton-wg
$env:PVPN_USER = 'you@example.com'
$env:PVPN_PASS = 'your-password'
$env:PYTHONWARNINGS = 'ignore'
$py = '.\.venv\Scripts\python.exe'

# get a config for one or more servers (creates cert on first ask, cached after)
& $py .\proton_wg.py get SG#20 SE-JP#1 US-NY#12

# find server names
& $py .\proton_wg.py search tokyo
& $py .\proton_wg.py search us

# what's cached locally
& $py .\proton_wg.py list

# batch, one cert per server (rate-limited by Proton after ~tens)
& $py .\proton_wg.py bulk --tier 2 --feature P2P --country JP SG --max 20
& $py .\proton_wg.py bulk --feature P2P --list        # preview only

# ROAM: one registered cert, every config built locally, NO rate limit
& $py .\proton_wg.py roam SE-JP#1 SG#20 US-NY#12
& $py .\proton_wg.py roam --all --tier 2 --feature P2P      # thousands, seconds

# session
& $py .\proton_wg.py whoami        # is the cached session still valid?
& $py .\proton_wg.py login         # force a fresh browser login
```

Server name forms accepted: `SG#20`, `sg#20`, `sg-20`, Secure Core `SE-JP#1`.

### Per-cert options (apply to configs created in that run)

`--netshield {0,1,2}` · `--port-forwarding` · `--moderate-nat` · `--no-accelerator`
· `--delay SECONDS` (gap between creations). Defaults: NetShield off, port
forwarding off, VPN Accelerator on. Change the baked-in defaults in
`CONFIG_FEATURES` at the top of `proton_wg.py`.

## roam mode (experimental)

`bulk`/`get` register one certificate per server -> Proton rate-limits after tens.
`roam` registers **one** cert (`.pvpn_master.json`, valid 1 year) and then writes
every `.conf` locally: same private key, only the `[Peer]` block (server public
key + endpoint) changes - taken from the cached server list. No per-server API
call, so no rate limit. This is how the Proton app itself hops servers.

**Verified working 2026-09-04.** Master cert was registered against `SE-JP#1`;
the roamed `wg-SG-20.conf` connected fine and exited in Singapore
(`curl ipinfo.io` -> `103.216.223.41`, SG). Proton does not bind the key to its
anchor server - same as how the app roams. Peer data roam writes is also
byte-identical to the per-server register API response (checked SG#20, KR#14,
SE-JP#1).

## Per-app tunneling with wireproxy

WireGuard routes by destination IP, never by process. To send *specific apps*
through Proton (and leave everything else direct), use wireproxy: a userspace
WireGuard that exposes a local SOCKS5 proxy. No admin, no system routing change,
and you can run several at once - one server per proxy port.

```powershell
# generate wireproxy configs (adds a [Socks5] section, one port per server)
& $py .\proton_wg.py roam SG#20 SE-JP#1 US-NY#12 --socks
#   SG#20     socks5 127.0.0.1:25344
#   SE-JP#1   socks5 127.0.0.1:25345
#   US-NY#12  socks5 127.0.0.1:25346
```

Files land in `proxies/` (`wg-<S>.conf`, `ports.json`, `run-all.cmd`).
`--socks 30000` sets a different base port.

### One-time: get the wireproxy binary

`bin\wp.tar.gz` is already downloaded and its SHA-256 verified against the
project's `checksums.txt`
(`bce041ea9fe0f8a3351301dcbe29cdf6a523bb25cf9c62f17ebb5699a8051d0f`). Extract it:

```powershell
cd C:\Users\Tung\Documents\work\proton-wg\bin
tar -xzf wp.tar.gz          # -> wireproxy.exe
.\wireproxy.exe --version
```

Source: https://github.com/windtf/wireproxy (formerly pufferffish/wireproxy).

### Run

```powershell
# one server:
bin\wireproxy.exe -c proxies\wg-SG-20.conf
# all of them, each in its own window:
proxies\run-all.cmd
```

Verified 2026-09-04: `wireproxy -c proxies/wg-SG-20.conf` +
`curl --proxy socks5h://127.0.0.1:25344 ipinfo.io` -> exits in Singapore, host
traffic unaffected.

Then point an app at the proxy: `socks5://127.0.0.1:25344`. Examples:
- curl: `curl.exe --proxy socks5h://127.0.0.1:25344 https://ipinfo.io/json`
- Firefox: Settings -> Network -> Manual proxy, SOCKS5 host `127.0.0.1` port `25344`
- Chrome: launch with `--proxy-server="socks5://127.0.0.1:25344"`
- system-wide per-app: Proxifier / ProxiFyre pointing at the port

"App A via Singapore, App B via Japan" = run both proxy configs, point each app
at its own port.

## Node integration note (Downloads\node)

The Node pipeline (`Downloads\node`) no longer uses `rotate-proxies` /
`PROXY_HTTP_PORTS.txt` at all. Its `src/core/proxyPool.js` manages wireproxy
processes itself, on demand: on a create-attempt failure it picks a server
this pool hasn't used yet (from `proxies/ports.json`), spawns wireproxy for it
if not already running (detached, survives past the `node` process, reused by
later runs), and resets the used-list once every server has been touched.
State in `Downloads\node\.proxy_state.json`. Don't run `rotate-proxies --loop`
at the same time as that pipeline - both would try to manage the same
processes/ports independently. `rotate-proxies` is still there as a
standalone tool for anything else that wants a rotating batch of exit IPs.

## Using all 146 countries without running 146 processes: `rotate-proxies`

`roam --all --tier 2 --feature P2P --per-country 1 --socks` builds one proxy
config per country (146). Running all of them at once works but is heavy
(~146 background processes). `rotate-proxies` instead keeps only a small batch
alive at a time and cycles through the rest automatically:

```powershell
# one-shot: stop current batch, start the next N, advance the cycle
& $py .\proton_wg.py rotate-proxies --batch-size 20
& $py .\proton_wg.py rotate-proxies --reset          # restart the cycle from server #1
& $py .\proton_wg.py rotate-proxies --stop           # stop the batch, start nothing

# fully automatic: keep swapping forever until Ctrl+C
& $py .\proton_wg.py rotate-proxies --loop --batch-size 20 --interval 900
```

Each call/tick: kills the previous batch's exact PIDs (`CREATE_NO_WINDOW`, no
visible windows), starts the next slice of `proxies\ports.json`, and rewrites
`proxies\PROXY_HTTP_PORTS.txt` with the live batch's http ports. Progress is
tracked (`N/146 distinct servers used so far this cycle`) and resets when a
full cycle completes.

**Node picks up each swap live, no restart needed:** `proxyPool.js` reads
`PROXY_HTTP_PORTS.txt` directly (re-checked every `PROXY_PORTS_RELOAD_MS`,
default 15s) instead of a frozen env var. So the flow is just:

```powershell
# terminal 1 - leave running (or use Task Scheduler to run it periodically)
& $py .\proton_wg.py rotate-proxies --loop --batch-size 20

# terminal 2 - runs normally, automatically using whichever batch is currently live
cd C:\Users\Tung\Downloads\node
node --env-file=.env createJobs.js --folder=all --command=all
node --env-file=.env processQueue.js
```

`PROXY_HTTP_PORTS` in `.env` is now only a static fallback for if the file
can't be read.

**Verified 2026-09-04:** `--loop --interval 6` swapped batches 4 times in 20s,
correctly killing the previous 3 PIDs each time and advancing `seen` from 0 to
12; both a single proxy and two simultaneous proxies (different servers, same
shared roamed key) round-tripped real requests correctly.

**Bug found + fixed during this:** `roam --socks` was computing new port
numbers every run but skipping the file rewrite for servers whose `.conf`
already existed - so `ports.json` and the actual file could disagree, causing
silent connection failures. `--socks` mode now always rewrites the file.

## How it decides to hit the API

| situation | what happens |
|-----------|--------------|
| `configs/wg-<S>.conf` exists | printed as `cached`, nothing else |
| file missing, session cached & valid | 2 API calls (keypair + register), write file |
| session missing/expired | one headless Firefox login, cache session, then as above |
| server list older than 6h | refetched once (`.logicals.json`); force with `--refresh` |

## Caveats

- **No 2FA / captcha support** - Selenium login is password-only. Enabling 2FA
  breaks this tool.
- Each created config = one certificate on your Proton account (see them under
  account.protonvpn.com -> Downloads -> WireGuard configuration; revoke there).
  Certs expire 1 year out; re-run `get --force <S>` to replace an expired one.
- Proton rate-limits bulk creation (~tens, then a cooldown). `bulk` sleeps
  `--cooldown` seconds (default 1200) and re-logs in on a 429; `get` just stops
  so you can re-run later.
- `.pvpn_session.json` holds a live session token and `configs/*.conf` hold
  private keys - both are chmod 600, keep them off any sync/git.
- Undocumented Proton API - may break on any site change.
- Setup/testing created several throwaway certs on the account (names like
  `wg-KR#14`, `wg-SG#20`, `claude-pipe-KR#14`, plus one real master `wg-SE-JP#1`).
  Bulk-revoke the ones you don't want under account.protonvpn.com -> Downloads ->
  WireGuard configuration. Keep the master (`wg-SE-JP#1`) if you use `roam`.
- `configs/` currently holds roamed configs for SE-JP#1, SG#20, DE#1.
