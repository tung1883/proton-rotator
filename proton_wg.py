#!/usr/bin/env python3
"""
proton_wg.py - on-demand ProtonVPN WireGuard config fetcher with local cache.

Creates a WireGuard certificate for a server only the first time you ask for it,
writes configs/wg-<SERVER>.conf, and reuses that file on every later request.
The Proton web session is cached too, so repeated calls skip the browser login.

Commands:
  python proton_wg.py get JP#5 US-NY#12 ...   # ensure a .conf exists for each
  python proton_wg.py list                    # show locally cached configs
  python proton_wg.py search tokyo            # find server names (logicals list)
  python proton_wg.py bulk --tier 2 --feature P2P --max 25   # batch create
  python proton_wg.py login                   # force a fresh browser login
  python proton_wg.py whoami                  # check the cached session

Credentials: env vars PVPN_USER / PVPN_PASS (or edit DEFAULT_USER/DEFAULT_PASS).
No 2FA / captcha support. Undocumented Proton API - may break on site changes.
Original approach: FuseTim 2024 / DonCharisma.org 2025. MIT / Apache-2.0.
"""
import argparse
import base64
import hashlib
import http.client
import json
import os
import re
import subprocess
import sys
import time
from datetime import date, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
API_HOST = "account.protonvpn.com"

DEFAULT_USER = "your_protonvpn_username"
DEFAULT_PASS = "your_protonvpn_password"

OUTPUT_DIR = os.path.join(HERE, "configs")
SESSION_FILE = os.path.join(HERE, ".pvpn_session.json")
LOGICALS_CACHE = os.path.join(HERE, ".logicals.json")
LOGICALS_MAX_AGE = 6 * 3600           # refetch server list if older than this

PLATFORM = "Windows"                  # "Linux"/"Router" -> LF newlines, else CRLF
CONFIG_PREFIX = "wg"
SCOPE_SETTLE_SECONDS = 8

# defaults baked into every generated cert; override per run with bulk flags
CONFIG_FEATURES = {
    "SafeMode": False,
    "SplitTCP": True,        # VPN Accelerator
    "PortForwarding": False,  # NAT-PMP / port forwarding
    "RandomNAT": False,       # Moderate NAT
    "NetShieldLevel": 0,     # 0 off, 1 malware, 2 malware+ads+trackers
}
FEATURE_MASK = {"SecureCore": 1, "TOR": 2, "P2P": 4, "XOR": 8, "IPv6": 16}


def creds():
    u = os.environ.get("PVPN_USER", DEFAULT_USER)
    p = os.environ.get("PVPN_PASS", DEFAULT_PASS)
    if u == DEFAULT_USER or p == DEFAULT_PASS:
        sys.exit("Set PVPN_USER and PVPN_PASS (env vars) or edit DEFAULT_USER/DEFAULT_PASS.")
    return u, p


def norm_server(name):
    """'jp-5' / 'jp#5' / 'JP#5' -> 'JP#5'. Secure Core 'se-jp#1' -> 'SE-JP#1'."""
    s = name.strip().upper().replace("_", "-")
    s = re.sub(r"-(\d+)$", r"#\1", s)
    return s


def _chmod600(path):
    try:
        os.chmod(path, 0o600)
    except (PermissionError, NotImplementedError, OSError):
        pass


# --------------------------------------------------------------------------
# Selenium login (only when there is no valid cached session)
# --------------------------------------------------------------------------
def browser_login(user, password):
    from seleniumwire import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException

    opts = webdriver.FirefoxOptions()
    opts.add_argument("-headless")
    d = webdriver.Firefox(options=opts, seleniumwire_options={"disable_encoding": True})
    try:
        d.get("https://account.protonvpn.com/login")
        WebDriverWait(d, 30).until(
            EC.presence_of_element_located((By.ID, "username"))
        ).send_keys(user)
        d.find_element(By.XPATH, "//button[contains(text(),'Continue')]").click()
        WebDriverWait(d, 30).until(
            EC.presence_of_element_located((By.ID, "password"))
        ).send_keys(password)
        d.find_element(By.XPATH, "//button[contains(text(),'Sign in')]").click()
        try:
            WebDriverWait(d, 45).until(EC.url_contains("/dashboard"))
        except TimeoutException:
            raise SystemExit("Login timed out - wrong password, 2FA, or a captcha.")
        time.sleep(SCOPE_SETTLE_SECONDS)

        uid = token = appver = None
        for r in d.requests:
            if not (r.response and "/api/" in r.url):
                continue
            h = r.headers
            ru, ra = h.get("x-pm-uid"), h.get("x-pm-appversion")
            ck = h.get("cookie", "") or ""
            if not (ru and ra and f"AUTH-{ru}=" in ck):
                continue
            m = re.search(rf"AUTH-{re.escape(ru)}=([^;]+)", ck)
            if m:
                uid, token, appver = ru, m.group(1), ra
        if not all((uid, token, appver)):
            raise SystemExit("Logged in but could not capture the session token.")
        return {"uid": uid, "token": token, "appversion": appver, "saved_at": time.time()}
    finally:
        d.quit()


# --------------------------------------------------------------------------
# API client
# --------------------------------------------------------------------------
class Proton:
    def __init__(self, session):
        self.s = session
        self.conn = http.client.HTTPSConnection(API_HOST)

    @property
    def headers(self):
        return {
            "x-pm-appversion": self.s["appversion"],
            "x-pm-uid": self.s["uid"],
            "Accept": "application/vnd.protonmail.v1+json",
            "Cookie": f"AUTH-{self.s['uid']}={self.s['token']}",
        }

    def _req(self, method, path, body=None):
        h = dict(self.headers)
        if body is not None:
            h["Content-Type"] = "application/json"
            body = json.dumps(body)
        self.conn.request(method, path, body=body, headers=h)
        resp = self.conn.getresponse()
        data = resp.read().decode()
        return resp.status, data

    def get(self, path):
        st, data = self._req("GET", path)
        if st != 200:
            raise ApiError(st, f"GET {path} -> {st}: {data[:200]}")
        return json.loads(data)

    def session_valid(self):
        try:
            st, _ = self._req("GET", "/api/vpn/v1/certificate/key/EC")
            return st == 200
        except OSError:
            self.conn = http.client.HTTPSConnection(API_HOST)
            return False

    def logicals(self):
        return self.get("/api/vpn/logicals")["LogicalServers"]

    def new_keypair(self):
        r = self.get("/api/vpn/v1/certificate/key/EC")
        return {"pub_wg": r["PublicKey"].split("\n")[1],
                "priv_b64": r["PrivateKey"].split("\n")[1]}

    def register(self, server, pub_wg, features):
        body = {
            "ClientPublicKey": pub_wg,
            "Mode": "persistent",
            "DeviceName": f"{CONFIG_PREFIX}-{server['Name']}",
            "Features": {
                "peerName": server["Name"],
                "peerIp": server["Servers"][0]["EntryIP"],
                "peerPublicKey": server["Servers"][0]["X25519PublicKey"],
                "platform": PLATFORM,
                **features,
            },
        }
        st, data = self._req("POST", "/api/vpn/v1/certificate", body)
        if st != 200:
            raise ApiError(st, f"register {server['Name']} -> {st}: {data[:200]}")
        return json.loads(data)


class ApiError(Exception):
    def __init__(self, status, msg):
        super().__init__(msg)
        self.status = status

    @property
    def rate_limited(self):
        return self.status == 429 or "8002" in str(self) or "2028" in str(self)


# --------------------------------------------------------------------------
# session + logicals caching
# --------------------------------------------------------------------------
def load_session():
    if not os.path.exists(SESSION_FILE):
        return None
    try:
        with open(SESSION_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def save_session(session):
    with open(SESSION_FILE, "w") as f:
        json.dump(session, f)
    _chmod600(SESSION_FILE)


def get_client(force_login=False):
    session = None if force_login else load_session()
    if session:
        p = Proton(session)
        if p.session_valid():
            return p
        print("cached session expired; logging in...", file=sys.stderr)
    user, password = creds()
    session = browser_login(user, password)
    save_session(session)
    return Proton(session)


def get_logicals(p, refresh=False):
    if not refresh and os.path.exists(LOGICALS_CACHE):
        age = time.time() - os.path.getmtime(LOGICALS_CACHE)
        if age < LOGICALS_MAX_AGE:
            try:
                with open(LOGICALS_CACHE) as f:
                    return json.load(f)
            except (OSError, ValueError):
                pass
    servers = p.logicals()
    with open(LOGICALS_CACHE, "w") as f:
        json.dump(servers, f)
    return servers


def index_by_name(servers):
    return {s["Name"].upper(): s for s in servers}


# --------------------------------------------------------------------------
# config file writing
# --------------------------------------------------------------------------
def wg_privkey(priv_b64):
    h = bytearray(hashlib.sha512(base64.b64decode(priv_b64)[-32:]).digest()[:32])
    h[0] &= 0xF8
    h[31] = (h[31] & 0x7F) | 0x40
    return base64.b64encode(bytes(h)).decode()


def _render(priv_b64, peer_name, peer_pubkey, peer_ip, features, expires,
            note="", socks_port=None, http_port=None):
    tag = f"  ({note})" if note else ""
    socks = f"\n[Socks5]\nBindAddress = 127.0.0.1:{socks_port}\n" if socks_port else ""
    http = f"\n[http]\nBindAddress = 127.0.0.1:{http_port}\n" if http_port else ""
    return f"""[Interface]
# {peer_name}{tag}   expires {expires}
# NetShield={features['NetShieldLevel']} ModerateNAT={features['RandomNAT']} \
PortForwarding={features['PortForwarding']} VPNAccelerator={features['SplitTCP']}
PrivateKey = {wg_privkey(priv_b64)}
Address = 10.2.0.2/32
DNS = 10.2.0.1

[Peer]
PublicKey = {peer_pubkey}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {peer_ip}:51820
PersistentKeepalive = 25
{socks}{http}"""


def render_config(priv_b64, registration, features, socks_port=None, http_port=None):
    f = registration["Features"]
    exp = f"{(date.today() + timedelta(days=365)):%d-%b-%Y}"
    return _render(priv_b64, f["peerName"], f["peerPublicKey"], f["peerIp"],
                   features, exp, socks_port=socks_port, http_port=http_port)


def render_roamed(master, server, features, socks_port=None, http_port=None):
    """Config built locally from the shared master key + this server's peer data."""
    phys = server["Servers"][0]
    return _render(master["priv_b64"], server["Name"], phys["X25519PublicKey"],
                   phys["EntryIP"], features, master["expires"],
                   note="roamed", socks_port=socks_port, http_port=http_port)


PROXY_DIR = os.path.join(HERE, "proxies")


def conf_path(server_name, base=None):
    base = base or OUTPUT_DIR
    return os.path.join(base, f"{CONFIG_PREFIX}-{server_name.replace('#', '-')}.conf")


def write_conf(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if PLATFORM in ("Linux", "Router"):
        with open(path, "wb") as fh:
            fh.write(text.encode("utf-8").replace(b"\r\n", b"\n"))
    else:
        with open(path, "w", newline="\r\n") as fh:
            fh.write(text)
    _chmod600(path)


def ensure_config(p, server, features, force=False):
    """Return (path, created?) - create the cert only if the file is missing."""
    path = conf_path(server["Name"])
    if os.path.exists(path) and not force:
        return path, False
    kp = p.new_keypair()
    reg = p.register(server, kp["pub_wg"], features)
    write_conf(path, render_config(kp["priv_b64"], reg, features))
    return path, True


# --------------------------------------------------------------------------
# roam mode: one registered cert, all configs built locally (no rate limit)
# --------------------------------------------------------------------------
MASTER_FILE = os.path.join(HERE, ".pvpn_master.json")


def load_master():
    try:
        with open(MASTER_FILE) as f:
            m = json.load(f)
        if date.fromisoformat(m["expires_iso"]) <= date.today():
            return None
        return m
    except (OSError, ValueError, KeyError):
        return None


def ensure_master(p, features, anchor_server):
    m = load_master()
    if m:
        return m, False
    kp = p.new_keypair()
    reg = p.register(anchor_server, kp["pub_wg"], features)
    exp_iso = date.today().replace(year=date.today().year + 1).isoformat()
    m = {
        "priv_b64": kp["priv_b64"],
        "pub_wg": kp["pub_wg"],
        "anchor": anchor_server["Name"],
        "expires_iso": exp_iso,
        "expires": f"{date.fromisoformat(exp_iso):%d-%b-%Y}",
        "saved_at": time.time(),
    }
    with open(MASTER_FILE, "w") as f:
        json.dump(m, f)
    _chmod600(MASTER_FILE)
    return m, True


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------
def features_from_args(args):
    f = dict(CONFIG_FEATURES)
    if getattr(args, "netshield", None) is not None:
        f["NetShieldLevel"] = args.netshield
    if getattr(args, "port_forwarding", False):
        f["PortForwarding"] = True
    if getattr(args, "no_accelerator", False):
        f["SplitTCP"] = False
    if getattr(args, "moderate_nat", False):
        f["RandomNAT"] = True
    return f


def cmd_get(args):
    wanted = [norm_server(x) for x in args.servers]
    missing = [w for w in wanted if not os.path.exists(conf_path(w)) or args.force]
    for w in wanted:
        if w not in missing:
            print(f"cached  {w:<14} {conf_path(w)}")
    if not missing:
        return
    p = get_client(force_login=args.login)
    idx = index_by_name(get_logicals(p, refresh=args.refresh))
    feats = features_from_args(args)
    for w in missing:
        srv = idx.get(w)
        if not srv:
            print(f"UNKNOWN {w:<14} (no such server; try: proton_wg.py search {w.split('#')[0]})")
            continue
        try:
            path, created = ensure_config(p, srv, feats, force=args.force)
            print(f"{'created' if created else 'cached '} {w:<14} {path}")
            if created:
                time.sleep(args.delay)
        except ApiError as e:
            if e.rate_limited:
                print(f"rate limited at {w}; stopping. Re-run later to continue.")
                break
            print(f"ERROR   {w:<14} {e}")


def cmd_list(args):
    if not os.path.isdir(OUTPUT_DIR):
        print("no configs yet")
        return
    files = sorted(f for f in os.listdir(OUTPUT_DIR) if f.endswith(".conf"))
    for f in files:
        full = os.path.join(OUTPUT_DIR, f)
        exp = ""
        try:
            with open(full, encoding="utf-8", errors="replace") as fh:
                m = re.search(r"expires ([0-9A-Za-z-]+)", fh.read(400), re.I)
                if m:
                    exp = "expires " + m.group(1)
        except OSError:
            pass
        print(f"  {f:<24} {exp}")
    print(f"{len(files)} config(s) in {OUTPUT_DIR}")


def cmd_search(args):
    p = get_client(force_login=args.login)
    servers = get_logicals(p, refresh=args.refresh)
    q = args.term.lower()
    hits = [s for s in servers
            if q in s["Name"].lower()
            or q in (s.get("City") or "").lower()
            or q in s["ExitCountry"].lower()
            or q in s["EntryCountry"].lower()]
    hits.sort(key=lambda s: s["Name"])
    for s in hits[: args.limit]:
        feats = [k for k, v in FEATURE_MASK.items() if s["Features"] & v] or ["-"]
        sc = f'{s["EntryCountry"]}->{s["ExitCountry"]}'
        print(f'  {s["Name"]:<14} {sc:<10} tier{s["Tier"]} {(s.get("City") or ""):<16} {",".join(feats)}')
    print(f"{len(hits)} match(es)" + (f", showing {args.limit}" if len(hits) > args.limit else ""))


def cmd_bulk(args):
    p = get_client(force_login=args.login)
    servers = get_logicals(p, refresh=args.refresh)
    feats = features_from_args(args)
    want_feat_mask = FEATURE_MASK.get(args.feature) if args.feature else None

    def keep(s):
        if args.tier is not None and s["Tier"] != args.tier:
            return False
        if args.country and s["ExitCountry"] not in args.country:
            return False
        if want_feat_mask is not None and not (s["Features"] & want_feat_mask):
            return False
        return True

    matches = [s for s in servers if keep(s)]
    print(f"{len(servers)} servers, {len(matches)} match")
    if args.list:
        for s in matches:
            print(f'  {s["Name"]:<14} {s["EntryCountry"]}->{s["ExitCountry"]} tier{s["Tier"]}')
        return
    done = 0
    for s in matches:
        if done >= args.max:
            break
        try:
            path, created = ensure_config(p, s, feats)
            print(f"{'[+]' if created else '[=]'} {s['Name']:<14} {path}")
            done += 1
            if created:
                time.sleep(args.delay)
        except ApiError as e:
            if e.rate_limited:
                wait = args.cooldown
                print(f"rate limited at {s['Name']}; sleeping {wait}s...")
                time.sleep(wait)
                p = get_client(force_login=True)
            else:
                print(f"skip {s['Name']}: {e}")
    print(f"done: {done} new/verified")


def cmd_roam(args):
    wanted = [norm_server(x) for x in args.servers]
    feats = features_from_args(args)
    p = get_client(force_login=args.login)
    servers = get_logicals(p, refresh=args.refresh)
    idx = index_by_name(servers)

    if args.all or not wanted:
        want_feat_mask = FEATURE_MASK.get(args.feature) if args.feature else None
        targets = [s for s in servers
                   if (args.tier is None or s["Tier"] == args.tier)
                   and (not args.country or s["ExitCountry"] in args.country)
                   and (want_feat_mask is None or s["Features"] & want_feat_mask)]
        if args.per_country:
            targets.sort(key=lambda s: s["Name"])
            by_country = {}
            for s in targets:
                bucket = by_country.setdefault(s["ExitCountry"], [])
                if len(bucket) < args.per_country:
                    bucket.append(s)
            targets = [s for bucket in by_country.values() for s in bucket]
    else:
        targets = []
        for w in wanted:
            if w in idx:
                targets.append(idx[w])
            else:
                print(f"UNKNOWN {w}")

    if not targets:
        print("no target servers")
        return

    anchor = next((s for s in servers if s["Tier"] == 2), servers[0])
    master, created = ensure_master(p, feats, anchor)
    print(f"master cert: {'CREATED against ' + master['anchor'] if created else 'reused'}"
          f"  expires {master['expires']}")

    socks = args.socks is not None
    outdir = PROXY_DIR if socks else OUTPUT_DIR
    n = 0
    portmap = {}
    for i, s in enumerate(targets):
        # each server gets a (socks, http) port pair from one running wireproxy process
        socks_port = args.socks + 2 * i if socks else None
        http_port = socks_port + 1 if socks else None
        path = conf_path(s["Name"], base=outdir)
        if socks:
            portmap[s["Name"]] = {"socks": socks_port, "http": http_port}
        # In --socks mode the port numbers are positional and must match ports.json (which is
        # always rewritten below) - an existing file with stale baked-in ports would silently
        # desync from ports.json, so always (re)write when socks is active.
        if os.path.exists(path) and not args.force and not socks:
            continue
        write_conf(path, render_roamed(master, s, feats, socks_port=socks_port, http_port=http_port))
        n += 1
    if socks:
        with open(os.path.join(PROXY_DIR, "ports.json"), "w") as f:
            json.dump(portmap, f, indent=1)
        _write_proxy_runner(portmap)
        http_ports = ",".join(str(v["http"]) for v in portmap.values())
        with open(os.path.join(PROXY_DIR, "PROXY_HTTP_PORTS.txt"), "w") as f:
            f.write(http_ports + "\n")
        if not args.quiet:
            for name, ports in portmap.items():
                print(f"  {name:<14} socks5 127.0.0.1:{ports['socks']}   http 127.0.0.1:{ports['http']}")
        print(f"wrote {n} proxy config(s) ({len(targets)} targets) -> {PROXY_DIR}")
        print("start one:  bin\\wireproxy.exe -c proxies\\wg-<SERVER>.conf")
        print("start all (minimized):  proxies\\run-all.cmd")
        print(f"full PROXY_HTTP_PORTS line saved to proxies\\PROXY_HTTP_PORTS.txt ({len(portmap)} ports)")
    else:
        print(f"wrote {n} roamed config(s) ({len(targets)} targets) -> {OUTPUT_DIR}")


def _write_proxy_runner(portmap):
    lines = ["@echo off", "rem launches every proxy config minimized (no wall of windows)", ""]
    for name in portmap:
        f = f"wg-{name.replace('#', '-')}.conf"
        lines.append(f'start /min "wp {name}" "%~dp0..\\bin\\wireproxy.exe" -c "%~dp0{f}"')
    with open(os.path.join(PROXY_DIR, "run-all.cmd"), "w", newline="\r\n") as fh:
        fh.write("\n".join(lines) + "\n")


WIREPROXY_EXE = os.path.join(HERE, "bin", "wireproxy.exe")
ROTATION_STATE = os.path.join(HERE, ".proxy_rotation.json")
CREATE_NO_WINDOW = 0x08000000


def _load_rotation_state():
    try:
        with open(ROTATION_STATE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"offset": 0, "pids": [], "seen": []}


def _save_rotation_state(state):
    with open(ROTATION_STATE, "w") as f:
        json.dump(state, f)
    _chmod600(ROTATION_STATE)


def _kill_pids(pids):
    for pid in pids:
        subprocess.run(["taskkill", "/PID", str(pid), "/F"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _rotate_once(all_ports, names, total, state, batch_size):
    """Stop the current batch, start the next `batch_size` servers, return new state."""
    print(f"stopping previous batch ({len(state['pids'])} process(es))...")
    _kill_pids(state["pids"])

    batch_size = min(batch_size, total)
    offset = state["offset"] % total
    idx = [(offset + i) % total for i in range(batch_size)]
    batch_names = [names[i] for i in idx]

    pids = []
    for name in batch_names:
        conf = os.path.join(PROXY_DIR, f"wg-{name.replace('#', '-')}.conf")
        proc = subprocess.Popen(
            [WIREPROXY_EXE, "-c", conf],
            creationflags=CREATE_NO_WINDOW,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        pids.append(proc.pid)

    http_ports = [str(all_ports[n]["http"]) for n in batch_names]
    with open(os.path.join(PROXY_DIR, "PROXY_HTTP_PORTS.txt"), "w") as f:
        f.write(",".join(http_ports) + "\n")

    seen = set(state.get("seen", [])) | set(batch_names)
    cycle_done = len(seen) >= total
    new_state = {
        "offset": (offset + batch_size) % total,
        "pids": pids,
        "seen": [] if cycle_done else sorted(seen),
    }

    print(f"batch running: {batch_size} proxies ({', '.join(batch_names[:6])}"
          f"{', ...' if batch_size > 6 else ''})")
    print(f"http ports -> proxies\\PROXY_HTTP_PORTS.txt ({len(http_ports)} ports)")
    if cycle_done:
        print(f"full cycle complete - all {total} servers have been used at least once; restarting the cycle.")
    else:
        print(f"{len(seen)}/{total} distinct servers used so far this cycle")
    return new_state


def cmd_rotate_proxies(args):
    """Run only `--batch-size` wireproxy processes at a time, cycling through every
    server in proxies/ports.json across repeated calls - so all of them get used
    eventually without ever having more than a handful live at once."""
    if not os.path.exists(WIREPROXY_EXE):
        sys.exit(f"wireproxy.exe not found at {WIREPROXY_EXE} - extract bin/wp.tar.gz first")
    try:
        with open(os.path.join(PROXY_DIR, "ports.json")) as f:
            all_ports = json.load(f)
    except (OSError, ValueError):
        sys.exit("proxies/ports.json not found - run `roam --socks` first")

    names = sorted(all_ports)  # deterministic order across calls
    total = len(names)
    if total == 0:
        sys.exit("proxies/ports.json is empty")

    state = _load_rotation_state()

    if args.stop:
        print(f"stopping {len(state['pids'])} process(es), not starting a new batch...")
        _kill_pids(state["pids"])
        offset = 0 if args.reset else state["offset"]
        seen = [] if args.reset else state.get("seen", [])
        _save_rotation_state({"offset": offset, "pids": [], "seen": seen})
        return

    if args.reset:
        _kill_pids(state["pids"])  # reset also stops whatever from the old cycle is still running
        state = {"offset": 0, "pids": [], "seen": []}

    if not args.loop:
        state = _rotate_once(all_ports, names, total, state, args.batch_size)
        _save_rotation_state(state)
        print("run this again later to stop this batch and start the next one.")
        print("Node: $env:PROXY_HTTP_PORTS = (Get-Content proxies\\PROXY_HTTP_PORTS.txt).Trim()")
        return

    print(f"looping: swap batch every {args.interval}s. Ctrl+C to stop (kills the running batch first).")
    print("Node picks up each new batch automatically (proxyPool.js re-reads PROXY_HTTP_PORTS.txt) "
          "- no need to re-set $env:PROXY_HTTP_PORTS or restart node.")
    try:
        while True:
            state = _rotate_once(all_ports, names, total, state, args.batch_size)
            _save_rotation_state(state)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nstopping...")
        _kill_pids(state["pids"])
        state["pids"] = []
        _save_rotation_state(state)
        print("batch stopped. state saved - next `rotate-proxies` continues from here.")


def cmd_login(args):
    user, password = creds()
    save_session(browser_login(user, password))
    print("session cached:", SESSION_FILE)


def cmd_whoami(args):
    s = load_session()
    if not s:
        print("no cached session")
        return
    age = int(time.time() - s.get("saved_at", 0))
    p = Proton(s)
    ok = p.session_valid()
    print(f"uid={s['uid']} appversion={s['appversion']} age={age}s valid={ok}")


def build_parser():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add_common(sp):
        sp.add_argument("--login", action="store_true", help="force a fresh browser login")
        sp.add_argument("--refresh", action="store_true", help="refetch the server list now")

    def add_feature_flags(sp):
        sp.add_argument("--netshield", type=int, choices=[0, 1, 2])
        sp.add_argument("--port-forwarding", action="store_true")
        sp.add_argument("--moderate-nat", action="store_true")
        sp.add_argument("--no-accelerator", action="store_true")
        sp.add_argument("--delay", type=float, default=2.0, help="seconds between creations")

    g = sub.add_parser("get", help="ensure a .conf exists for each server")
    g.add_argument("servers", nargs="+")
    g.add_argument("--force", action="store_true", help="recreate even if cached")
    add_common(g); add_feature_flags(g); g.set_defaults(func=cmd_get)

    l = sub.add_parser("list", help="show cached configs")
    l.set_defaults(func=cmd_list)

    s = sub.add_parser("search", help="find servers by name/city/country")
    s.add_argument("term")
    s.add_argument("--limit", type=int, default=60)
    add_common(s); s.set_defaults(func=cmd_search)

    b = sub.add_parser("bulk", help="batch create by filter")
    b.add_argument("--tier", type=int)
    b.add_argument("--country", nargs="*", help="ExitCountry codes")
    b.add_argument("--feature", choices=list(FEATURE_MASK))
    b.add_argument("--max", type=int, default=25)
    b.add_argument("--cooldown", type=int, default=1200)
    b.add_argument("--list", action="store_true", help="print matches, create nothing")
    add_common(b); add_feature_flags(b); b.set_defaults(func=cmd_bulk)

    r = sub.add_parser("roam", help="1 registered cert, configs built locally (no rate limit)")
    r.add_argument("servers", nargs="*", help="server names; omit + --all for a filtered batch")
    r.add_argument("--all", action="store_true")
    r.add_argument("--tier", type=int)
    r.add_argument("--country", nargs="*", help="ExitCountry codes")
    r.add_argument("--feature", choices=list(FEATURE_MASK))
    r.add_argument("--per-country", type=int, metavar="N",
                   help="keep at most N servers per ExitCountry (e.g. 1 = one server per country)")
    r.add_argument("--force", action="store_true", help="overwrite existing files")
    r.add_argument("--quiet", action="store_true", help="skip the per-server port listing (for large --all runs)")
    r.add_argument("--socks", type=int, metavar="BASEPORT", nargs="?", const=25344,
                   help="emit wireproxy configs into proxies/ with a [Socks5] "
                        "section; port = BASEPORT + index (default base 25344)")
    add_common(r); add_feature_flags(r); r.set_defaults(func=cmd_roam)

    rp = sub.add_parser("rotate-proxies",
                         help="run only a small batch of wireproxy processes at a time, "
                              "cycling through every server in proxies/ports.json over repeated calls")
    rp.add_argument("--batch-size", type=int, default=20, metavar="N",
                     help="max wireproxy processes to keep running at once (default 20)")
    rp.add_argument("--reset", action="store_true", help="restart the cycle from the first server")
    rp.add_argument("--stop", action="store_true", help="stop the current batch, start nothing")
    rp.add_argument("--loop", action="store_true",
                     help="keep running, swapping to the next batch every --interval seconds, "
                          "until Ctrl+C")
    rp.add_argument("--interval", type=int, default=900, metavar="SECONDS",
                     help="seconds between batch swaps in --loop mode (default 900 = 15min)")
    rp.set_defaults(func=cmd_rotate_proxies)

    lg = sub.add_parser("login", help="force a fresh browser login")
    lg.set_defaults(func=cmd_login)

    w = sub.add_parser("whoami", help="check the cached session")
    w.set_defaults(func=cmd_whoami)
    return ap


if __name__ == "__main__":
    args = build_parser().parse_args()
    args.func(args)
