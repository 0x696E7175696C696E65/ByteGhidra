# Destiny 2 Private Server

Full-stack private server for Destiny 2 — Tier 1 (solo/offline) and Tier 2 (multiplayer).

🇺🇸 **English** | [🇧🇷 Português (Brasil)](README_pt-BR.md)

---

## Confirmed Architecture (via binary RE)

```
┌─────────────────────────────────────────────────────────────┐
│  Destiny 2 Client                                            │
│   HTTP stack: libcurl (static) + SChannel TLS backend       │
│   DNS:  WS2_32::getaddrinfo → hosts file intercept ✓        │
│   TLS:  CRYPT32::CertEnumCertificatesInStore → Win cert store│
│   Port: connects to :443 → netsh portproxy → :8443          │
│   Auth: OAuth loopback, bap_connection binds to port 0      │
│   UDP:  separate raw WS2_32 layer (game state packets)      │
└──────────────┬──────────────────────────────┬───────────────┘
               │ HTTPS :443 → :8443            │ UDP :7777
               ▼                               ▼
  ┌─────────────────────┐           ┌──────────────────────┐
  │  API Server          │           │  UDP Relay            │
  │  api/bungie_api.py   │           │  relay/udp_relay.py   │
  │  Flask + SQLite      │           │  blind packet forward │
  │  port 8443           │           │  port 7777            │
  └─────────────────────┘           └──────────────────────┘

Traffic redirect (proxy/winhttp_proxy.py — requires Admin):
  Step 1 — hosts file  : *.bungie.net → 127.0.0.1  (DNS level)
  Step 2 — netsh proxy : 127.0.0.1:443 → 127.0.0.1:8443  (port level)

patch/driver_patcher/bin/x64/Release/d2_driver_patcher.exe — patches running game process through the loaded driver (requires Admin):
  • Fakes g_user_session (auth bypass)
  • Disables kill switches (all 512 feature gates)
  • Sets xgameruntime_ready flag
  • Disables DLC license check → inserts fake entitlement 0xe0200001
```

---

## Pre-Flight Checklist

Run these **once** before your first launch (all as Administrator):

```
[ ] 1. python patch\gen_certs.py          # generate TLS cert + install to Trusted Root
[ ] 2. python db\manifest_manager.py download --api-key <your_key>  # ~200MB, one time
[ ] 3. ipconfig /flushdns                 # flush DNS cache after first hosts injection
```

---

## Quick Start

### Install
```bash
pip install flask cryptography psutil pyqt6
```

### Tier 1 — Solo / Offline
```bash
# As Administrator (required for hosts + portproxy + cert)
python server.py --tier1

# After Destiny 2 reaches the login screen:
patch\driver_patcher\bin\x64\Release\d2_driver_patcher.exe
```

### Tier 2 — Full Multiplayer
```bash
python server.py --tier2
patch\driver_patcher\bin\x64\Release\d2_driver_patcher.exe
```

### GUI (optional)
```bash
python gui.py
```

---

## How Each Component Works

### Traffic Redirect (`proxy/winhttp_proxy.py`)

Confirmed via binary RE: the game uses **libcurl statically linked** with the **Windows SChannel TLS backend** (`schannel:` debug strings in FUN_7ff7115f2480). DNS is resolved via `WS2_32::getaddrinfo` — the system hosts file intercepts at the DNS level.

Two steps are required:
```
1. hosts file:
   # Bungie REST API + OAuth
   127.0.0.1  platform.bungie.net
   127.0.0.1  www.bungie.net
   127.0.0.1  oauth.bungie.net
   127.0.0.1  stats.bungie.net
   # Bungie internal signon server (CRITICAL — hit BEFORE bungie.net)
   127.0.0.1  signon2.gravityshavings.net
   127.0.0.1  www1.signon2.gravityshavings.net
   127.0.0.1  www2.signon2.gravityshavings.net

2. netsh portproxy:  127.0.0.1:443 → 127.0.0.1:8443
   (game connects to :443 by default for HTTPS)
```

**⚠️ Critical:** `gravityshavings.net` is Bungie's **internal signon server**, discovered via RE of `signon_platform_s_build_s` @ `7ff7102ea8e0`. The game calls:
```
https://www[1|2].signon2.gravityshavings.net/SignOn?platform=xbox&build=<version>
```
This is the **very first HTTP call at startup** — before any platform.bungie.net requests. Without this redirect the game hangs immediately at launch.
Both are automated by `proxy/winhttp_proxy.py`. Cleanup happens automatically on Ctrl+C via `atexit`.

### TLS Certificates (`patch/gen_certs.py`)

SChannel TLS uses `CRYPT32::CertEnumCertificatesInStore` (confirmed in `FUN_7ff7115f5850`) — it reads from the **Windows certificate store**. Installing a self-signed cert to Windows Trusted Root is sufficient.

```bash
python patch\gen_certs.py   # generates cert + installs via certutil
```

Covers SANs: `platform.bungie.net`, `www.bungie.net`, `oauth.bungie.net`, `*.bungie.net`, `localhost`, `127.0.0.1`

### OAuth Flow

The game uses a **BAP (Bungie Application Platform) connection** that binds a TCP listener to **port 0** (OS assigns a free dynamic port). It passes the actual port in the `redirect_uri` query parameter when opening the OAuth URL.

Our server:
1. Intercepts `GET /en/OAuth/Authorize?...&redirect_uri=http://127.0.0.1:<dynamic>/callback`
2. Reads the `redirect_uri` from params
3. Immediately redirects to `redirect_uri?code=<fake_code>&state=<state>`
4. Game's BAP listener on the dynamic port receives the code
5. Game POSTs to `/Platform/App/OAuth/Token/` — we return a fake access token

No hardcoded port needed. No browser interaction needed. Fully automated.

### Memory Patches (`patch/driver_patcher/.../d2_driver_patcher.exe`)

All RVAs **confirmed via Ghidra MCP read-only analysis**:

| Global | RVA | Xrefs | What to write |
|---|---|---|---|
| `g_user_session` | `0x1d72f90` | 65+ | Fake token ptr at +0x108, user_id=1 at +0x5c0 |
| `g_killswitch_registry` | `0x1fa33c0` | 19 | Set 512 uint32s at +0x19808 to value 5 |
| `xgameruntime_ready` | `0x2f235a8` | 5 | Write byte `1` |
| `license_suppression` | `0x1fcf410` | 5 | Write byte `1` ← disables checks |
| `g_dlc_state` | `0x1fcf428` | — | DLC container pointer |

**License suppression logic** (confirmed via `is_license_check_enabled @ 7ff710ef3790`):
```c
// Returns 0 = checks DISABLED (DLC granted) when *ptr != 0
// Returns 1 = checks ENABLED  (DLC blocked) when *ptr == 0
if (*param_1 != '\0') return 0;  // write 1 here → all DLC unlocked
return 1;
```
When checks are disabled, the game automatically inserts fake entitlement `0xe0200001` (all DLC owned).

### Manifest (`db/manifest_manager.py`)

The manifest is a ~200MB SQLite database downloaded from Bungie CDN on every game startup. It contains all item definitions, activity hashes, vendor layouts, etc. Without it, item names/icons are blank and loading screens may stall.

```bash
# Download once (public endpoint, no OAuth needed)
python db\manifest_manager.py download --api-key b024a73245664547ac211e2eb374068f

# Check status
python db\manifest_manager.py status

# Query an item by hash
python db\manifest_manager.py query --hash 1363886209 --table InventoryItem
```

The server automatically serves the manifest and all content files locally when the game requests them.

---

## API Endpoints

### Implemented
| Endpoint | Method | Description |
|---|---|---|
| `/SignOn` | GET/POST | **First call at launch** — `signon2.gravityshavings.net/SignOn?platform=&build=` |
| `/tigerheart_version` | GET | **Required at startup** — login stalls without it |
| `/en/OAuth/Authorize` | GET | Auto-authorizes, no browser needed |
| `/Platform/App/OAuth/Token/` | POST | Issues fake access + refresh tokens |
| `/Platform/User/GetCurrentBungieNetUser/` | GET | Current user info |
| `/Platform/User/GetMembershipsForCurrentUser/` | GET | Membership list |
| `/Platform/User/GetMembershipsById/<id>/<type>/` | GET | By membership ID |
| `/Platform/User/GetLinkedProfiles/<id>/` | GET | Cross-save profiles |
| `/Platform/Destiny2/Manifest/` | GET | Manifest index (local) |
| `/Platform/Destiny2/<type>/Profile/<id>/` | GET | Full profile + components |
| `/Platform/Destiny2/Actions/Items/TransferItem/` | POST | Vault transfers |
| `/Platform/Destiny2/Actions/Items/EquipItem/` | POST | Equip item |
| `/Platform/Destiny2/Actions/Items/EquipItems/` | POST | Equip batch |
| `/Platform/Destiny2/Actions/Items/SetItemLockState/` | POST | Lock/unlock |
| `/Platform/Destiny2/Actions/Loadouts/SnapshotLoadout/` | POST | Save loadout |
| `/Platform/Destiny2/Actions/Loadouts/EquipLoadout/` | POST | Equip loadout |
| `/Platform/Destiny2/Milestones/` | GET | Weekly milestones |
| `/Platform/Destiny2/GetAvailableLocales/` | GET | Language list |
| `/Platform/GroupV2/User/...` | GET | Clan membership |
| `/Platform/Social/Friends/` | GET | Friends list |
| `/Platform/FireteamFinder/...` | GET/POST | Fireteam finder |
| `/Platform/<path:path>` | ALL | Catch-all stub (returns empty `{}`) |

### Profile Components Supported
`100` Profile, `102` ProfileInventory, `200` Characters, `201` CharacterInventories,
`205` CharacterEquipment, `300+` Item instances (stub)

---

## Current Status

### What Works
- ✅ TLS redirect (libcurl + SChannel + Windows cert store)
- ✅ DNS redirect (hosts file → getaddrinfo)
- ✅ Port redirect (netsh portproxy 443 → 8443)
- ✅ OAuth auto-authorize (no browser, no user input)
- ✅ Token issuance and auth flow
- ✅ Profile API with character/inventory data
- ✅ Manifest download and local serving
- ✅ Memory patcher with confirmed RVAs
- ✅ Kill switch bypass (512 gates)
- ✅ DLC license bypass (fake entitlement 0xe0200001)
- ✅ GUI control panel

### Still Needed
- ⏳ First boot + 404 log harvest (run game, collect unknown endpoints)
- ⏳ Fix unknown endpoints from log (typically 10-20 stubs needed)
- ⏳ Seed real item hashes for starter gear
- ⏳ Multiplayer relay handshake validation (tier 2)

---

## File Structure

```
private_server/
├── server.py                  Master entry point
├── config.py                  Your credentials (gitignored)
├── config.example.py          Template — copy to config.py
├── gui.py                     PyQt6 control panel
│
├── api/
│   └── bungie_api.py          Flask REST API emulator (~700 lines)
│
├── db/
│   └── manifest_manager.py    Manifest downloader, server, query tool
│
├── patch/
│   ├── gen_certs.py           TLS cert generator + Windows store installer
│   ├── patch_memory.py        Compatibility launcher for the C++ patcher
│   └── driver_patcher/        C++ driver-backed runtime memory patcher
│
├── proxy/
│   └── winhttp_proxy.py       Hosts file + netsh portproxy manager
│
└── relay/
    └── udp_relay.py           UDP packet relay (tier 2 multiplayer)
```

---

## Credentials

Get a free Bungie developer API key at https://www.bungie.net/en/Application

Copy `config.example.py` → `config.py` and fill in:
```python
BUNGIE_API_KEY      = "your_api_key_here"
OAUTH_CLIENT_ID     = "your_client_id_here"
OAUTH_CLIENT_SECRET = "your_client_secret_here"
OAUTH_REDIRECT_URL  = "https://localhost:8080/callback"
```

`config.py` is gitignored and will never be committed.

---

## RVA Reference

All addresses are RVAs (add to actual load base, e.g. `base + 0x1d72f90`).

| Symbol | RVA | Confirmed |
|---|---|---|
| `g_user_session` | `0x1d72f90` | ✅ 65+ xrefs |
| `g_killswitch_registry` | `0x1fa33c0` | ✅ 19 xrefs |
| `license_suppression` | `0x1fcf410` | ✅ is_license_check_enabled |
| `xgameruntime_ready` | `0x2f235a8` | ✅ FUN_7ff7116f41fc |
| `g_dlc_state` | `0x1fcf428` | ✅ dlc_entitlement_response_callback |
| `player_login_session_manager` | `0x6f39a0` | ✅ named, 3 callers |
| `http_build_request_url` | `0x6f29e0` | ✅ named, 13 callers |
| `is_license_check_enabled` | `0xef3790` | ✅ named, decompiled |
| `dlc_entitlement_response_callback` | `0xfc62a0` | ✅ named |
| `bap_connection` listener | `0x9516f0` | ✅ dynamic port, TCP |
