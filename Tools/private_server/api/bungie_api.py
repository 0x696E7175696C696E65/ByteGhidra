"""
Bungie.net REST API Emulator
============================
Implements every endpoint the game calls.
Uses SQLite for character/inventory persistence.
"""

from flask import Flask, jsonify, request, g, send_file
import sqlite3
import json
import uuid
import time
import os
import sys
import logging
from pathlib import Path

# Try to import manifest manager for local content serving
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'db'))
    from manifest_manager import get_local_manifest_response, CONTENT_DIR, ASSETS_DIR
    MANIFEST_AVAILABLE = True
except ImportError:
    MANIFEST_AVAILABLE = False
    CONTENT_DIR = Path(os.path.join(os.path.dirname(__file__), '..', 'db', 'content'))
    ASSETS_DIR  = Path(os.path.join(os.path.dirname(__file__), '..', 'db', 'assets'))

log = logging.getLogger("BungieAPI")

# Load credentials from config.py
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    from config import (BUNGIE_API_KEY, OAUTH_CLIENT_ID,
                        OAUTH_CLIENT_SECRET, OAUTH_REDIRECT_URL)
except ImportError:
    BUNGIE_API_KEY      = os.environ.get("D2_API_KEY", "")
    OAUTH_CLIENT_ID     = os.environ.get("D2_CLIENT_ID", "")
    OAUTH_CLIENT_SECRET = os.environ.get("D2_CLIENT_SECRET", "")
    OAUTH_REDIRECT_URL  = "https://localhost:8080/callback"

# ── Response helpers ──────────────────────────────────────────────────────────

def ok(data=None, message="Ok", throttle=0):
    return jsonify({
        "Response":        data or {},
        "ErrorCode":       1,
        "ThrottleSeconds": throttle,
        "ErrorStatus":     "Success",
        "Message":         message,
        "MessageData":     {},
    })

def err(code=1, message="SystemDisabled", status=503):
    return jsonify({
        "Response":        {},
        "ErrorCode":       code,
        "ThrottleSeconds": 0,
        "ErrorStatus":     message,
        "Message":         message,
        "MessageData":     {},
    }), status

# ── Database helpers ──────────────────────────────────────────────────────────

def get_db(db_path):
    db = sqlite3.connect(db_path)
    db.row_factory = sqlite3.Row
    return db

def init_db(db_path):
    db = get_db(db_path)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS accounts (
            membership_id     TEXT PRIMARY KEY,
            display_name      TEXT,
            membership_type   INTEGER DEFAULT 3,
            access_token      TEXT,
            refresh_token     TEXT,
            token_expiry      INTEGER,
            created_at        INTEGER
        );

        CREATE TABLE IF NOT EXISTS characters (
            character_id      TEXT PRIMARY KEY,
            membership_id     TEXT,
            class_type        INTEGER DEFAULT 0,
            race_type         INTEGER DEFAULT 0,
            gender_type       INTEGER DEFAULT 0,
            light_level       INTEGER DEFAULT 1810,
            emblem_hash       INTEGER DEFAULT 0,
            minutes_played    INTEGER DEFAULT 0,
            date_last_played  TEXT,
            FOREIGN KEY (membership_id) REFERENCES accounts(membership_id)
        );

        CREATE TABLE IF NOT EXISTS items (
            item_instance_id  TEXT PRIMARY KEY,
            membership_id     TEXT,
            character_id      TEXT,
            item_hash         INTEGER,
            quantity          INTEGER DEFAULT 1,
            bucket_hash       INTEGER,
            transfer_status   INTEGER DEFAULT 0,
            lock_flags        INTEGER DEFAULT 0,
            state             INTEGER DEFAULT 0,
            overrides         TEXT DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS loadouts (
            loadout_id        INTEGER PRIMARY KEY AUTOINCREMENT,
            character_id      TEXT,
            slot_index        INTEGER,
            name_hash         INTEGER DEFAULT 0,
            icon_hash         INTEGER DEFAULT 0,
            color_hash        INTEGER DEFAULT 0,
            items             TEXT DEFAULT '[]'
        );

        CREATE TABLE IF NOT EXISTS records (
            membership_id     TEXT,
            record_hash       INTEGER,
            state             INTEGER DEFAULT 0,
            objectives        TEXT DEFAULT '[]',
            interval_objectives TEXT DEFAULT '[]',
            PRIMARY KEY (membership_id, record_hash)
        );

        CREATE TABLE IF NOT EXISTS milestones (
            milestone_hash    INTEGER PRIMARY KEY,
            start_date        TEXT,
            end_date          TEXT,
            activities        TEXT DEFAULT '[]',
            rewards           TEXT DEFAULT '[]'
        );
    """)
    db.commit()

    # Seed a default account if empty
    if not db.execute("SELECT 1 FROM accounts LIMIT 1").fetchone():
        mid = "4611686018467262000"
        db.execute("""
            INSERT INTO accounts (membership_id, display_name, membership_type, created_at)
            VALUES (?, 'Guardian', 3, ?)
        """, (mid, int(time.time())))
        # Create one character per class
        for (char_id, class_type) in [("2305843009260645000", 0),
                                       ("2305843009260645001", 1),
                                       ("2305843009260645002", 2)]:
            db.execute("""
                INSERT INTO characters (character_id, membership_id, class_type, light_level)
                VALUES (?, ?, ?, 1810)
            """, (char_id, mid, class_type))
        db.commit()
        log.info("Seeded default account: membership_id={}".format(mid))

    db.close()

# ── App factory ───────────────────────────────────────────────────────────────

def create_api_app(db_path="d2_private.db"):
    app = Flask(__name__)
    app.config["DB_PATH"] = db_path
    app.config["LAST_SIGNON_VERSION"] = "private_server_v1"
    app.config["LAST_SIGNON_ENVIRONMENT"] = "private"
    init_db(db_path)

    @app.errorhandler(404)
    def fallback_not_found(error):
        log.warning("Fallback 404: {} {}".format(request.method, request.path))
        return ok({}, message="NotImplemented (private server fallback)")

    @app.errorhandler(405)
    def fallback_method_not_allowed(error):
        log.warning("Fallback 405: {} {}".format(request.method, request.path))
        return ok({}, message="MethodAllowedFallback (private server stub)")

    @app.errorhandler(500)
    def fallback_server_error(error):
        log.exception("Fallback 500: {} {}".format(request.method, request.path))
        return ok({}, message="ServerErrorFallback (private server stub)")

    # ── OAuth ─────────────────────────────────────────────────────────────────

    @app.route("/en/OAuth/Authorize", methods=["GET"])
    def oauth_authorize():
        """
        Intercepts the OAuth authorization redirect.
        Normally the game opens a browser → Bungie login → redirect back.
        We short-circuit: immediately redirect to our callback with a fake code.
        """
        redirect_uri = request.args.get("redirect_uri", OAUTH_REDIRECT_URL)
        state        = request.args.get("state", "")
        fake_code    = str(uuid.uuid4()).replace("-", "")
        # Store the code temporarily
        db = get_db(app.config["DB_PATH"])
        db.execute("UPDATE accounts SET access_token=? WHERE 1", (fake_code,))
        db.commit()
        db.close()
        # Redirect immediately to callback with fake auth code
        callback = "{}?code={}&state={}".format(redirect_uri, fake_code, state)
        log.info("OAuth: auto-authorizing, redirecting to callback")
        from flask import redirect as flask_redirect
        return flask_redirect(callback)

    @app.route("/Platform/App/OAuth/Token/", methods=["POST"])
    def oauth_token():
        """
        Exchange auth code for access token.
        Accepts both authorization_code and refresh_token grant types.
        Returns our fake token — the game sends it back on every API call.
        """
        grant_type    = request.form.get("grant_type", "")
        client_id     = request.form.get("client_id", "")
        client_secret = request.form.get("client_secret", "")
        code          = request.form.get("code", "")
        refresh_token = request.form.get("refresh_token", "")

        log.info("OAuth token: grant_type={} client_id={}".format(grant_type, client_id))

        db  = get_db(app.config["DB_PATH"])
        mid = db.execute("SELECT membership_id FROM accounts LIMIT 1").fetchone()
        if not mid:
            db.close()
            return err(99, "NoAccounts")
        mid = mid["membership_id"]

        # Issue a new access token
        token         = str(uuid.uuid4()).replace("-", "")
        refresh       = str(uuid.uuid4()).replace("-", "")
        exp           = int(time.time()) + 3600
        db.execute(
            "UPDATE accounts SET access_token=?, token_expiry=? WHERE membership_id=?",
            (token, exp, mid))
        db.commit()
        db.close()

        return jsonify({
            "access_token":       token,
            "token_type":         "Bearer",
            "expires_in":         3600,
            "refresh_token":      refresh,
            "refresh_expires_in": 7776000,
            "membership_id":      mid,
        })

    @app.route("/callback", methods=["GET"])
    @app.route("/Platform/App/OAuth/callback", methods=["GET"])
    def oauth_callback():
        """Handles the OAuth callback redirect from our own authorize endpoint."""
        code  = request.args.get("code", "")
        state = request.args.get("state", "")
        log.info("OAuth callback received: code={:.8}... state={}".format(code, state))
        return "<html><body><h2>Authorization successful.</h2>" \
               "<p>Return to Destiny 2.</p></body></html>"

    # ── User endpoints ────────────────────────────────────────────────────────

    @app.route("/Platform/User/GetCurrentBungieAccount/", methods=["GET"])
    @app.route("/Platform/User/GetCurrentBungieNetUser/", methods=["GET"])
    def get_current_user():
        db  = get_db(app.config["DB_PATH"])
        acc = db.execute("SELECT * FROM accounts LIMIT 1").fetchone()
        db.close()
        if not acc: return err()
        return ok({
            "bungieNetUser": {
                "membershipId":   acc["membership_id"],
                "uniqueName":     acc["display_name"],
                "displayName":    acc["display_name"],
                "profilePicturePath": "/img/profile/avatars/default_avatar.gif",
            },
            "destinyMemberships": [{
                "membershipId":   acc["membership_id"],
                "membershipType": acc["membership_type"],
                "displayName":    acc["display_name"],
                "crossSaveOverride": 0,
                "isPublic":       True,
            }],
            "primaryMembershipId": acc["membership_id"],
        })

    @app.route("/Platform/User/GetLinkedProfiles/<membership_id>/", methods=["GET"])
    def get_linked_profiles(membership_id):
        db  = get_db(app.config["DB_PATH"])
        acc = db.execute("SELECT * FROM accounts WHERE membership_id=?",
                         (membership_id,)).fetchone()
        db.close()
        if not acc: return err()
        return ok({
            "profiles": [{
                "membershipId":   acc["membership_id"],
                "membershipType": acc["membership_type"],
                "displayName":    acc["display_name"],
                "isCrossSavePrimary": True,
                "applicableMembershipTypes": [acc["membership_type"]],
            }],
            "bnetMembership": {
                "membershipId": acc["membership_id"],
                "displayName":  acc["display_name"],
            },
        })

    # ── Destiny2 Profile ──────────────────────────────────────────────────────

    @app.route("/Platform/Destiny2/<int:mtype>/Profile/<membership_id>/", methods=["GET"])
    def get_profile(mtype, membership_id):
        db    = get_db(app.config["DB_PATH"])
        acc   = db.execute("SELECT * FROM accounts WHERE membership_id=?",
                            (membership_id,)).fetchone()
        chars = db.execute("SELECT * FROM characters WHERE membership_id=?",
                            (membership_id,)).fetchall()
        db.close()
        if not acc: return err()

        char_ids = [c["character_id"] for c in chars]
        components = request.args.get("components", "200,201,202,205,300,305")
        comp_list  = [int(c.strip()) for c in components.split(",") if c.strip().isdigit()]

        response = {}

        # 100 — Profiles
        if 100 in comp_list or not comp_list:
            response["profile"] = {"data": {
                "userInfo": {
                    "membershipId":   membership_id,
                    "membershipType": mtype,
                    "displayName":    acc["display_name"],
                },
                "characterIds": char_ids,
                "versionsOwned": 0xFF,  # all DLC
                "dateLastPlayed": "2024-01-01T00:00:00Z",
                "seasonHashes": [],
                "activeEventCardHash": 0,
            }, "privacy": 1}

        # 200 — Characters
        if 200 in comp_list:
            char_data = {}
            for c in chars:
                char_data[c["character_id"]] = {
                    "membershipId":    membership_id,
                    "membershipType":  mtype,
                    "characterId":     c["character_id"],
                    "dateLastPlayed":  c["date_last_played"] or "2024-01-01T00:00:00Z",
                    "minutesPlayedThisSession": 0,
                    "minutesPlayedTotal": str(c["minutes_played"]),
                    "light":           c["light_level"],
                    "stats":           {"2996146975": c["light_level"]},
                    "raceType":        c["race_type"],
                    "genderType":      c["gender_type"],
                    "classType":       c["class_type"],
                    "raceHash":        [898774759, 3887404748, 898774760][c["race_type"] % 3],
                    "genderHash":      [3111576190, 2204441813][c["gender_type"] % 2],
                    "classHash":       [671679912, 3655393136, 2271682572][c["class_type"] % 3],
                    "emblemHash":      c["emblem_hash"],
                    "emblemPath":      "/common/destiny2_content/icons/default_emblem.jpg",
                    "emblemBackgroundPath": "/common/destiny2_content/icons/default_emblem_bg.jpg",
                    "levelProgression": {"progressionHash": 0, "currentProgress": 0,
                                          "level": 50, "levelCap": 50, "dailyProgress": 0},
                    "baseCharacterLevel": 50,
                    "percentToNextLevel": 0.0,
                    "titleRecordHash": 0,
                }
            response["characters"] = {"data": char_data, "privacy": 1}

        # 205 — Equipment
        if 205 in comp_list:
            equipment = {}
            db2 = get_db(app.config["DB_PATH"])
            for c in chars:
                cid   = c["character_id"]
                items = db2.execute(
                    "SELECT * FROM items WHERE character_id=? AND bucket_hash IN (?,?,?,?,?,?,?,?,?)",
                    (cid, 0x14239138, 0x2ae25b0e, 0x05813880,
                     0x107de4f9, 0x14e5a81f, 0x1816aa82, 0x18ae5d2d,
                     0x19153148, 0x1469ff4d)).fetchall()
                equipment[cid] = {"items": [
                    {"itemHash": i["item_hash"], "itemInstanceId": i["item_instance_id"],
                     "quantity": 1, "bindStatus": 0, "location": 1,
                     "bucketHash": i["bucket_hash"], "transferStatus": 0,
                     "lockFlags": i["lock_flags"], "state": i["state"]}
                    for i in items
                ]}
            db2.close()
            response["characterEquipment"] = {"data": equipment, "privacy": 1}

        # 201 — CharacterInventories
        if 201 in comp_list:
            inventory = {}
            db2 = get_db(app.config["DB_PATH"])
            for c in chars:
                cid   = c["character_id"]
                items = db2.execute(
                    "SELECT * FROM items WHERE character_id=? AND bucket_hash NOT IN (?,?,?,?,?,?,?,?,?)",
                    (cid, 0x14239138, 0x2ae25b0e, 0x05813880,
                     0x107de4f9, 0x14e5a81f, 0x1816aa82, 0x18ae5d2d,
                     0x19153148, 0x1469ff4d)).fetchall()
                inventory[cid] = {"items": [
                    {"itemHash": i["item_hash"], "itemInstanceId": i["item_instance_id"],
                     "quantity": i["quantity"], "bindStatus": 0, "location": 2,
                     "bucketHash": i["bucket_hash"], "transferStatus": i["transfer_status"],
                     "lockFlags": i["lock_flags"], "state": i["state"]}
                    for i in items
                ]}
            db2.close()
            response["characterInventories"] = {"data": inventory, "privacy": 1}

        # 102 — ProfileInventory (vault)
        if 102 in comp_list:
            db2   = get_db(app.config["DB_PATH"])
            vault = db2.execute(
                "SELECT * FROM items WHERE character_id='' AND bucket_hash=?",
                (0x3d5f90ea,)).fetchall()
            db2.close()
            response["profileInventory"] = {"data": {"items": [
                {"itemHash": i["item_hash"], "itemInstanceId": i["item_instance_id"],
                 "quantity": i["quantity"], "bucketHash": 0x3d5f90ea,
                 "transferStatus": 0, "lockFlags": 0, "state": 0}
                for i in vault
            ]}, "privacy": 1}

        return ok(response)

    # ── Item actions ──────────────────────────────────────────────────────────

    @app.route("/Platform/Destiny2/Actions/Items/TransferItem/", methods=["POST"])
    def transfer_item():
        body = request.get_json() or {}
        item_id    = str(body.get("itemInstanceId", ""))
        char_id    = str(body.get("characterId", ""))
        to_vault   = bool(body.get("transferToVault", False))
        membership = str(body.get("membershipType", 3))

        db = get_db(app.config["DB_PATH"])
        if to_vault:
            db.execute("UPDATE items SET character_id='' WHERE item_instance_id=?", (item_id,))
        else:
            db.execute("UPDATE items SET character_id=? WHERE item_instance_id=?",
                       (char_id, item_id))
        db.commit()
        db.close()
        log.info("Transfer: item={} char={} vault={}".format(item_id[:12], char_id[:12], to_vault))
        return ok(1)

    @app.route("/Platform/Destiny2/Actions/Items/EquipItem/", methods=["POST"])
    def equip_item():
        body    = request.get_json() or {}
        item_id = str(body.get("itemInstanceId", ""))
        char_id = str(body.get("characterId", ""))
        db = get_db(app.config["DB_PATH"])
        item = db.execute("SELECT * FROM items WHERE item_instance_id=?", (item_id,)).fetchone()
        if item:
            # Unequip anything else in this bucket
            db.execute("""UPDATE items SET state = state & ~1
                          WHERE character_id=? AND bucket_hash=?""",
                       (char_id, item["bucket_hash"]))
            db.execute("UPDATE items SET state = state | 1, character_id=? WHERE item_instance_id=?",
                       (char_id, item_id))
            db.commit()
        db.close()
        log.info("Equip: item={} char={}".format(item_id[:12], char_id[:12]))
        return ok(1)

    @app.route("/Platform/Destiny2/Actions/Items/EquipItems/", methods=["POST"])
    def equip_items():
        body     = request.get_json() or {}
        char_id  = str(body.get("characterId", ""))
        item_ids = body.get("itemIds", [])
        results  = []
        db = get_db(app.config["DB_PATH"])
        for item_id in item_ids:
            item = db.execute("SELECT * FROM items WHERE item_instance_id=?",
                              (str(item_id),)).fetchone()
            if item:
                db.execute("UPDATE items SET state=state|1, character_id=? WHERE item_instance_id=?",
                           (char_id, str(item_id)))
                results.append({"itemInstanceId": item_id, "equipStatus": 1})
            else:
                results.append({"itemInstanceId": item_id, "equipStatus": 0})
        db.commit()
        db.close()
        return ok({"equipResults": results})

    @app.route("/Platform/Destiny2/Actions/Items/SetItemLockState/", methods=["POST"])
    def set_lock_state():
        body    = request.get_json() or {}
        item_id = str(body.get("itemInstanceId", ""))
        locked  = bool(body.get("state", False))
        db = get_db(app.config["DB_PATH"])
        if locked:
            db.execute("UPDATE items SET lock_flags = lock_flags | 1 WHERE item_instance_id=?", (item_id,))
        else:
            db.execute("UPDATE items SET lock_flags = lock_flags & ~1 WHERE item_instance_id=?", (item_id,))
        db.commit()
        db.close()
        return ok(1)

    @app.route("/Platform/Destiny2/Actions/Items/PullFromPostmaster/", methods=["POST"])
    def pull_from_postmaster():
        body    = request.get_json() or {}
        item_id = str(body.get("itemInstanceId", ""))
        char_id = str(body.get("characterId", ""))
        db = get_db(app.config["DB_PATH"])
        db.execute("UPDATE items SET character_id=? WHERE item_instance_id=?", (char_id, item_id))
        db.commit()
        db.close()
        return ok(1)

    # ── Manifest ──────────────────────────────────────────────────────────────

    @app.route("/Platform/Destiny2/Manifest/", methods=["GET"])
    def get_manifest():
        """
        Returns manifest pointing to local content files if downloaded,
        or a stub if not. Run db/manifest_manager.py download first.
        """
        if MANIFEST_AVAILABLE:
            manifest_data = get_local_manifest_response()
            if manifest_data.get("version", "").startswith("private_server_stub"):
                log.warning("Manifest not downloaded — serving stub. "
                            "Run: python db/manifest_manager.py download")
            else:
                log.info("Serving local manifest v{}".format(
                    manifest_data.get("version", "?")))
            return ok(manifest_data)
        # Fallback stub
        manifest_path = os.path.join(os.path.dirname(__file__), "..", "db", "manifest.json")
        if os.path.exists(manifest_path):
            with open(manifest_path) as f:
                return ok(json.load(f))
        return ok({
            "version":                  "private_server_stub_v1",
            "mobileWorldContentPaths":  {"en": ""},
            "mobileAssetContentPath":   "",
            "mobileClanBannerDatabasePath": "",
            "mobileGearCDN":            {},
        })

    # ── Manifest content file serving ─────────────────────────────────────────
    # Game downloads SQLite content files from CDN — we serve them locally.
    # These URLs come from the manifest response above.

    @app.route("/content/<path:filename>", methods=["GET"])
    def serve_content_file(filename):
        """Serve downloaded world content files (SQLite DBs ~200MB each)."""
        file_path = CONTENT_DIR / filename
        if not file_path.exists():
            log.warning("Content file not found: {} — run manifest_manager.py download".format(filename))
            return "Not found — run: python db/manifest_manager.py download", 404
        log.info("Serving content: {}  ({:.1f}MB)".format(
            filename, file_path.stat().st_size / 1024 / 1024))
        return send_file(str(file_path), mimetype="application/octet-stream",
                         as_attachment=True, download_name=filename)

    @app.route("/assets/<path:filename>", methods=["GET"])
    def serve_asset_file(filename):
        """Serve downloaded asset content files."""
        file_path = ASSETS_DIR / filename
        if not file_path.exists():
            return "Not found", 404
        return send_file(str(file_path), mimetype="application/octet-stream",
                         as_attachment=True, download_name=filename)

    @app.route("/common/destiny2_content/<path:path>", methods=["GET"])
    def serve_bungie_cdn(path):
        """
        Handle CDN requests for /common/destiny2_content/...
        These are the actual Bungie CDN URLs embedded in the manifest.
        We intercept them here and serve from local cache.
        """
        filename = Path(path).name
        # Check content dir
        file_path = CONTENT_DIR / filename
        if file_path.exists():
            log.info("Serving CDN: {}".format(filename))
            return send_file(str(file_path), mimetype="application/octet-stream",
                             as_attachment=True, download_name=filename)
        # Check assets dir
        file_path = ASSETS_DIR / filename
        if file_path.exists():
            return send_file(str(file_path), mimetype="application/octet-stream",
                             as_attachment=True, download_name=filename)
        log.warning("CDN miss: {} — run manifest_manager.py download".format(filename))
        return "Not found in local cache", 404

    # ── Milestones ────────────────────────────────────────────────────────────

    @app.route("/Platform/Destiny2/Milestones/", methods=["GET"])
    def get_milestones():
        return ok({})

    # ── Search ────────────────────────────────────────────────────────────────

    @app.route("/Platform/Destiny2/SearchDestinyPlayer/<int:mtype>/<display_name>/", methods=["GET"])
    def search_player(mtype, display_name):
        db   = get_db(app.config["DB_PATH"])
        accs = db.execute("SELECT * FROM accounts WHERE display_name LIKE ?",
                          ("%{}%".format(display_name),)).fetchall()
        db.close()
        return ok([{
            "membershipId":   a["membership_id"],
            "membershipType": a["membership_type"],
            "displayName":    a["display_name"],
            "isPublic":       True,
        } for a in accs])

    # ── Stats ─────────────────────────────────────────────────────────────────

    @app.route("/Platform/Destiny2/<int:mtype>/Account/<membership_id>/Stats/", methods=["GET"])
    def get_stats(mtype, membership_id):
        return ok({"mergedAllCharacters": {"results": {
            "allPvE": {"allTime": {}},
            "allPvP": {"allTime": {}},
        }}})

    # ── Loadouts ──────────────────────────────────────────────────────────────

    @app.route("/Platform/Destiny2/Actions/Loadouts/SnapshotLoadout/", methods=["POST"])
    def snapshot_loadout():
        body     = request.get_json() or {}
        char_id  = str(body.get("characterId", ""))
        slot     = int(body.get("loadoutIndex", 0))
        db = get_db(app.config["DB_PATH"])
        items = db.execute("SELECT item_instance_id FROM items WHERE character_id=? AND state & 1",
                            (char_id,)).fetchall()
        item_list = [{"itemInstanceId": i["item_instance_id"]} for i in items]
        db.execute("INSERT OR REPLACE INTO loadouts (character_id, slot_index, items) VALUES (?,?,?)",
                   (char_id, slot, json.dumps(item_list)))
        db.commit()
        db.close()
        return ok(1)

    @app.route("/Platform/Destiny2/Actions/Loadouts/EquipLoadout/", methods=["POST"])
    def equip_loadout():
        body    = request.get_json() or {}
        char_id = str(body.get("characterId", ""))
        slot    = int(body.get("loadoutIndex", 0))
        db = get_db(app.config["DB_PATH"])
        row = db.execute("SELECT items FROM loadouts WHERE character_id=? AND slot_index=?",
                          (char_id, slot)).fetchone()
        if row:
            items = json.loads(row["items"])
            for item in items:
                iid = str(item.get("itemInstanceId",""))
                if iid:
                    db.execute("UPDATE items SET state=state|1, character_id=? WHERE item_instance_id=?",
                               (char_id, iid))
            db.commit()
        db.close()
        return ok(1)

    # ── GroupV2 (Clans) ───────────────────────────────────────────────────────

    @app.route("/Platform/GroupV2/User/<int:mtype>/<membership_id>/0/1/", methods=["GET"])
    def get_user_groups(mtype, membership_id):
        return ok({"results": [], "totalResults": 0, "hasMore": False})

    # ── Tokens / Rewards ──────────────────────────────────────────────────────

    @app.route("/Platform/Tokens/Rewards/GetRewardsForCurrentUser/", methods=["GET"])
    def get_rewards():
        return ok({"items": []})

    @app.route("/Platform/Tokens/Rewards/ClaimReward/", methods=["POST"])
    def claim_reward():
        return ok({"items": []})

    # ── Health check ──────────────────────────────────────────────────────────

    @app.route("/Platform/Settings/", methods=["GET"])
    @app.route("/Platform/GlobalAlerts/", methods=["GET"])
    def settings():
        return ok({"systems": {}, "destiny2CoreSettings": {
            "undiscoveredCollectibleImage": "",
            "ammoTypeHeavyIcon": "", "ammoTypeSpecialIcon": "", "ammoTypePrimaryIcon": "",
        }})

    # ── Bungie Internal Signon Server ────────────────────────────────────────
    # DISCOVERED via RE: signon_platform_s_build_s @ 7ff7102ea8e0
    # Game calls: https://www[1|2].signon2.gravityshavings.net/SignOn?platform=%s&build=%s
    # This is the FIRST external call at startup (before platform.bungie.net)
    # Hosts file must redirect signon2.gravityshavings.net → localhost
    # Response tells the game what content version is live and which API servers to use

    @app.route("/SignOn", methods=["GET", "POST"])
    def signon():
        platform = request.args.get("platform", "xbox")
        build    = request.args.get("build", "0")
        reported_version = build if build and build != "0" else "private_server_v1"
        environment = "live" if "live" in reported_version.lower() else "private"
        app.config["LAST_SIGNON_VERSION"] = reported_version
        app.config["LAST_SIGNON_ENVIRONMENT"] = environment
        log.info("SignOn: platform={} build={} method={} content_length={}".format(
            platform, build, request.method, request.content_length or 0))
        # Return minimal signon response — tells game which API environment to use
        # signon_server_reported_content_version @ 7ff7111886b0 processes the version field
        return jsonify({
            "AuthorizationEndpoint": "https://www.bungie.net/en/OAuth/Authorize",
            "TokenEndpoint":         "https://www.bungie.net/Platform/App/OAuth/Token/",
            "environment":           environment,
            "ContentVersion":        reported_version,
            "contentVersion":        reported_version,
            "version":               reported_version,
            "build":                 build,
            "platform":              platform,
            "isLive":                True,
            "maintenanceWindow":     None,
        })

    # ── Tiger Engine Version Endpoint ────────────────────────────────────────
    # Discovered via RE: game checks URL path for "tigerheart_version" at startup.
    # player_login_session_manager (7ff7106f39a0) calls wcsncmp against this path.
    # Must return valid version data or login flow fails.

    @app.route("/tigerheart_version", methods=["GET"])
    @app.route("/Platform/tigerheart_version", methods=["GET"])
    def tigerheart_version():
        reported_version = app.config.get("LAST_SIGNON_VERSION", "private_server_v1")
        environment = app.config.get("LAST_SIGNON_ENVIRONMENT", "private")
        return jsonify({
            "version":          reported_version,
            "build":            reported_version,
            "environment":      environment,
            "engineVersion":    "tiger_12.0",
            "contentVersion":   reported_version,
            "betaName":         "",
            "isLive":           True,
        })

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok", "server": "D2 Private Server"})

    # ── Membership / Identity ─────────────────────────────────────────────────

    @app.route("/Platform/User/GetMembershipsById/<membership_id>/<int:mtype>/", methods=["GET"])
    def get_memberships_by_id(membership_id, mtype):
        db  = get_db(app.config["DB_PATH"])
        acc = db.execute("SELECT * FROM accounts WHERE membership_id=?",
                         (membership_id,)).fetchone()
        db.close()
        if not acc:
            acc_data = {"membershipId": membership_id, "membershipType": mtype,
                        "displayName": "Guardian"}
        else:
            acc_data = {"membershipId": acc["membership_id"],
                        "membershipType": acc["membership_type"],
                        "displayName": acc["display_name"]}
        return ok({
            "destinyMemberships": [acc_data],
            "bungieNetUser": {
                "membershipId": acc_data["membershipId"],
                "uniqueName":   acc_data["displayName"],
                "displayName":  acc_data["displayName"],
            },
            "primaryMembershipId": acc_data["membershipId"],
        })

    @app.route("/Platform/User/GetMembershipsForCurrentUser/", methods=["GET"])
    def get_memberships_current():
        db  = get_db(app.config["DB_PATH"])
        acc = db.execute("SELECT * FROM accounts LIMIT 1").fetchone()
        db.close()
        if not acc:
            return err()
        return ok({
            "destinyMemberships": [{
                "membershipId":   acc["membership_id"],
                "membershipType": acc["membership_type"],
                "displayName":    acc["display_name"],
                "crossSaveOverride": 0,
                "applicableMembershipTypes": [acc["membership_type"]],
                "isPublic": True,
            }],
            "bungieNetUser": {
                "membershipId": acc["membership_id"],
                "uniqueName":   acc["display_name"],
                "displayName":  acc["display_name"],
            },
            "primaryMembershipId": acc["membership_id"],
        })

    # ── Destiny2 common endpoints ─────────────────────────────────────────────

    @app.route("/Platform/Destiny2/GetAvailableLocales/", methods=["GET"])
    def get_locales():
        return ok({"en": "English", "fr": "Français", "es": "Español",
                   "es-mx": "Español mexicano", "de": "Deutsch",
                   "it": "Italiano", "ja": "日本語", "pt-br": "Português Brasileiro",
                   "ru": "Русский", "pl": "Polski", "ko": "한국어",
                   "zh-cht": "繁體中文", "zh-chs": "简体中文"})

    @app.route("/Platform/Destiny2/Stats/Definition/", methods=["GET"])
    def get_stats_def():
        return ok({})

    @app.route("/Platform/Destiny2/<int:mtype>/Account/<membership_id>/Character/<character_id>/Stats/",
               methods=["GET"])
    def get_char_stats(mtype, membership_id, character_id):
        return ok({"activities": {}})

    @app.route("/Platform/Destiny2/<int:mtype>/Account/<membership_id>/Character/<character_id>/Activities/",
               methods=["GET"])
    def get_char_activities(mtype, membership_id, character_id):
        return ok({"activities": []})

    @app.route("/Platform/Destiny2/Actions/Characters/SetFactionVendorEngrams/", methods=["POST"])
    def set_faction_vendor():
        return ok(1)

    # ── Fireteam Finder ───────────────────────────────────────────────────────
    # FireteamFinder endpoints — return empty results to prevent startup errors

    @app.route("/Platform/FireteamFinder/", methods=["GET", "POST"])
    @app.route("/Platform/FireteamFinder/<path:path>", methods=["GET", "POST"])
    def fireteam_finder(path=""):
        return ok({"results": [], "totalResults": 0, "hasMore": False})

    # ── Social / Friends ──────────────────────────────────────────────────────

    @app.route("/Platform/Social/Friends/", methods=["GET"])
    @app.route("/Platform/Social/Friends/Requests/", methods=["GET"])
    def get_friends():
        return ok({"friends": [], "requests": []})

    # ── Trending / Content ────────────────────────────────────────────────────

    @app.route("/Platform/Trending/Categories/", methods=["GET"])
    def get_trending():
        return ok({"categories": []})

    @app.route("/Platform/Content/<path:path>", methods=["GET"])
    def get_content(path):
        return ok({"subject": None, "results": [], "totalResults": 0})

    # ── Seasonal Content ──────────────────────────────────────────────────────

    @app.route("/Platform/Destiny2/Eras/Bnet/Account/<membership_id>/Character/<char_id>/Artisan/",
               methods=["GET", "POST"])
    def artisan(membership_id, char_id):
        return ok({})

    # ── Catch-all ─────────────────────────────────────────────────────────────

    @app.route("/Platform/<path:path>", methods=["GET","POST","PUT","DELETE","PATCH"])
    def catch_all(path):
        log.warning("Unimplemented: {} /Platform/{}".format(request.method, path))
        return ok({}, message="NotImplemented (private server stub)")

    log.info("Bungie API app created ({} routes)".format(len(app.url_map._rules)))
    return app
