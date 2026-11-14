import os
import re
import json
import hmac
import hashlib
import sqlite3
import secrets
from urllib.parse import parse_qsl
from datetime import datetime, timezone, timedelta
from functools import wraps

from flask import (
    Flask, request, jsonify, session,
    send_from_directory
)
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "sabbir_v2.db")
BOT_TOKEN = os.getenv("BOT_TOKEN", "")
SECRET_KEY = os.getenv("SECRET_KEY", "")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
app = Flask(__name__)
app.secret_key = SECRET_KEY or secrets.token_hex(32)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "1") == "1",
    SESSION_COOKIE_SAMESITE="Lax"
)

BD_TZ = timezone(timedelta(hours=6))


def now_bd():
    return datetime.now(BD_TZ).strftime("%Y-%m-%d %H:%M:%S")


def connect():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def setup():
    con = connect()

    con.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY,
        username TEXT DEFAULT '',
        first_name TEXT DEFAULT '',
        coins INTEGER DEFAULT 0,
        ads_since_withdraw INTEGER DEFAULT 0,
        total_earned INTEGER DEFAULT 0,
        total_withdrawn INTEGER DEFAULT 0,
        banned INTEGER DEFAULT 0,
        created_at TEXT
    );

    CREATE TABLE IF NOT EXISTS withdrawals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        amount_bdt INTEGER,
        coins INTEGER,
        method TEXT,
        phone TEXT,
        status TEXT DEFAULT 'pending',
        reason TEXT DEFAULT '',
        refund_coins INTEGER DEFAULT 0,
        created_at TEXT,
        updated_at TEXT
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_action TEXT,
        details TEXT,
        created_at TEXT
    );
    """)

    con.commit()
    con.close()


def telegram_user():
    if not BOT_TOKEN:
        return None

    raw = request.headers.get("X-Telegram-Init-Data", "")
    if not raw:
        return None

    try:
        values = dict(parse_qsl(raw, keep_blank_values=True))
        received_hash = values.pop("hash", None)

        if not received_hash:
            return None

        data_check = "\n".join(
            f"{key}={values[key]}" for key in sorted(values)
        )

        secret = hmac.new(
            b"WebAppData",
            BOT_TOKEN.encode(),
            hashlib.sha256
        ).digest()

        calculated = hmac.new(
            secret,
            data_check.encode(),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(calculated, received_hash):
            return None

        auth_date = int(values.get("auth_date", "0"))

        if abs(datetime.now(timezone.utc).timestamp() - auth_date) > 86400:
            return None

        user = json.loads(values.get("user", "{}"))

        if not user.get("id"):
            return None

        return user

    except Exception:
        return None


def user_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        user = telegram_user()

        if not user:
            return jsonify({
                "ok": False,
                "message": "Telegram authentication failed"
            }), 401

        con = connect()
        existing = con.execute(
            "SELECT banned FROM users WHERE user_id=?",
            (user["id"],)
        ).fetchone()

        if existing and existing["banned"]:
            con.close()
            return jsonify({
                "ok": False,
                "message": "Your account is blocked"
            }), 403

        con.execute("""
            INSERT OR IGNORE INTO users
            (user_id, username, first_name, created_at)
            VALUES (?, ?, ?, ?)
        """, (
            user["id"],
            user.get("username", ""),
            user.get("first_name", ""),
            now_bd()
        ))

        con.execute("""
            UPDATE users SET username=?, first_name=?
            WHERE user_id=?
        """, (
            user.get("username", ""),
            user.get("first_name", ""),
            user["id"]
        ))

        con.commit()
        con.close()

        return func(user, *args, **kwargs)

    return wrapper


def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("admin"):
            return jsonify({
                "ok": False,
                "message": "Admin login required"
            }), 401

        if request.method == "POST":
            token = request.headers.get("X-Admin-CSRF", "")
            if not token or not hmac.compare_digest(
                token, session.get("csrf_token", "")
            ):
                return jsonify({
                    "ok": False,
                    "message": "Invalid security token"
                }), 403

        return func(*args, **kwargs)

    return wrapper


def audit(action, details):
    con = connect()
    con.execute("""
        INSERT INTO audit_logs (admin_action, details, created_at)
        VALUES (?, ?, ?)
    """, (action, str(details), now_bd()))
    con.commit()
    con.close()


@app.route("/")
def home():
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/admin")
def admin_page():
    return send_from_directory(BASE_DIR, "admin.html")


@app.route("/admin/login", methods=["POST"])
def admin_login():
    data = request.get_json(silent=True) or {}
    password = str(data.get("password", ""))

    if not ADMIN_PASSWORD:
        return jsonify({
            "ok": False,
            "message": "Admin password is not configured"
        }), 500

    if not hmac.compare_digest(password, ADMIN_PASSWORD):
        return jsonify({
            "ok": False,
            "message": "Wrong password"
        }), 401

    session.clear()
    session["admin"] = True
    session["csrf_token"] = secrets.token_urlsafe(32)

    return jsonify({
        "ok": True,
        "csrf_token": session["csrf_token"]
    })


@app.route("/admin/logout", methods=["POST"])
@admin_required
def admin_logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/user")
@user_required
def get_user(user):
    con = connect()
    row = con.execute(
        "SELECT * FROM users WHERE user_id=?",
        (user["id"],)
    ).fetchone()
    con.close()

    return jsonify({
        "ok": True,
        "user": dict(row),
        "conversion": "1000 coins = 1 BDT",
        "minimum_withdrawal_bdt": 1000
    })


@app.route("/api/ad/complete", methods=["POST"])
@user_required
def ad_complete(user):
    # Real ad provider verification is not connected yet.
    # Never reward users from an unverified browser request.
    return jsonify({
        "ok": False,
        "message": "Ad network is not configured yet"
    }), 503






MONETAG_POSTBACK_SECRET = os.getenv("MONETAG_POSTBACK_SECRET", "")
MONETAG_ZONE_ID = "12206288"

def ensure_monetag_tables():
    con = connect()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS monetag_pending (
        ymid TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        rewarded INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS monetag_rewards (
        ymid TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        coins INTEGER NOT NULL DEFAULT 50,
        created_at TEXT NOT NULL
    );
    """)
    con.commit()
    con.close()

@app.route("/api/monetag-session", methods=["POST"])
@user_required
def monetag_session(user):
    ensure_monetag_tables()
    ymid = "tg" + str(user["id"]) + "_" + secrets.token_hex(16)
    con = connect()
    try:
        con.execute(
            "INSERT INTO monetag_pending (ymid,user_id,created_at) VALUES (?,?,?)",
            (ymid, int(user["id"]), now_bd())
        )
        con.commit()
        return jsonify({"ok": True, "ymid": ymid})
    finally:
        con.close()

@app.route("/api/monetag-status", methods=["GET"])
@user_required
def monetag_status(user):
    ensure_monetag_tables()
    ymid = request.args.get("ymid", "")
    con = connect()
    try:
        row = con.execute(
            "SELECT rewarded FROM monetag_pending WHERE ymid=? AND user_id=?",
            (ymid, int(user["id"]))
        ).fetchone()
        return jsonify({"ok": True, "rewarded": bool(row and row["rewarded"])})
    finally:
        con.close()

@app.route("/api/monetag-postback", methods=["GET"])
def monetag_postback():
    import hmac
    supplied = request.args.get("secret", "")
    if not MONETAG_POSTBACK_SECRET or not hmac.compare_digest(
        supplied, MONETAG_POSTBACK_SECRET
    ):
        return "Unauthorized", 403

    ymid = request.args.get("ymid", "")
    if (request.args.get("zone_id") != MONETAG_ZONE_ID
        or request.args.get("reward_event_type") != "valued"
        or request.args.get("event_type") != "impression"
        or not re.fullmatch(r"[A-Za-z0-9_.-]{1,150}", ymid)):
        return "Invalid postback", 400

    ensure_monetag_tables()
    con = connect()
    try:
        con.execute("BEGIN IMMEDIATE")
        pending = con.execute(
            "SELECT user_id,rewarded FROM monetag_pending WHERE ymid=?",
            (ymid,)
        ).fetchone()
        if not pending:
            con.rollback()
            return "Unknown ymid", 404
        if pending["rewarded"]:
            con.rollback()
            return "Already rewarded", 200

        cur = con.execute("""
            INSERT OR IGNORE INTO monetag_rewards
            (ymid,user_id,coins,created_at) VALUES (?,?,50,?)
        """, (ymid, int(pending["user_id"]), 50, now_bd()))
        if cur.rowcount != 1:
            con.rollback()
            return "Duplicate reward", 200

        cur = con.execute("""
            UPDATE users
            SET coins=coins+50,
                total_earned=total_earned+50,
                ads_since_withdraw=ads_since_withdraw+1
            WHERE user_id=?
        """, (int(pending["user_id"]),))
        if cur.rowcount != 1:
            con.rollback()
            return "User not found", 404

        con.execute(
            "UPDATE monetag_pending SET rewarded=1 WHERE ymid=?",
            (ymid,)
        )
        con.commit()
        return "Reward added", 200
    except Exception:
        con.rollback()
        app.logger.exception("Monetag postback error")
        return "Server error", 500
    finally:
        con.close()




@app.route("/api/daily-ads-statistics")
@user_required
def daily_ads_statistics(user):
    ensure_monetag_tables()
    today = now_bd()[:10]
    con = connect()
    try:
        row = con.execute("""
            SELECT COUNT(*) AS ads, COALESCE(SUM(coins),0) AS coins
            FROM monetag_rewards
            WHERE user_id=? AND substr(created_at,1,10)=?
        """, (int(user["id"]), today)).fetchone()

        days = con.execute("""
            SELECT substr(created_at,1,10) AS day,
                   COUNT(*) AS ads, COALESCE(SUM(coins),0) AS coins
            FROM monetag_rewards
            WHERE user_id=?
            GROUP BY substr(created_at,1,10)
            ORDER BY day DESC LIMIT 7
        """, (int(user["id"]),)).fetchall()

        return jsonify({
            "ok": True,
            "today": today,
            "today_ads": row["ads"],
            "today_coins": row["coins"],
            "days": [dict(x) for x in days]
        })
    finally:
        con.close()

@app.route("/api/withdraw", methods=["POST"])
@user_required
def withdraw(user):
    data = request.get_json(silent=True) or {}

    try:
        amount = int(data.get("amount_bdt", 0))
    except (ValueError, TypeError):
        return jsonify({"ok": False, "message": "Invalid amount"}), 400

    method = str(data.get("method", "")).lower().strip()
    phone = str(data.get("phone", "")).strip()

    if amount < 1000:
        return jsonify({
            "ok": False,
            "message": "Minimum withdrawal is 1000 BDT"
        }), 400

    if method not in ("bkash", "nagad"):
        return jsonify({
            "ok": False,
            "message": "Choose bKash or Nagad"
        }), 400

    if len(phone) != 11 or not phone.isdigit() or phone[:3] not in (
        "013", "014", "015", "016", "017", "018", "019"
    ):
        return jsonify({
            "ok": False,
            "message": "Enter a valid Bangladesh mobile number"
        }), 400

    current_time = datetime.now(BD_TZ)

    if not (6 <= current_time.hour < 22):
        return jsonify({
            "ok": False,
            "message": "Withdrawal requests are open from 6 AM to 10 PM Bangladesh time"
        }), 400

    coins = amount * 1000

    con = connect()

    try:
        con.execute("BEGIN IMMEDIATE")

        row = con.execute(
            "SELECT coins, ads_since_withdraw FROM users WHERE user_id=?",
            (user["id"],)
        ).fetchone()

        if not row:
            con.rollback()
            return jsonify({"ok": False, "message": "User not found"}), 404

        if row["ads_since_withdraw"] < 10:
            con.rollback()
            return jsonify({
                "ok": False,
                "message": "Complete 10 verified ads before requesting withdrawal"
            }), 400

        if row["coins"] < coins:
            con.rollback()
            return jsonify({
                "ok": False,
                "message": "Insufficient balance"
            }), 400

        con.execute("""
            UPDATE users
            SET coins=coins-?, ads_since_withdraw=0
            WHERE user_id=?
        """, (coins, user["id"]))

        con.execute("""
            INSERT INTO withdrawals
            (user_id, amount_bdt, coins, method, phone, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)
        """, (
            user["id"], amount, coins, method, phone,
            now_bd(), now_bd()
        ))

        con.commit()

        return jsonify({
            "ok": True,
            "message": "Withdrawal request submitted",
            "status": "pending"
        })

    except Exception:
        con.rollback()
        return jsonify({"ok": False, "message": "Request failed"}), 500

    finally:
        con.close()


@app.route("/api/history")
@user_required
def history(user):
    con = connect()

    rows = con.execute("""
        SELECT id, amount_bdt, coins, method, phone,
               status, reason, refund_coins, created_at, updated_at
        FROM withdrawals
        WHERE user_id=?
        ORDER BY id DESC
    """, (user["id"],)).fetchall()

    con.close()

    return jsonify({
        "ok": True,
        "history": [dict(row) for row in rows]
    })


@app.route("/api/admin/stats")
@admin_required
def admin_stats():
    con = connect()

    users = con.execute(
        "SELECT COUNT(*) AS total FROM users"
    ).fetchone()["total"]

    pending = con.execute(
        "SELECT COUNT(*) AS total FROM withdrawals WHERE status='pending'"
    ).fetchone()["total"]

    paid = con.execute(
        "SELECT COALESCE(SUM(amount_bdt),0) AS total FROM withdrawals WHERE status='paid'"
    ).fetchone()["total"]

    con.close()

    return jsonify({
        "ok": True,
        "total_users": users,
        "pending_withdrawals": pending,
        "total_paid_bdt": paid
    })


@app.route("/api/admin/withdrawals")
@admin_required
def admin_withdrawals():
    con = connect()

    rows = con.execute("""
        SELECT * FROM withdrawals ORDER BY id DESC LIMIT 500
    """).fetchall()

    con.close()

    return jsonify({
        "ok": True,
        "withdrawals": [dict(row) for row in rows]
    })


@app.route("/api/admin/users")
@admin_required
def admin_users():
    con = connect()

    rows = con.execute("""
        SELECT user_id, username, first_name, coins,
               ads_since_withdraw, total_earned,
               total_withdrawn, banned, created_at
        FROM users ORDER BY user_id DESC LIMIT 500
    """).fetchall()

    con.close()

    return jsonify({
        "ok": True,
        "users": [dict(row) for row in rows]
    })


@app.route("/api/admin/action", methods=["POST"])
@admin_required
def admin_action():
    data = request.get_json(silent=True) or {}

    try:
        withdrawal_id = int(data.get("withdrawal_id", 0))
    except (ValueError, TypeError):
        return jsonify({"ok": False, "message": "Invalid ID"}), 400

    action = str(data.get("action", "")).strip()
    reason = str(data.get("reason", "")).strip()

    if action not in ("paid", "fraud_rejected", "normal_rejected"):
        return jsonify({"ok": False, "message": "Invalid action"}), 400

    if action != "paid" and not reason:
        return jsonify({
            "ok": False,
            "message": "Enter a rejection reason"
        }), 400

    con = connect()

    try:
        con.execute("BEGIN IMMEDIATE")

        row = con.execute("""
            SELECT * FROM withdrawals WHERE id=?
        """, (withdrawal_id,)).fetchone()

        if not row or row["status"] != "pending":
            con.rollback()
            return jsonify({
                "ok": False,
                "message": "Withdrawal not found or already processed"
            }), 404

        if action == "paid":
            con.execute("""
                UPDATE withdrawals
                SET status='paid', reason=?, updated_at=?
                WHERE id=?
            """, (reason, now_bd(), withdrawal_id))

            con.execute("""
                UPDATE users SET total_withdrawn=total_withdrawn+?
                WHERE user_id=?
            """, (row["amount_bdt"], row["user_id"]))

        elif action == "normal_rejected":
            con.execute("""
                UPDATE users SET coins=coins+?
                WHERE user_id=?
            """, (row["coins"], row["user_id"]))

            con.execute("""
                UPDATE withdrawals
                SET status='normal_rejected', reason=?,
                    refund_coins=?, updated_at=?
                WHERE id=?
            """, (reason, row["coins"], now_bd(), withdrawal_id))

        else:
            con.execute("""
                UPDATE withdrawals
                SET status='fraud_rejected', reason=?,
                    refund_coins=0, updated_at=?
                WHERE id=?
            """, (reason, now_bd(), withdrawal_id))

        con.commit()
        audit(action, f"Withdrawal #{withdrawal_id}: {reason}")

        return jsonify({"ok": True, "message": "Action completed"})

    except Exception:
        con.rollback()
        return jsonify({"ok": False, "message": "Action failed"}), 500

    finally:
        con.close()


@app.route("/api/admin/ban", methods=["POST"])
@admin_required
def admin_ban():
    data = request.get_json(silent=True) or {}

    try:
        user_id = int(data.get("user_id", 0))
        banned = int(data.get("banned", 1))
    except (ValueError, TypeError):
        return jsonify({"ok": False, "message": "Invalid data"}), 400

    if banned not in (0, 1):
        return jsonify({"ok": False, "message": "Invalid ban value"}), 400

    con = connect()
    con.execute(
        "UPDATE users SET banned=? WHERE user_id=?",
        (banned, user_id)
    )
    con.commit()
    con.close()

    audit("ban_user", f"user_id={user_id}, banned={banned}")

    return jsonify({"ok": True})


@app.route("/api/admin/balance", methods=["POST"])
@admin_required
def admin_balance():
    data = request.get_json(silent=True) or {}

    try:
        user_id = int(data.get("user_id", 0))
        coins = int(data.get("coins", 0))
    except (ValueError, TypeError):
        return jsonify({"ok": False, "message": "Invalid data"}), 400

    if coins == 0:
        return jsonify({"ok": False, "message": "Amount cannot be zero"}), 400

    con = connect()

    row = con.execute(
        "SELECT coins FROM users WHERE user_id=?",
        (user_id,)
    ).fetchone()

    if not row or row["coins"] + coins < 0:
        con.close()
        return jsonify({"ok": False, "message": "User not found or insufficient balance"}), 400

    con.execute(
        "UPDATE users SET coins=coins+? WHERE user_id=?",
        (coins, user_id)
    )
    con.commit()
    con.close()

    audit("balance_adjustment", f"user_id={user_id}, coins={coins}")

    return jsonify({"ok": True})


@app.route("/api/admin/audit")
@admin_required
def admin_audit():
    con = connect()

    rows = con.execute("""
        SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200
    """).fetchall()

    con.close()

    return jsonify({
        "ok": True,
        "logs": [dict(row) for row in rows]
    })


setup()



# AdsGram Reward integration - Block ID 59034
def ensure_adsgram_tables():
    con = connect()
    try:
        con.executescript("""
            CREATE TABLE IF NOT EXISTS adsgram_pending (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                rewarded INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS adsgram_rewards (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                coins INTEGER NOT NULL DEFAULT 50,
                created_at TEXT NOT NULL
            );
        """)
        con.commit()
    finally:
        con.close()

@app.route("/api/adsgram-session", methods=["POST"])
@user_required
def adsgram_session(user):
    ensure_adsgram_tables()
    token = secrets.token_urlsafe(32)
    con = connect()
    try:
        con.execute(
            "INSERT INTO adsgram_pending (token,user_id,created_at) VALUES (?,?,?)",
            (token, int(user["id"]), now_bd())
        )
        con.commit()
        return jsonify({"ok": True, "token": token})
    finally:
        con.close()

@app.route("/api/adsgram-reward", methods=["POST"])
@user_required
def adsgram_reward(user):
    ensure_adsgram_tables()
    ensure_monetag_tables()
    data = request.get_json(silent=True) or {}
    token = data.get("token", "")
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{30,100}", token):
        return jsonify({"ok": False, "message": "Invalid reward token"}), 400

    con = connect()
    try:
        con.execute("BEGIN IMMEDIATE")
        pending = con.execute(
            "SELECT user_id,rewarded FROM adsgram_pending WHERE token=?",
            (token,)
        ).fetchone()

        if not pending or int(pending["user_id"]) != int(user["id"]):
            con.rollback()
            return jsonify({"ok": False, "message": "Invalid session"}), 403

        if pending["rewarded"]:
            con.rollback()
            return jsonify({"ok": False, "message": "Already rewarded"}), 409

        cur = con.execute(
            "INSERT OR IGNORE INTO adsgram_rewards (token,user_id,coins,created_at) VALUES (?,?,50,?)",
            (token, int(user["id"]), now_bd())
        )
        if cur.rowcount != 1:
            con.rollback()
            return jsonify({"ok": False, "message": "Duplicate reward"}), 409

        cur = con.execute("""
            UPDATE users
            SET coins=coins+50,
                total_earned=total_earned+50,
                ads_since_withdraw=ads_since_withdraw+1
            WHERE user_id=?
        """, (int(user["id"]),))

        if cur.rowcount != 1:
            con.rollback()
            return jsonify({"ok": False, "message": "User not found"}), 404

        con.execute(
            "UPDATE adsgram_pending SET rewarded=1 WHERE token=?",
            (token,)
        )

        # Keep existing daily ad statistics compatible
        con.execute(
            "INSERT OR IGNORE INTO monetag_rewards (ymid,user_id,coins,created_at) VALUES (?,?,50,?)",
            (token, int(user["id"]), now_bd())
        )

        con.commit()
        return jsonify({"ok": True, "coins": 50})
    except Exception:
        con.rollback()
        app.logger.exception("AdsGram reward error")
        return jsonify({"ok": False, "message": "Server error"}), 500
    finally:
        con.close()


@app.route("/api/litebits-callback", methods=["POST"])
def litebits_callback():
    import os, json, time, hmac, hashlib, base64

    secret = os.getenv("LITEBITS_CALLBACK_SECRET", "")
    if not secret:
        return "Callback secret not configured", 503

    raw = request.get_data()
    timestamp = request.headers.get("x-lba-timestamp", "")
    event_id = request.headers.get("x-lba-event-id", "")
    signature = request.headers.get("x-lba-signature", "")

    try:
        ts = int(timestamp)
        if not event_id or abs(int(time.time()) - ts) > 300:
            return "Invalid timestamp or event id", 400

        expected = base64.urlsafe_b64encode(
            hmac.new(
                secret.encode(),
                timestamp.encode() + b"." + raw,
                hashlib.sha256
            ).digest()
        ).decode().rstrip("=")

        if not hmac.compare_digest(expected, signature):
            return "Invalid signature", 401

        data = json.loads(raw.decode("utf-8"))
        if data.get("event_id") and data["event_id"] != event_id:
            return "Event id mismatch", 400

        if data.get("event") != "impression.verified":
            return "Event ignored", 200

        user_id = int(data["telegram_user_id"])
        if user_id <= 0:
            return "Invalid user", 400

    except Exception:
        return "Invalid callback data", 400

    con = connect()
    try:
        con.execute("""
            CREATE TABLE IF NOT EXISTS litebits_events (
                event_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                coins INTEGER NOT NULL DEFAULT 50,
                created_at TEXT NOT NULL
            )
        """)
        con.execute("BEGIN IMMEDIATE")
        cur = con.execute(
            """INSERT OR IGNORE INTO litebits_events
               (event_id, user_id, coins, created_at)
               VALUES (?, ?, 50, datetime('now'))""",
            (event_id, user_id)
        )

        if cur.rowcount == 0:
            con.commit()
            return "Already processed", 200

        updated = con.execute(
            """UPDATE users
               SET coins=coins+50, total_earned=total_earned+50
               WHERE user_id=?""",
            (user_id,)
        )

        if updated.rowcount == 0:
            con.rollback()
            return "User not found", 404

        con.commit()
        return "Reward added", 200

    except Exception:
        con.rollback()
        app.logger.exception("LiteBits callback error")
        return "Server error", 500
    finally:
        con.close()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
