import os, secrets, string, hmac
from datetime import datetime, timedelta, timezone
import psycopg2, psycopg2.extras
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)
DB = os.environ["DATABASE_URL"]
ADMIN = os.environ["ADMIN_PASSWORD"]
ALPHA = string.ascii_letters + string.digits

def db():
    return psycopg2.connect(DB, cursor_factory=psycopg2.extras.RealDictCursor)

def init():
    with db() as c, c.cursor() as q:
        q.execute("""CREATE TABLE IF NOT EXISTS keys(
            key TEXT PRIMARY KEY, duration_hours INT NOT NULL, max_devices INT NOT NULL,
            created_at TIMESTAMPTZ DEFAULT now(), activated_at TIMESTAMPTZ,
            revoked BOOLEAN DEFAULT FALSE, note TEXT DEFAULT '');
        CREATE TABLE IF NOT EXISTS devices(
            key TEXT REFERENCES keys(key) ON DELETE CASCADE, device_id TEXT,
            first_seen TIMESTAMPTZ DEFAULT now(), PRIMARY KEY(key, device_id));""")
init()

def is_admin():
    return hmac.compare_digest(request.headers.get("X-Admin", ""), ADMIN)

def admin_only(f):
    def w(*a, **k):
        if not is_admin():
            return jsonify(error="Wrong admin password"), 401
        return f(*a, **k)
    w.__name__ = f.__name__
    return w

def now():
    return datetime.now(timezone.utc)

@app.get("/")
def home():
    return render_template("index.html")

# ---------- PUBLIC: your app calls this ----------
@app.post("/api/verify")
def verify():
    d = request.get_json(silent=True) or {}
    key, dev = (d.get("key") or "").strip(), (d.get("device_id") or "").strip()
    if not key or not dev:
        return jsonify(valid=False, reason="missing_fields"), 400
    with db() as c, c.cursor() as q:
        q.execute("SELECT * FROM keys WHERE key=%s FOR UPDATE", (key,))
        k = q.fetchone()
        if not k:
            return jsonify(valid=False, reason="invalid_key"), 404
        if k["revoked"]:
            return jsonify(valid=False, reason="revoked"), 403
        if k["activated_at"] is None:   # timer starts on first login
            q.execute("UPDATE keys SET activated_at=now() WHERE key=%s RETURNING activated_at", (key,))
            k["activated_at"] = q.fetchone()["activated_at"]
        exp = k["activated_at"] + timedelta(hours=k["duration_hours"])
        if now() > exp:
            return jsonify(valid=False, reason="expired"), 403
        q.execute("SELECT device_id FROM devices WHERE key=%s", (key,))
        ids = [r["device_id"] for r in q.fetchall()]
        if dev not in ids:
            if len(ids) >= k["max_devices"]:
                return jsonify(valid=False, reason="device_limit"), 403
            q.execute("INSERT INTO devices(key, device_id) VALUES(%s,%s)", (key, dev))
    return jsonify(valid=True, expires_at=exp.isoformat(), devices_used=len(set(ids + [dev])), max_devices=k["max_devices"])

# ---------- ADMIN ----------
@app.post("/admin/generate")
@admin_only
def generate():
    d = request.get_json(force=True)
    hours = max(1, int(d.get("hours", 720)))
    devs = max(1, int(d.get("devices", 1)))
    count = min(100, max(1, int(d.get("count", 1))))
    custom = (d.get("custom") or "").strip()
    note = (d.get("note") or "")[:100]
    made = []
    with db() as c, c.cursor() as q:
        for _ in range(1 if custom else count):
            key = custom or "Shadow-" + "".join(secrets.choice(ALPHA) for _ in range(12))
            if not all(ch.isalnum() or ch in "-_" for ch in key):
                return jsonify(error="Custom key: letters, numbers, - and _ only"), 400
            q.execute("INSERT INTO keys(key,duration_hours,max_devices,note) VALUES(%s,%s,%s,%s) ON CONFLICT DO NOTHING RETURNING key",
                      (key, hours, devs, note))
            if q.fetchone():
                made.append(key)
            elif custom:
                return jsonify(error="That key already exists"), 409
    return jsonify(keys=made)

@app.get("/admin/list")
@admin_only
def lst():
    with db() as c, c.cursor() as q:
        q.execute("""SELECT k.*, (SELECT count(*) FROM devices d WHERE d.key=k.key) AS used
                     FROM keys k ORDER BY created_at DESC LIMIT 500""")
        rows = q.fetchall()
    out = []
    for r in rows:
        exp = r["activated_at"] + timedelta(hours=r["duration_hours"]) if r["activated_at"] else None
        status = "revoked" if r["revoked"] else "unused" if not exp else "expired" if now() > exp else "active"
        out.append(dict(key=r["key"], status=status, hours=r["duration_hours"], devices=r["max_devices"],
                        used=r["used"], note=r["note"], expires_at=exp.isoformat() if exp else None))
    return jsonify(keys=out)

@app.post("/admin/reset")
@admin_only
def reset():
    with db() as c, c.cursor() as q:
        q.execute("DELETE FROM devices WHERE key=%s", (request.get_json(force=True)["key"],))
    return jsonify(ok=True)

@app.post("/admin/revoke")
@admin_only
def revoke():
    d = request.get_json(force=True)
    with db() as c, c.cursor() as q:
        q.execute("UPDATE keys SET revoked=%s WHERE key=%s", (bool(d.get("revoked", True)), d["key"]))
    return jsonify(ok=True)

@app.post("/admin/delete")
@admin_only
def delete():
    with db() as c, c.cursor() as q:
        q.execute("DELETE FROM keys WHERE key=%s", (request.get_json(force=True)["key"],))
    return jsonify(ok=True)
