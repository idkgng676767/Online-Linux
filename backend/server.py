#!/usr/bin/env python3
"""
Online Linux — Backend Server
User management + 1GB persistent file storage per user.
"""

import os
import sqlite3
import hashlib
import hmac
import secrets
import json
import shutil
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, request, jsonify, send_file, g
from flask_cors import CORS
import jwt

# ── Config ──────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
USER_STORAGE_DIR = os.path.join(DATA_DIR, "user_files")
DB_PATH = os.path.join(DATA_DIR, "users.db")
JWT_SECRET = os.environ.get("JWT_SECRET", secrets.token_hex(32))
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 72
STORAGE_QUOTA_BYTES = 1 * 1024 * 1024 * 1024  # 1 GB

os.makedirs(USER_STORAGE_DIR, exist_ok=True)

app = Flask(__name__)
CORS(app, origins="*", supports_credentials=True)

# ── Database ────────────────────────────────────────────────────
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_login TEXT
        )
    """)
    db.commit()
    db.close()


# ── Password hashing ────────────────────────────────────────────
def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    if salt is None:
        salt = secrets.token_hex(16)
    pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200000).hex()
    return pw_hash, salt


def verify_password(password: str, pw_hash: str, salt: str) -> bool:
    computed, _ = hash_password(password, salt)
    return hmac.compare_digest(computed, pw_hash)


# ── JWT ─────────────────────────────────────────────────────────
def create_token(username: str, user_id: int) -> str:
    payload = {
        "sub": username,
        "uid": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRY_HOURS),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid token"}), 401
        token = auth_header[7:]
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            g.current_user = payload["sub"]
            g.current_user_id = payload["uid"]
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated


# ── File helpers ────────────────────────────────────────────────
def user_dir(username: str) -> str:
    d = os.path.join(USER_STORAGE_DIR, username)
    os.makedirs(d, exist_ok=True)
    return d


def safe_path(username: str, rel_path: str) -> str | None:
    """Resolve a relative path safely under the user's directory (no traversal)."""
    base = user_dir(username)
    full = os.path.normpath(os.path.join(base, rel_path))
    if not full.startswith(base + os.sep) and full != base:
        return None
    return full


def get_storage_used(username: str) -> int:
    total = 0
    base = user_dir(username)
    for root, dirs, files in os.walk(base):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total


# ── Auth routes ─────────────────────────────────────────────────
@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if len(username) < 2 or len(username) > 32:
        return jsonify({"error": "Username must be 2-32 characters"}), 400
    if len(password) < 4:
        return jsonify({"error": "Password must be at least 4 characters"}), 400
    if not username.isalnum() and "_" not in username and "-" not in username:
        return jsonify({"error": "Username can only contain letters, numbers, _ and -"}), 400

    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if existing:
        return jsonify({"error": "Username already taken"}), 409

    pw_hash, salt = hash_password(password)
    now = datetime.now(timezone.utc).isoformat()
    cursor = db.execute(
        "INSERT INTO users (username, password_hash, salt, created_at, last_login) VALUES (?, ?, ?, ?, ?)",
        (username, pw_hash, salt, now, now),
    )
    db.commit()
    user_id = cursor.lastrowid

    os.makedirs(user_dir(username), exist_ok=True)

    token = create_token(username, user_id)
    return jsonify({"token": token, "username": username}), 201


@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    db = get_db()
    row = db.execute("SELECT id, password_hash, salt FROM users WHERE username = ?", (username,)).fetchone()
    if not row:
        return jsonify({"error": "Invalid username or password"}), 401

    if not verify_password(password, row["password_hash"], row["salt"]):
        return jsonify({"error": "Invalid username or password"}), 401

    now = datetime.now(timezone.utc).isoformat()
    db.execute("UPDATE users SET last_login = ? WHERE id = ?", (now, row["id"]))
    db.commit()

    token = create_token(username, row["id"])
    return jsonify({"token": token, "username": username}), 200


@app.route("/api/auth/me", methods=["GET"])
@require_auth
def me():
    db = get_db()
    row = db.execute("SELECT username, created_at, last_login FROM users WHERE id = ?", (g.current_user_id,)).fetchone()
    if not row:
        return jsonify({"error": "User not found"}), 404
    return jsonify({
        "username": row["username"],
        "created_at": row["created_at"],
        "last_login": row["last_login"],
        "storage_used": get_storage_used(row["username"]),
        "storage_limit": STORAGE_QUOTA_BYTES,
    })


# ── File routes ─────────────────────────────────────────────────
@app.route("/api/files/upload", methods=["POST"])
@require_auth
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "Empty filename"}), 400

    rel_path = request.form.get("path", "").strip("/")
    username = g.current_user

    # Check quota
    current_used = get_storage_used(username)
    file.seek(0, 2)
    file_size = file.tell()
    file.seek(0)

    if current_used + file_size > STORAGE_QUOTA_BYTES:
        remaining = STORAGE_QUOTA_BYTES - current_used
        return jsonify({"error": f"Storage quota exceeded. {remaining} bytes remaining"}), 413

    dest_dir = user_dir(username)
    if rel_path:
        dest_dir = safe_path(username, rel_path)
        if dest_dir is None:
            return jsonify({"error": "Invalid path"}), 400
        os.makedirs(dest_dir, exist_ok=True)

    # Sanitize filename
    safe_name = os.path.basename(file.filename).replace("..", "")
    if not safe_name:
        safe_name = "unnamed_file"
    dest_path = os.path.join(dest_dir, safe_name)

    file.save(dest_path)
    return jsonify({
        "path": os.path.relpath(dest_path, user_dir(username)),
        "size": os.path.getsize(dest_path),
    }), 201


@app.route("/api/files/list", methods=["GET"])
@require_auth
def list_files():
    rel_path = request.args.get("path", "").strip("/")
    username = g.current_user

    target = safe_path(username, rel_path) if rel_path else user_dir(username)
    if target is None:
        return jsonify({"error": "Invalid path"}), 400
    if not os.path.isdir(target):
        return jsonify({"error": "Not a directory"}), 404

    files = []
    try:
        entries = os.scandir(target)
    except OSError:
        return jsonify({"files": []}), 200

    for entry in entries:
        try:
            stat = entry.stat()
            files.append({
                "name": entry.name,
                "path": os.path.relpath(entry.path, user_dir(username)),
                "size": stat.st_size if entry.is_file() else 0,
                "type": "file" if entry.is_file() else "folder",
                "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            })
        except OSError:
            continue

    files.sort(key=lambda x: (x["type"] != "folder", x["name"].lower()))
    return jsonify({"files": files}), 200


@app.route("/api/files/download", methods=["GET"])
@require_auth
def download_file():
    rel_path = request.args.get("path", "").strip("/")
    if not rel_path:
        return jsonify({"error": "No path specified"}), 400

    username = g.current_user
    full_path = safe_path(username, rel_path)
    if full_path is None:
        return jsonify({"error": "Invalid path"}), 400
    if not os.path.isfile(full_path):
        return jsonify({"error": "File not found"}), 404

    return send_file(full_path, as_attachment=True, download_name=os.path.basename(full_path))


@app.route("/api/files/delete", methods=["DELETE"])
@require_auth
def delete_file():
    rel_path = request.args.get("path", "").strip("/")
    if not rel_path:
        return jsonify({"error": "No path specified"}), 400

    username = g.current_user
    full_path = safe_path(username, rel_path)
    if full_path is None:
        return jsonify({"error": "Invalid path"}), 400
    if not os.path.exists(full_path):
        return jsonify({"error": "Not found"}), 404

    if os.path.isdir(full_path):
        shutil.rmtree(full_path)
    else:
        os.remove(full_path)

    return jsonify({"success": True}), 200


@app.route("/api/files/mkdir", methods=["POST"])
@require_auth
def make_dir():
    data = request.get_json(force=True)
    rel_path = (data.get("path") or "").strip("/")
    if not rel_path:
        return jsonify({"error": "No path specified"}), 400

    username = g.current_user
    full_path = safe_path(username, rel_path)
    if full_path is None:
        return jsonify({"error": "Invalid path"}), 400

    os.makedirs(full_path, exist_ok=True)
    return jsonify({"success": True}), 201


@app.route("/api/files/quota", methods=["GET"])
@require_auth
def get_quota():
    username = g.current_user
    used = get_storage_used(username)
    return jsonify({
        "used": used,
        "limit": STORAGE_QUOTA_BYTES,
        "available": max(0, STORAGE_QUOTA_BYTES - used),
        "used_mb": round(used / (1024 * 1024), 2),
        "limit_mb": round(STORAGE_QUOTA_BYTES / (1024 * 1024), 2),
    }), 200


# ── Admin routes (list users, delete user) ──────────────────────
@app.route("/api/admin/users", methods=["GET"])
@require_auth
def admin_list_users():
    db = get_db()
    rows = db.execute("SELECT id, username, created_at, last_login FROM users ORDER BY id").fetchall()
    users = []
    for r in rows:
        users.append({
            "id": r["id"],
            "username": r["username"],
            "created_at": r["created_at"],
            "last_login": r["last_login"],
            "storage_used": get_storage_used(r["username"]),
        })
    return jsonify({"users": users}), 200


@app.route("/api/admin/users/<int:user_id>", methods=["DELETE"])
@require_auth
def admin_delete_user(user_id):
    db = get_db()
    row = db.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        return jsonify({"error": "User not found"}), 404

    username = row["username"]
    # Delete user files
    udir = user_dir(username)
    if os.path.isdir(udir):
        shutil.rmtree(udir)
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    return jsonify({"success": True, "deleted": username}), 200


# ── Health ──────────────────────────────────────────────────────
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "version": "1.0.0"}), 200


# ── CLI: manage users from command line ─────────────────────────
def cli():
    import sys
    if len(sys.argv) < 2:
        print("Usage: python server.py <command> [args]")
        print("Commands:")
        print("  run                          Start the server")
        print("  user-list                    List all users")
        print("  user-add <username> <pass>   Create a user")
        print("  user-del <username>          Delete a user")
        print("  user-pass <username> <pass>  Reset a user's password")
        print("  quota <username>             Show user's storage usage")
        return

    cmd = sys.argv[1]
    init_db()

    if cmd == "run":
        port = int(os.environ.get("PORT", "5001"))
        print(f"Starting Online Linux backend on port {port}...")
        print(f"JWT_SECRET: {JWT_SECRET[:8]}...")
        print(f"Storage quota: 1 GB per user")
        app.run(host="0.0.0.0", port=port, debug=True)

    elif cmd == "user-list":
        db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
        rows = db.execute("SELECT id, username, created_at, last_login FROM users ORDER BY id").fetchall()
        if not rows:
            print("No users found.")
        for r in rows:
            used = get_storage_used(r["username"])
            print(f"  [{r['id']}] {r['username']}  created={r['created_at'][:19]}  storage={used/(1024*1024):.1f}MB")
        db.close()

    elif cmd == "user-add":
        if len(sys.argv) < 4:
            print("Usage: python server.py user-add <username> <password>")
            sys.exit(1)
        username, password = sys.argv[2], sys.argv[3]
        db = sqlite3.connect(DB_PATH)
        existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if existing:
            print(f"User '{username}' already exists (id={existing[0]})")
            sys.exit(1)
        pw_hash, salt = hash_password(password)
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO users (username, password_hash, salt, created_at, last_login) VALUES (?, ?, ?, ?, ?)",
            (username, pw_hash, salt, now, now),
        )
        db.commit()
        os.makedirs(user_dir(username), exist_ok=True)
        print(f"User '{username}' created successfully.")

    elif cmd == "user-del":
        if len(sys.argv) < 3:
            print("Usage: python server.py user-del <username>")
            sys.exit(1)
        username = sys.argv[2]
        db = sqlite3.connect(DB_PATH)
        row = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if not row:
            print(f"User '{username}' not found.")
            sys.exit(1)
        udir = user_dir(username)
        if os.path.isdir(udir):
            shutil.rmtree(udir)
        db.execute("DELETE FROM users WHERE username = ?", (username,))
        db.commit()
        print(f"User '{username}' deleted.")

    elif cmd == "user-pass":
        if len(sys.argv) < 4:
            print("Usage: python server.py user-pass <username> <newpassword>")
            sys.exit(1)
        username, password = sys.argv[2], sys.argv[3]
        db = sqlite3.connect(DB_PATH)
        row = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if not row:
            print(f"User '{username}' not found.")
            sys.exit(1)
        pw_hash, salt = hash_password(password)
        db.execute("UPDATE users SET password_hash = ?, salt = ? WHERE username = ?", (pw_hash, salt, username))
        db.commit()
        print(f"Password updated for '{username}'.")

    elif cmd == "quota":
        if len(sys.argv) < 3:
            print("Usage: python server.py quota <username>")
            sys.exit(1)
        username = sys.argv[2]
        used = get_storage_used(username)
        print(f"User '{username}': {used/(1024*1024):.2f} MB / {STORAGE_QUOTA_BYTES/(1024*1024):.0f} MB")

    else:
        print(f"Unknown command: {cmd}")


if __name__ == "__main__":
    init_db()
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "run":
        # Default to port 5001 to avoid macOS AirPlay conflict on 5000
        os.environ.setdefault("PORT", "5001")
    cli()
