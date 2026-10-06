"""ИСПРАВЛЕННАЯ версия API."""
import os
import re
import sqlite3
from html import escape
from hmac import compare_digest
from flask import Flask, request, jsonify

app = Flask(__name__)
API_KEY = os.environ.get("API_KEY", "")          # секрет из окружения
_conn = sqlite3.connect(":memory:", check_same_thread=False)
_conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, email TEXT)")

NAME_RE = re.compile(r"^[A-Za-zА-Яа-яЁё0-9 _.\-]{1,50}$")
EMAIL_RE = re.compile(r"^[^@\s<>'\"]+@[^@\s<>'\"]+\.[^@\s<>'\"]+$")


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/api/users", methods=["POST"])
def create_user():
    data = request.get_json(silent=True) or {}
    name, email = data.get("name"), data.get("email")
    if not isinstance(name, str) or not NAME_RE.match(name):
        return jsonify({"error": "invalid name"}), 400
    if not isinstance(email, str) or not EMAIL_RE.match(email) or len(email) > 100:
        return jsonify({"error": "invalid email"}), 400
    _conn.execute("INSERT INTO users (name, email) VALUES (?, ?)", (name, email))
    _conn.commit()
    return jsonify({"status": "created"}), 201


@app.route("/api/users", methods=["GET"])
def get_users():
    name = request.args.get("name", "")[:50]
    rows = _conn.execute(
        "SELECT id, name, email FROM users WHERE name LIKE ?", (f"%{name}%",)
    ).fetchall()
    return jsonify([{"id": r[0], "name": r[1], "email": r[2]} for r in rows])


@app.route("/api/users/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):
    key = request.headers.get("X-API-Key", "")
    if not API_KEY or not compare_digest(key, API_KEY):
        return jsonify({"error": "unauthorized"}), 401
    _conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    _conn.commit()
    return jsonify({"status": "deleted"})


@app.route("/users", methods=["GET"])
def users_page():
    rows = _conn.execute("SELECT name FROM users").fetchall()
    items = "".join("<li>%s</li>" % escape(r[0]) for r in rows)
    return "<html><body><h1>Users</h1><ul>%s</ul></body></html>" % items


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
