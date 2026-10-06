"""УЯЗВИМАЯ версия API (учебная). Используется для демонстрации находок SAST/DAST."""
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)
SECRET_KEY = "admin123"          # A07: захардкоженный секрет
_conn = sqlite3.connect(":memory:", check_same_thread=False)
_conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, email TEXT)")


@app.route("/api/users", methods=["POST"])
def create_user():
    data = request.get_json(force=True)
    # A03: SQL Injection (конкатенация строки)
    query = "INSERT INTO users (name, email) VALUES ('%s', '%s')" % (data.get("name"), data.get("email"))
    _conn.execute(query)
    _conn.commit()
    return jsonify({"status": "created"}), 201


@app.route("/api/users", methods=["GET"])
def get_users():
    name = request.args.get("name", "")
    # A03: SQL Injection
    query = f"SELECT id, name, email FROM users WHERE name LIKE '%{name}%'"
    try:
        rows = _conn.execute(query).fetchall()
    except sqlite3.Error as e:
        return jsonify({"error": str(e), "query": query}), 500   # A05: утечка деталей
    return jsonify([{"id": r[0], "name": r[1], "email": r[2]} for r in rows])


@app.route("/api/users/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):
    # A01: Broken Access Control - нет аутентификации
    _conn.execute("DELETE FROM users WHERE id = %d" % user_id)
    _conn.commit()
    return jsonify({"status": "deleted"})


@app.route("/users", methods=["GET"])
def users_page():
    # A03: XSS - данные выводятся в HTML без экранирования
    rows = _conn.execute("SELECT name FROM users").fetchall()
    items = "".join("<li>%s</li>" % r[0] for r in rows)
    return "<html><body><h1>Users</h1><ul>%s</ul></body></html>" % items


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)   # A05: debug=True, 0.0.0.0
