from flask import Flask, jsonify, request

app = Flask(__name__)

# Простая база данных в памяти
users = [
    {"id": 1, "name": "Alice", "email": "alice@example.com"},
    {"id": 2, "name": "Bob", "email": "bob@example.com"},
]


@app.route("/api/users", methods=["GET"])
def get_users():
  return jsonify(users), 200


@app.route("/api/users", methods=["POST"])
def create_user():
  data = request.get_json()
  new_user = {
      "id": len(users) + 1,
      "name": data.get("name"),
      "email": data.get("email"),
  }
  users.append(new_user)
  return jsonify(new_user), 201


@app.route("/api/users/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):
  global users
  users = [u for u in users if u["id"] != user_id]
  return jsonify({"message": "User deleted"}), 200


if __name__ == "__main__":
  # debug=True вызовет предупреждение в Bandit (Security Misconfiguration)
  app.run(host="0.0.0.0", port=5000, debug=True)