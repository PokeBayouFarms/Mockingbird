import os
import json
import sqlite3
import base64
import time
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)
DB_FILE = "server.db"

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS clients (
                username TEXT PRIMARY KEY,
                public_key TEXT NOT NULL,
                registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS mailboxes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recipient TEXT NOT NULL,
                sender TEXT NOT NULL,
                message_data TEXT NOT NULL,
                received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (recipient) REFERENCES clients (username),
                FOREIGN KEY (sender) REFERENCES clients (username)
            )
        ''')
        conn.commit()

init_db()

def verify_signature(public_key_b64, message, signature_b64):
    try:
        public_key = serialization.load_pem_public_key(base64.b64decode(public_key_b64))
        public_key.verify(
            base64.b64decode(signature_b64),
            message.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    public_key = data.get("public_key")
    if not username or not public_key:
        return jsonify({"error": "Missing username or public_key"}), 400
    if not username.isalnum() or len(username) > 50:
        return jsonify({"error": "Invalid username format"}), 400
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO clients (username, public_key) VALUES (?, ?)",
                (username, public_key)
            )
            conn.commit()
        return jsonify({"status": f"User '{username}' registered successfully."})
    except sqlite3.Error as e:
        return jsonify({"error": "Database error", "details": str(e)}), 500

@app.route("/send", methods=["POST"])
def send_message():
    data = request.json
    required_fields = ["recipient", "sender", "encrypted_key", "ciphertext", "signature"]
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Incomplete message payload"}), 400
    message_to_verify = f"{data['sender']}:{data['recipient']}:{data['encrypted_key']}:{data['ciphertext']}"
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT public_key FROM clients WHERE username = ?", (data['sender'],))
        sender_row = cursor.fetchone()
        if not sender_row:
            return jsonify({"error": "Sender not found"}), 404
        if not verify_signature(sender_row[0], message_to_verify, data['signature']):
            return jsonify({"error": "Invalid signature. Authentication failed."}), 403
        cursor.execute("SELECT 1 FROM clients WHERE username = ?", (data['recipient'],))
        if not cursor.fetchone():
            return jsonify({"error": "Recipient not found"}), 404
        message_data_str = json.dumps({
            "encrypted_key": data["encrypted_key"],
            "ciphertext": data["ciphertext"],
            "signature": data["signature"]
        })
        cursor.execute(
            "INSERT INTO mailboxes (recipient, sender, message_data) VALUES (?, ?, ?)",
            (data['recipient'], data['sender'], message_data_str)
        )
        conn.commit()
    return jsonify({"status": "Message successfully sent and stored."})

@app.route("/inbox/<username>", methods=["GET"])
def get_inbox(username):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Signature "):
        return jsonify({"error": "Missing authorization signature"}), 401
    signature_b64 = auth_header.split(" ")[1]
    message_to_verify = username
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT public_key FROM clients WHERE username = ?", (username,))
        user_row = cursor.fetchone()
        if not user_row:
            return jsonify({"error": "User not found"}), 404
        if not verify_signature(user_row[0], message_to_verify, signature_b64):
            return jsonify({"error": "Invalid authorization signature"}), 403
        cursor.execute(
            "SELECT id, sender, message_data FROM mailboxes WHERE recipient = ?",
            (username,)
        )
        messages = cursor.fetchall()
        if not messages:
            return jsonify([])
        inbox = []
        message_ids_to_delete = []
        for msg_id, sender, message_data_str in messages:
            message_data = json.loads(message_data_str)
            inbox.append({
                "sender": sender,
                **message_data
            })
            message_ids_to_delete.append((msg_id,))
        cursor.executemany("DELETE FROM mailboxes WHERE id = ?", message_ids_to_delete)
        conn.commit()
    return jsonify(inbox)

@app.route("/clients", methods=["GET"])
def list_clients():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username, public_key FROM clients")
        clients = {row[0]: row[1] for row in cursor.fetchall()}
    return jsonify(clients)

if __name__ == "__main__":
    print("Server starting on http://127.0.0.1:5000...")
    print("NOTE: This is a development server. For production, use 'gunicorn server:app'")
    app.run(host="127.0.0.1", port=5000, debug=True)
