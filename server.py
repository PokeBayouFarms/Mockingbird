from flask import Flask, request, jsonify
import os
import json
import base64

app = Flask(__name__)

CLIENTS_FILE = "clients.json"
MAILBOX_DIR = "mailboxes"
CONFIG_FILE = "server_config.json"

os.makedirs(MAILBOX_DIR, exist_ok=True)
if not os.path.exists(CLIENTS_FILE):
    with open(CLIENTS_FILE, "w") as f:
        json.dump({}, f)

# ---------------- Helper Functions ----------------
def load_clients():
    with open(CLIENTS_FILE, "r") as f:
        return json.load(f)

def save_clients(clients):
    with open(CLIENTS_FILE, "w") as f:
        json.dump(clients, f, indent=2)

def get_mailbox(username):
    path = os.path.join(MAILBOX_DIR, f"{username}.json")
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        return json.load(f)

def save_mailbox(username, messages):
    path = os.path.join(MAILBOX_DIR, f"{username}.json")
    with open(path, "w") as f:
        json.dump(messages, f, indent=2)

def load_config():
    default_config = {"host": "0.0.0.0", "port": 5000, "public_host": None, "public_port": None}
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            cfg = json.load(f)
            default_config.update(cfg)
    return default_config

# ---------------- Routes ----------------
@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    public_key = data.get("public_key")
    if not username or not public_key:
        return jsonify({"error": "Missing username or public_key"}), 400

    clients = load_clients()
    clients[username] = public_key
    save_clients(clients)
    return jsonify({"status": "registered"})

@app.route("/send", methods=["POST"])
def send_message():
    data = request.json
    recipient = data.get("recipient")
    sender = data.get("sender")
    encrypted_key = data.get("encrypted_key")
    ciphertext = data.get("ciphertext")
    signature = data.get("signature")

    if not all([recipient, sender, encrypted_key, ciphertext, signature]):
        return jsonify({"error": "Incomplete message"}), 400

    clients = load_clients()
    if recipient not in clients:
        return jsonify({"error": f"Recipient {recipient} not found"}), 404
    if sender not in clients:
        return jsonify({"error": f"Sender {sender} not found"}), 404

    mailbox = get_mailbox(recipient)
    mailbox.append({
        "sender": sender,
        "encrypted_key": encrypted_key,
        "ciphertext": ciphertext,
        "signature": signature
    })
    save_mailbox(recipient, mailbox)
    return jsonify({"status": "message stored"})

@app.route("/inbox/<username>", methods=["GET"])
def get_inbox(username):
    mailbox = get_mailbox(username)
    save_mailbox(username, [])
    return jsonify(mailbox)

@app.route("/clients", methods=["GET"])
def list_clients():
    return jsonify(load_clients())

# ---------------- Run Server ----------------
if __name__ == "__main__":
    config = load_config()
    host = config["host"]
    port = config["port"]
    print(f"Server starting on {host}:{port}...")
    app.run(host=host, port=port)
