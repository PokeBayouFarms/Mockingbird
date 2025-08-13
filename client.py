import os
import json
import base64
import pyotp
import keyring
import tkinter as tk
from tkinter import messagebox, ttk
from PIL import Image, ImageTk
import qrcode
import requests
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

CONFIG_FILE = "config.json"
PUBLIC_KEY_FILE = "public_key.pem"
ENCRYPTED_KEY_FILE = "private_key.enc"
TOTP_KEYRING_SERVICE = "Mockingbird_TOTP"
ISSUER_NAME = "Mockingbird"

# ---------------- Encryption / Signing Helpers ----------------
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_data(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return iv + encryptor.update(data) + encryptor.finalize()

def decrypt_data(data, key):
    iv = data[:16]
    ct = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()

def aes_encrypt(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(message) + encryptor.finalize()
    return iv + ct

def aes_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()

def encrypt_for_recipient(message_bytes, recipient_pub_bytes):
    pub_key = serialization.load_pem_public_key(recipient_pub_bytes)
    session_key = os.urandom(32)
    encrypted_msg = aes_encrypt(message_bytes, session_key)
    encrypted_key = pub_key.encrypt(
        session_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )
    return base64.b64encode(encrypted_key).decode(), base64.b64encode(encrypted_msg).decode()

def decrypt_from_sender(encrypted_key_b64, encrypted_msg_b64, private_key_bytes):
    private_key = serialization.load_pem_private_key(private_key_bytes, password=None)
    encrypted_key = base64.b64decode(encrypted_key_b64)
    ciphertext = base64.b64decode(encrypted_msg_b64)
    session_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )
    return aes_decrypt(ciphertext, session_key)

def sign_message(private_key_bytes, message_bytes):
    private_key = serialization.load_pem_private_key(private_key_bytes, password=None)
    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

def verify_signature(public_key_bytes, message_bytes, signature_b64):
    public_key = serialization.load_pem_public_key(public_key_bytes)
    try:
        public_key.verify(
            base64.b64decode(signature_b64),
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# ---------------- GUI ----------------
class SecureApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.withdraw()  # Hide main window until setup/unlock complete

        self.private_key_bytes = None
        self.username = None
        self.server_url = None
        self.first_run_success = False

        self.check_first_run()  # Blocks until done

        if not self.first_run_success:
            self.destroy()
            return

        self.deiconify()
        self.title("Mockingbird Messaging App")
        self.geometry("650x800")
        self.resizable(False, False)

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(expand=True, fill="both")

        self.messaging_frame = ttk.Frame(self.notebook)
        self.server_frame = ttk.Frame(self.notebook)

        self.notebook.add(self.messaging_frame, text="Messaging")
        self.notebook.add(self.server_frame, text="Server")

        self.setup_server_tab()
        self.setup_messaging_tab()

    # ---------------- First Run / Unlock ----------------
    def check_first_run(self):
        if not os.path.exists(ENCRYPTED_KEY_FILE):
            self.first_run_setup()
        else:
            self.unlock_popup()

    def first_run_setup(self):
        popup = tk.Toplevel()
        popup.title("First Time Setup")
        popup.grab_set()
        tk.Label(popup, text="=== First Time Setup ===", font=("Arial", 14)).pack(pady=5)

        tk.Label(popup, text="Create username:").pack()
        username_entry = tk.Entry(popup)
        username_entry.pack(pady=5)

        tk.Label(popup, text="Create password:").pack()
        pw_entry = tk.Entry(popup, show="*")
        pw_entry.pack(pady=5)

        def do_setup():
            username = username_entry.get().strip()
            password = pw_entry.get()
            if not username or not password:
                messagebox.showwarning("Warning", "Both fields are required")
                return
            self.username = username

            # RSA key
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            self.private_key_bytes = private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            )
            public_bytes = private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open(PUBLIC_KEY_FILE, "wb") as f:
                f.write(public_bytes)

            # Encrypt private key
            salt = os.urandom(16)
            key_bytes = derive_key(password, salt)
            enc_private = encrypt_data(self.private_key_bytes, key_bytes)
            with open(ENCRYPTED_KEY_FILE, "wb") as f:
                f.write(salt + enc_private)

            # TOTP
            totp_secret = pyotp.random_base32()
            keyring.set_password(TOTP_KEYRING_SERVICE, "user_totp", totp_secret)
            config = {"account_name": self.username, "issuer_name": ISSUER_NAME}
            with open(CONFIG_FILE, "w") as f:
                json.dump(config, f)

            # QR code
            uri = pyotp.TOTP(totp_secret).provisioning_uri(name=self.username, issuer_name=ISSUER_NAME)
            qr_img = qrcode.make(uri).resize((250, 250))
            self.qr_photo = ImageTk.PhotoImage(qr_img)
            qr_label = tk.Label(popup, image=self.qr_photo)
            qr_label.pack(pady=10)

            messagebox.showinfo("Setup Complete", "Scan the QR code in your authenticator app.")
            self.first_run_success = True
            popup.destroy()

        tk.Button(popup, text="Setup", command=do_setup).pack(pady=5)
        popup.wait_window()

    def unlock_popup(self):
        popup = tk.Toplevel()
        popup.title("Unlock")
        popup.grab_set()
        tk.Label(popup, text="=== Unlock Private Key ===", font=("Arial", 14)).pack(pady=5)

        tk.Label(popup, text="Password:").pack()
        pw_entry = tk.Entry(popup, show="*")
        pw_entry.pack(pady=5)

        tk.Label(popup, text="TOTP code:").pack()
        totp_entry = tk.Entry(popup)
        totp_entry.pack(pady=5)

        def do_unlock():
            password = pw_entry.get()
            totp_code = totp_entry.get()
            totp_secret = keyring.get_password(TOTP_KEYRING_SERVICE, "user_totp")
            if totp_secret is None:
                messagebox.showerror("Error", "TOTP secret not found!")
                return
            totp = pyotp.TOTP(totp_secret)
            if not totp.verify(totp_code):
                messagebox.showerror("Error", "Invalid TOTP code!")
                return
            with open(ENCRYPTED_KEY_FILE, "rb") as f:
                data = f.read()
            salt, enc_private = data[:16], data[16:]
            key_bytes = derive_key(password, salt)
            try:
                self.private_key_bytes = decrypt_data(enc_private, key_bytes)
                with open(CONFIG_FILE, "r") as f:
                    cfg = json.load(f)
                    self.username = cfg.get("account_name", self.username)
                self.first_run_success = True
                popup.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to decrypt private key: {e}")

        tk.Button(popup, text="Unlock", command=do_unlock).pack(pady=5)
        popup.wait_window()

    # ---------------- Server Tab ----------------
    def setup_server_tab(self):
        tk.Label(self.server_frame, text="Server hostname:").pack()
        self.server_entry = tk.Entry(self.server_frame)
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r") as f:
                cfg = json.load(f)
                self.server_url = cfg.get("server_url")
                if self.server_url:
                    self.server_entry.insert(0, self.server_url.replace("http://",""))
        self.server_entry.pack(pady=5)

        tk.Button(self.server_frame, text="Register / Reregister", command=self.register_to_server).pack(pady=5)
        tk.Button(self.server_frame, text="Query Registered Users", command=self.query_recipients).pack(pady=5)

        self.reregister_status = tk.Text(self.server_frame, height=10, width=70)
        self.reregister_status.pack(pady=5)
        self.clients_text = tk.Text(self.server_frame, height=15, width=70)
        self.clients_text.pack(pady=5)

    def register_to_server(self):
        server_host = self.server_entry.get().strip()
        if not server_host:
            messagebox.showwarning("Warning", "Enter a server hostname")
            return
        server_url = f"http://{server_host}"
        with open(PUBLIC_KEY_FILE, "rb") as f:
            public_bytes = f.read()

        def reg_thread():
            try:
                r = requests.post(f"{server_url}/register", json={
                    "username": self.username,
                    "public_key": base64.b64encode(public_bytes).decode()
                })
                self.reregister_status.insert(tk.END, f"{r.json()}\n")
                self.reregister_status.see(tk.END)
            except Exception as e:
                self.reregister_status.insert(tk.END, f"Failed: {e}\n")
                self.reregister_status.see(tk.END)

        threading.Thread(target=reg_thread, daemon=True).start()

    def query_recipients(self):
        server_host = self.server_entry.get().strip()
        server_url = f"http://{server_host}"
        self.clients_text.delete("1.0", tk.END)

        def fetch_thread():
            try:
                clients = requests.get(f"{server_url}/clients").json()
                if clients:
                    for user in clients.keys():
                        self.clients_text.insert(tk.END, f"- {user}\n")
                else:
                    self.clients_text.insert(tk.END, "No users registered.\n")
            except Exception as e:
                self.clients_text.insert(tk.END, f"Failed: {e}\n")

        threading.Thread(target=fetch_thread, daemon=True).start()

    # ---------------- Messaging Tab ----------------
    def setup_messaging_tab(self):
        tk.Label(self.messaging_frame, text="Recipient username:").pack()
        self.recipient_entry = tk.Entry(self.messaging_frame)
        self.recipient_entry.pack(pady=5)

        tk.Label(self.messaging_frame, text="Message:").pack()
        self.msg_entry = tk.Text(self.messaging_frame, height=5, width=50)
        self.msg_entry.pack(pady=5)

        tk.Button(self.messaging_frame, text="Send", command=self.send_message_gui).pack(pady=5)
        tk.Button(self.messaging_frame, text="Check Mailbox", command=self.refresh_inbox).pack(pady=5)

        tk.Label(self.messaging_frame, text="Inbox:").pack()
        self.inbox_text = tk.Text(self.messaging_frame, height=20, width=70)
        self.inbox_text.pack(pady=5)

    # ---------------- Messaging Functions ----------------
    def send_message_gui(self):
        recipient = self.recipient_entry.get().strip()
        if not recipient:
            messagebox.showwarning("Warning", "Enter a recipient")
            return
        server_host = self.server_entry.get().strip()
        server_url = f"http://{server_host}"

        message = self.msg_entry.get("1.0", tk.END).strip()
        if not message:
            messagebox.showwarning("Warning", "Message cannot be empty")
            return

        def send_thread():
            try:
                clients = requests.get(f"{server_url}/clients").json()
                if recipient not in clients:
                    self.inbox_text.insert(tk.END, f"Error: Recipient {recipient} not found\n")
                    return
                recipient_pub_bytes = base64.b64decode(clients[recipient])
                message_bytes = message.encode()
                signature = sign_message(self.private_key_bytes, message_bytes)
                enc_key, enc_msg = encrypt_for_recipient(message_bytes, recipient_pub_bytes)
                r = requests.post(f"{server_url}/send", json={
                    "sender": self.username,
                    "recipient": recipient,
                    "encrypted_key": enc_key,
                    "ciphertext": enc_msg,
                    "signature": signature
                }).json()
                if r.get("status"):
                    self.msg_entry.delete("1.0", tk.END)
                    self.inbox_text.insert(tk.END, f"Message sent to {recipient}\n")
                else:
                    self.inbox_text.insert(tk.END, f"Error sending message: {r}\n")
            except Exception as e:
                self.inbox_text.insert(tk.END, f"Error sending message: {e}\n")

        threading.Thread(target=send_thread, daemon=True).start()

    def refresh_inbox(self):
        server_host = self.server_entry.get().strip()
        server_url = f"http://{server_host}"

        def fetch_thread():
            try:
                r = requests.get(f"{server_url}/inbox/{self.username}").json()
                clients = requests.get(f"{server_url}/clients").json()
                for msg in r:
                    sender = msg["sender"]
                    sender_pub_bytes = base64.b64decode(clients[sender])
                    decrypted = decrypt_from_sender(msg["encrypted_key"], msg["ciphertext"], self.private_key_bytes)
                    if verify_signature(sender_pub_bytes, decrypted, msg["signature"]):
                        self.inbox_text.insert(tk.END, f"From {sender}: {decrypted.decode()}\n\n")
                    else:
                        self.inbox_text.insert(tk.END, f"From {sender}: <Invalid signature>\n\n")
            except Exception as e:
                self.inbox_text.insert(tk.END, f"Error checking mailbox: {e}\n")

        threading.Thread(target=fetch_thread, daemon=True).start()


if __name__ == "__main__":
    app = SecureApp()
    app.mainloop()
