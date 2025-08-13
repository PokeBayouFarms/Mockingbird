import os, json, base64, queue, threading, tkinter as tk
from tkinter import messagebox, ttk
import pyotp, keyring, qrcode, requests
from PIL import Image, ImageTk
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

CONFIG_FILE = "config.json"
PUBLIC_KEY_FILE = "public_key.pem"
ENCRYPTED_KEY_FILE = "private_key.enc"
TOTP_KEYRING_SERVICE = "Mockingbird_TOTP"
ISSUER_NAME = "Mockingbird"

class CryptoManager:
    def derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=300_000, backend=default_backend())
        return kdf.derive(password.encode())
    def encrypt_private_key(self, key_bytes: bytes, password: str) -> bytes:
        salt = os.urandom(16)
        derived_key = self.derive_key(password, salt)
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(key_bytes) + encryptor.finalize()
        return salt + iv + encryptor.tag + ciphertext
    def decrypt_private_key(self, encrypted_data: bytes, password: str) -> bytes:
        salt, iv, tag, ciphertext = encrypted_data[:16], encrypted_data[16:28], encrypted_data[28:44], encrypted_data[44:]
        derived_key = self.derive_key(password, salt)
        cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    def aes_gcm_encrypt(self, message: bytes, key: bytes) -> bytes:
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message) + encryptor.finalize()
        return iv + encryptor.tag + ciphertext
    def aes_gcm_decrypt(self, encrypted_message: bytes, key: bytes) -> bytes:
        iv, tag, ciphertext = encrypted_message[:12], encrypted_message[12:28], encrypted_message[28:]
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    def encrypt_for_recipient(self, message_bytes: bytes, recipient_pub_bytes: bytes) -> (str, str):
        pub_key = serialization.load_pem_public_key(recipient_pub_bytes)
        session_key = os.urandom(32)
        encrypted_msg = self.aes_gcm_encrypt(message_bytes, session_key)
        encrypted_key = pub_key.encrypt(session_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return base64.b64encode(encrypted_key).decode(), base64.b64encode(encrypted_msg).decode()
    def decrypt_from_sender(self, encrypted_key_b64: str, encrypted_msg_b64: str, private_key_bytes: bytes) -> bytes:
        private_key = serialization.load_pem_private_key(private_key_bytes, password=None)
        session_key = private_key.decrypt(base64.b64decode(encrypted_key_b64), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return self.aes_gcm_decrypt(base64.b64decode(encrypted_msg_b64), session_key)
    def sign_message(self, private_key_bytes: bytes, message_bytes: bytes) -> str:
        private_key = serialization.load_pem_private_key(private_key_bytes, password=None)
        signature = private_key.sign(message_bytes, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return base64.b64encode(signature).decode()
    def verify_signature(self, public_key_bytes: bytes, message_bytes: bytes, signature_b64: str) -> bool:
        public_key = serialization.load_pem_public_key(public_key_bytes)
        try:
            public_key.verify(base64.b64decode(signature_b64), message_bytes, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            return True
        except Exception:
            return False

class ApiClient:
    def __init__(self, server_url: str):
        self.base_url = f"https://{server_url}" if not server_url.startswith("https://") else server_url
    def register(self, username: str, public_key_b64: str) -> dict:
        return requests.post(f"{self.base_url}/register", json={"username": username, "public_key": public_key_b64}, timeout=10).json()
    def get_clients(self) -> dict:
        return requests.get(f"{self.base_url}/clients", timeout=10).json()
    def send_message(self, payload: dict) -> dict:
        return requests.post(f"{self.base_url}/send", json=payload, timeout=15).json()
    def get_inbox(self, username: str) -> list:
        return requests.get(f"{self.base_url}/inbox/{username}", timeout=15).json()

class SetupPopup(tk.Toplevel):
    def __init__(self, parent, crypto: CryptoManager):
        super().__init__(parent)
        self.transient(parent)
        self.grab_set()
        self.title("First Time Setup")
        self.crypto = crypto
        self.result = None
        tk.Label(self, text="Create Username:").pack(pady=5)
        self.username_entry = tk.Entry(self)
        self.username_entry.pack(padx=10)
        tk.Label(self, text="Create Password:").pack(pady=5)
        self.pw_entry = tk.Entry(self, show="*")
        self.pw_entry.pack(padx=10)
        self.qr_label = tk.Label(self)
        self.qr_label.pack(pady=10)
        tk.Button(self, text="Complete Setup", command=self.do_setup).pack(pady=10)
        self.wait_window()
    def do_setup(self):
        username = self.username_entry.get().strip()
        password = self.pw_entry.get()
        if not username or not password:
            messagebox.showwarning("Input Required", "Username and password cannot be empty.", parent=self)
            return
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_key_bytes = private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
        public_key_bytes = private_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        with open(PUBLIC_KEY_FILE, "wb") as f: f.write(public_key_bytes)
        encrypted_pk = self.crypto.encrypt_private_key(private_key_bytes, password)
        with open(ENCRYPTED_KEY_FILE, "wb") as f: f.write(encrypted_pk)
        totp_secret = pyotp.random_base32()
        keyring.set_password(TOTP_KEYRING_SERVICE, username, totp_secret)
        with open(CONFIG_FILE, "w") as f: json.dump({"account_name": username, "issuer_name": ISSUER_NAME}, f)
        uri = pyotp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name=ISSUER_NAME)
        qr_img = qrcode.make(uri).resize((250, 250))
        self.qr_photo = ImageTk.PhotoImage(qr_img)
        self.qr_label.config(image=self.qr_photo)
        messagebox.showinfo("Scan QR Code", "Scan the QR code with your authenticator app, then close this setup window.", parent=self)
        self.result = {"username": username, "private_key": private_key_bytes}
        self.destroy()

class UnlockPopup(tk.Toplevel):
    def __init__(self, parent, crypto: CryptoManager, username: str):
        super().__init__(parent)
        self.transient(parent)
        self.grab_set()
        self.title("Unlock")
        self.crypto = crypto
        self.username = username
        self.result = None
        tk.Label(self, text="Enter Password:").pack(pady=5)
        self.pw_entry = tk.Entry(self, show="*")
        self.pw_entry.pack(padx=10)
        tk.Label(self, text="Enter TOTP Code:").pack(pady=5)
        self.totp_entry = tk.Entry(self)
        self.totp_entry.pack(padx=10)
        tk.Button(self, text="Unlock", command=self.do_unlock).pack(pady=10)
        self.wait_window()
    def do_unlock(self):
        password = self.pw_entry.get()
        totp_code = self.totp_entry.get().strip()
        totp_secret = keyring.get_password(TOTP_KEYRING_SERVICE, self.username)
        if not totp_secret or not pyotp.TOTP(totp_secret).verify(totp_code):
            messagebox.showerror("Auth Failed", "Invalid TOTP code.", parent=self)
            return
        try:
            with open(ENCRYPTED_KEY_FILE, "rb") as f: encrypted_data = f.read()
            private_key_bytes = self.crypto.decrypt_private_key(encrypted_data, password)
            self.result = {"private_key": private_key_bytes}
            self.destroy()
        except InvalidTag:
            messagebox.showerror("Auth Failed", "Decryption failed. Incorrect password or corrupted key file.", parent=self)
        except Exception as e:
            messagebox.showerror("Error", "An unexpected error occurred during decryption.", parent=self)

class SecureApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.withdraw()
        self.crypto = CryptoManager()
        self.api_client = None
        self.username = None
        self.private_key_bytes = None
        self.config = self.load_config()
        self.gui_queue = queue.Queue()
        if self.run_startup_flow():
            self.create_main_window()
            self.after(100, self.process_queue)
            self.deiconify()
        else:
            self.destroy()
    def load_config(self):
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        return {}
    def save_config(self):
        with open(CONFIG_FILE, 'w') as f:
            json.dump(self.config, f, indent=4)
    def run_startup_flow(self) -> bool:
        if not os.path.exists(ENCRYPTED_KEY_FILE):
            popup = SetupPopup(self, self.crypto)
            if popup.result:
                self.username = popup.result["username"]
                self.private_key_bytes = popup.result["private_key"]
                self.config["account_name"] = self.username
                self.save_config()
                return True
        else:
            self.username = self.config.get("account_name")
            if not self.username:
                messagebox.showerror("Config Error", "Username not found in config. Cannot unlock.")
                return False
            popup = UnlockPopup(self, self.crypto, self.username)
            if popup.result:
                self.private_key_bytes = popup.result["private_key"]
                return True
        return False
    def create_main_window(self):
        self.title(f"Mockingbird Secure Messenger - {self.username}")
        self.geometry("700x800")
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(expand=True, fill="both", padx=10, pady=10)
        self.messaging_frame = ttk.Frame(self.notebook)
        self.server_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.messaging_frame, text="Messaging")
        self.notebook.add(self.server_frame, text="Server & Users")
        self.setup_server_tab()
        self.setup_messaging_tab()
        server_url = self.config.get("server_url", "")
        if server_url:
            self.api_client = ApiClient(server_url)
            self.server_entry.insert(0, server_url)
    def process_queue(self):
        try:
            while True:
                callback, args = self.gui_queue.get_nowait()
                callback(*args)
        except queue.Empty:
            pass
        finally:
            self.after(100, self.process_queue)
    def setup_server_tab(self):
        server_group = ttk.LabelFrame(self.server_frame, text="Server Configuration", padding=10)
        server_group.pack(fill="x", padx=5, pady=5)
        tk.Label(server_group, text="Server URL (e.g., my-server.com):").pack(anchor="w")
        self.server_entry = tk.Entry(server_group, width=50)
        self.server_entry.pack(fill="x", pady=5)
        tk.Button(server_group, text="Set & Save Server", command=self.set_server).pack(pady=5)
        reg_group = ttk.LabelFrame(self.server_frame, text="Registration", padding=10)
        reg_group.pack(fill="x", padx=5, pady=5)
        tk.Button(reg_group, text="Register This Client", command=self.register_client).pack(pady=5)
        self.reg_status_text = tk.Text(reg_group, height=4, width=70)
        self.reg_status_text.pack(pady=5)
        user_group = ttk.LabelFrame(self.server_frame, text="Registered Users", padding=10)
        user_group.pack(fill="both", expand=True, padx=5, pady=5)
        tk.Button(user_group, text="Query Users", command=self.query_recipients).pack(pady=5)
        self.clients_text = tk.Text(user_group, height=15, width=70)
        self.clients_text.pack(fill="both", expand=True, pady=5)
    def setup_messaging_tab(self):
        send_group = ttk.LabelFrame(self.messaging_frame, text="Send Message", padding=10)
        send_group.pack(fill="x", padx=5, pady=5)
        tk.Label(send_group, text="Recipient Username:").pack(anchor="w")
        self.recipient_entry = tk.Entry(send_group)
        self.recipient_entry.pack(fill="x", pady=5)
        tk.Label(send_group, text="Message:").pack(anchor="w")
        self.msg_entry = tk.Text(send_group, height=5, width=50)
        self.msg_entry.pack(fill="x", pady=5)
        tk.Button(send_group, text="Send", command=self.send_message).pack(pady=5)
        inbox_group = ttk.LabelFrame(self.messaging_frame, text="Inbox", padding=10)
        inbox_group.pack(fill="both", expand=True, padx=5, pady=5)
        tk.Button(inbox_group, text="Check Mailbox", command=self.refresh_inbox).pack(pady=5)
        self.inbox_text = tk.Text(inbox_group, height=20, width=70)
        self.inbox_text.pack(fill="both", expand=True, pady=5)
    def set_server(self):
        server_host = self.server_entry.get().strip()
        if not server_host:
            messagebox.showwarning("Input Required", "Please enter a server URL.")
            return
        self.api_client = ApiClient(server_host)
        self.config["server_url"] = server_host
        self.save_config()
        messagebox.showinfo("Success", f"Server URL set to: {self.api_client.base_url}")
    def _execute_in_thread(self, target_func, on_success, on_error):
        if not self.api_client:
            messagebox.showerror("Error", "Server URL not set. Please set it in the Server tab.")
            return
        def worker():
            try:
                result = target_func()
                self.gui_queue.put((on_success, (result,)))
            except requests.exceptions.RequestException as e:
                self.gui_queue.put((on_error, (f"Network Error: {e}",)))
            except Exception as e:
                self.gui_queue.put((on_error, (f"An unexpected error occurred: {e}",)))
        threading.Thread(target=worker, daemon=True).start()
    def register_client(self):
        def do_reg():
            with open(PUBLIC_KEY_FILE, "rb") as f: pub_key_b64 = base64.b64encode(f.read()).decode()
            return self.api_client.register(self.username, pub_key_b64)
        def on_success(result): self.reg_status_text.insert(tk.END, f"Server response: {result}\n")
        def on_error(error): self.reg_status_text.insert(tk.END, f"Failed: {error}\n")
        self._execute_in_thread(do_reg, on_success, on_error)
    def query_recipients(self):
        def on_success(clients):
            self.clients_text.delete("1.0", tk.END)
            if clients:
                for user in clients.keys(): self.clients_text.insert(tk.END, f"- {user}\n")
            else:
                self.clients_text.insert(tk.END, "No users registered.\n")
        def on_error(error):
            self.clients_text.delete("1.0", tk.END)
            self.clients_text.insert(tk.END, f"Failed to fetch users: {error}\n")
        self._execute_in_thread(self.api_client.get_clients, on_success, on_error)
    def send_message(self):
        recipient = self.recipient_entry.get().strip()
        message = self.msg_entry.get("1.0", tk.END).strip()
        if not recipient or not message:
            messagebox.showwarning("Input Required", "Recipient and message cannot be empty.")
            return
        def do_send():
            clients = self.api_client.get_clients()
            if recipient not in clients: raise ValueError(f"Recipient '{recipient}' not found on server.")
            recipient_pub_bytes = base64.b64decode(clients[recipient])
            message_bytes = message.encode()
            signature = self.crypto.sign_message(self.private_key_bytes, message_bytes)
            enc_key, enc_msg = self.crypto.encrypt_for_recipient(message_bytes, recipient_pub_bytes)
            payload = {"sender": self.username, "recipient": recipient, "encrypted_key": enc_key, "ciphertext": enc_msg, "signature": signature}
            return self.api_client.send_message(payload)
        def on_success(result):
            if result.get("status"):
                self.msg_entry.delete("1.0", tk.END)
                messagebox.showinfo("Success", f"Message sent to {recipient}!")
            else:
                messagebox.showerror("Send Error", f"Server error: {result}")
        def on_error(error): messagebox.showerror("Send Error", str(error))
        self._execute_in_thread(do_send, on_success, on_error)
    def refresh_inbox(self):
        def do_fetch():
            messages = self.api_client.get_inbox(self.username)
            clients = self.api_client.get_clients()
            decrypted_messages = []
            for msg in messages:
                try:
                    sender = msg["sender"]
                    if sender not in clients:
                        decrypted_messages.append(f"From {sender}: <Sender public key not found>\n\n")
                        continue
                    sender_pub_bytes = base64.b64decode(clients[sender])
                    decrypted_bytes = self.crypto.decrypt_from_sender(msg["encrypted_key"], msg["ciphertext"], self.private_key_bytes)
                    if self.crypto.verify_signature(sender_pub_bytes, decrypted_bytes, msg["signature"]):
                        decrypted_messages.append(f"From {sender}:\n{decrypted_bytes.decode()}\n\n")
                    else:
                        decrypted_messages.append(f"From {sender}: <INVALID SIGNATURE>\n\n")
                except Exception:
                    decrypted_messages.append(f"From {msg.get('sender', 'Unknown')}: <DECRYPTION FAILED>\n\n")
            return decrypted_messages
        def on_success(messages):
            self.inbox_text.delete("1.0", tk.END)
            if messages:
                for msg_text in messages: self.inbox_text.insert(tk.END, msg_text)
            else:
                self.inbox_text.insert(tk.END, "Your inbox is empty.\n")
        def on_error(error): messagebox.showerror("Inbox Error", f"Could not fetch inbox: {error}")
        self._execute_in_thread(do_fetch, on_success, on_error)

if __name__ == "__main__":
    app = SecureApp()
    app.mainloop()
