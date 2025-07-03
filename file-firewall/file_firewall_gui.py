import tkinter as tk
from tkinter import messagebox, simpledialog
from PIL import ImageTk, Image
import getpass
import hashlib
from PIL import Image, ImageTk
from cryptography.fernet import Fernet
import shutil
import os
from datetime import datetime
from config import FIREWALL_RULES
import pyotp

FAILURE_TRACK_FILE = "failure_count.txt"
MAX_ATTEMPTS = 3

# === Helpers ===
def log_access(status, reason):
    with open("log.txt", "a") as log:
        log.write(f"{datetime.now()} - {getpass.getuser()} - {status}: {reason}\n")

def get_failed_attempts():
    if not os.path.exists(FAILURE_TRACK_FILE):
        return 0
    with open(FAILURE_TRACK_FILE, "r") as f:
        return int(f.read().strip() or 0)

def increment_failed_attempts():
    attempts = get_failed_attempts() + 1
    with open(FAILURE_TRACK_FILE, "w") as f:
        f.write(str(attempts))
    return attempts

def reset_failed_attempts():
    with open(FAILURE_TRACK_FILE, "w") as f:
        f.write("0")

def get_file_hash(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()

def evacuate_file():
    src = FIREWALL_RULES["file_path"]
    dest = "hidden_vault/encrypted_file_backup.bin"
    if os.path.exists(src):
        shutil.move(src, dest)
        log_access("ALERT", "File evacuated to hidden vault after multiple failed attempts.")
        with open(src, "wb") as f:
            f.write(b"Decoy file")
        messagebox.showwarning("Tamper Alert", "File evacuated to hidden vault.")

def decrypt_file():
    with open(FIREWALL_RULES["key_path"], "rb") as key_file:
        key = key_file.read()
    fernet = Fernet(key)
    with open(FIREWALL_RULES["file_path"], "rb") as enc_file:
        encrypted = enc_file.read()
    decrypted = fernet.decrypt(encrypted)
    return decrypted.decode()

def check_mfa_gui():
    totp = pyotp.TOTP("HYFPKKIVN7XJQWSAPHV67DINH7WEJVEH")  # Replace with your secret
    code = simpledialog.askstring("MFA Verification", "Enter MFA code from Google Authenticator:")
    if totp.verify(code):
        messagebox.showinfo("MFA", "✅ MFA verification successful!")
        return True
    else:
        messagebox.showerror("MFA", "❌ Invalid MFA code! Access denied.")
        return False

def show_decrypted_content(content):
    new_window = tk.Toplevel(root)
    new_window.title("Decrypted File Content")
    text_box = tk.Text(new_window, wrap=tk.WORD, width=100, height=30)
    text_box.insert(tk.END, content)
    text_box.pack(padx=10, pady=10)

def access_file():
    user = getpass.getuser()
    if user not in FIREWALL_RULES["allowed_users"]:
        attempts = increment_failed_attempts()
        log_access("DENIED", f"User '{user}' not allowed")
        messagebox.showerror("Access Denied", f"Unauthorized user.\nAttempt #{attempts}")
        if attempts >= MAX_ATTEMPTS:
            evacuate_file()
            reset_failed_attempts()
        return

    entered = password_entry.get()
    correct_password = FIREWALL_RULES["ACCESS_PASSWORD"]
    if entered != correct_password:
        attempts = increment_failed_attempts()
        log_access("DENIED", f"Wrong password attempt #{attempts}")
        messagebox.showerror("Access Denied", f"Wrong password.\nAttempt #{attempts}")
        if attempts >= MAX_ATTEMPTS:
            evacuate_file()
            reset_failed_attempts()
        return

    if not check_mfa_gui():
        return

    if get_file_hash(FIREWALL_RULES["file_path"]) != FIREWALL_RULES["sha256_checksum"]:
        log_access("DENIED", "File integrity failed")
        messagebox.showerror("Access Denied", "File integrity check failed.")
        return

    reset_failed_attempts()
    log_access("ALLOWED", "Access granted")
    content = decrypt_file()
    show_decrypted_content(content)

def restore_file():
    admin_password = simple_input.get()
    if admin_password != FIREWALL_RULES["ADMIN_PASSWORD"]:
        messagebox.showerror("Admin Access Denied", "Invalid admin password.")
        return

    vault_file = "hidden_vault/encrypted_file_backup.bin"
    if os.path.exists(vault_file):
        shutil.move(vault_file, FIREWALL_RULES["file_path"])
        reset_failed_attempts()
        messagebox.showinfo("Admin", "File restored from hidden vault.")
    else:
        messagebox.showinfo("Admin", "No backup file found.")

# === GUI ===
root = tk.Tk()
root.title("Secure File Firewall")

# Banner image at top
try:
    banner_img = Image.open("banner.png")
    banner_img = banner_img.resize((600, 200))
    banner_photo = ImageTk.PhotoImage(banner_img)
    banner_label = tk.Label(root, image=banner_photo)
    banner_label.pack(pady=10)
except Exception as e:
    print("Banner image not found or error loading:", e)

tk.Label(root, text="Enter Access Password:").pack()
password_entry = tk.Entry(root, show="*")
password_entry.pack()

tk.Button(root, text="Access File", command=access_file).pack(pady=5)

tk.Label(root, text="Admin Restore - Enter Admin Password:").pack(pady=10)
simple_input = tk.Entry(root, show="*")
simple_input.pack()
tk.Button(root, text="Restore File", command=restore_file).pack()

root.mainloop()

