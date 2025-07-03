import os
import sys
import getpass
import hashlib
import shutil
from datetime import datetime
import pyotp
from cryptography.fernet import Fernet
from config import FIREWALL_RULES

# === SETTINGS ===
FAILURE_TRACK_FILE = "failure_count.txt"
MAX_ATTEMPTS = 3

# === UTILITY: macOS native notifications ===
def send_notification(title, message):
    os.system(f"""
        osascript -e 'display notification "{message}" with title "{title}"'
    """)

# === LOGGING ===
def log_access(status, reason):
    with open("log.txt", "a") as log:
        log.write(f"{datetime.now()} - {getpass.getuser()} - {status}: {reason}\n")

# === FAILURE TRACKING ===
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

# === FILE INTEGRITY ===
def get_file_hash(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()

# === ENCRYPTION ===
def decrypt_and_show_file():
    with open(FIREWALL_RULES["key_path"], "rb") as key_file:
        key = key_file.read()

    fernet = Fernet(key)

    with open(FIREWALL_RULES["file_path"], "rb") as enc_file:
        encrypted = enc_file.read()

    decrypted = fernet.decrypt(encrypted)
    print("\n Access Granted. File content:\n")
    print(decrypted.decode())

# === EVACUATE ON BREACH ===
def evacuate_file():
    src = FIREWALL_RULES["file_path"]
    dest = "hidden_vault/encrypted_file_backup.bin"
    if os.path.exists(src):
        shutil.move(src, dest)
        log_access("ALERT", "File evacuated to hidden vault after multiple failed attempts.")
        print("️ File evacuated to secure vault.")
        # Optional decoy
        with open(src, "wb") as f:
            f.write(b"This is a decoy file. Nice try.")

# === PASSWORD CHECK ===
def check_password():
    correct_password = FIREWALL_RULES["ACCESS_PASSWORD"]
    entered = getpass.getpass("Enter file access password: ")

    if entered != correct_password:
        attempts = increment_failed_attempts()
        log_access("DENIED", f"Wrong password. Attempt #{attempts}")
        print(f" Wrong password. Attempt #{attempts}")

        send_notification(
            " File Firewall Alert",
            f"Unauthorized access attempt detected!\nAttempts: {attempts}"
        )

        if attempts >= MAX_ATTEMPTS:
            evacuate_file()
            reset_failed_attempts()

        exit()
    else:
        reset_failed_attempts()

# === MFA CHECK ===
def check_mfa():
    totp = pyotp.TOTP("HYFPKKIVN7XJQWSAPHV67DINH7WEJVEH")  # replace with your secret
    code = input("Enter MFA code from Google Authenticator: ")
    if totp.verify(code):
        print(" MFA verification successful!")
    else:
        print(" Invalid MFA code! Access denied.")
        exit()

# === ENFORCE FIREWALL ===
def enforce_firewall():
    user = getpass.getuser()

    if user not in FIREWALL_RULES["allowed_users"]:
        attempts = increment_failed_attempts()
        reason = f"User '{user}' is not allowed."
        log_access("DENIED", reason)
        print(f" {reason}")

        send_notification(
            "️ File Firewall Alert",
            f"Unauthorized user detected!\nAttempts: {attempts}"
        )

        if attempts >= MAX_ATTEMPTS:
            evacuate_file()
            reset_failed_attempts()

        exit()

    check_password()
    check_mfa()

    current_hash = get_file_hash(FIREWALL_RULES["file_path"])
    if current_hash != FIREWALL_RULES["sha256_checksum"]:
        reason = "File integrity check failed!"
        log_access("DENIED", reason)
        print(f" {reason}")

        send_notification(
            " File Firewall Alert",
            "File integrity check failed!"
        )

        exit()

    log_access("ALLOWED", "Access granted.")
    decrypt_and_show_file()

# === ADMIN MODE ===
def admin_mode():
    admin_pass = getpass.getpass("Enter admin password: ")
    if admin_pass != FIREWALL_RULES["ADMIN_PASSWORD"]:
        print(" Invalid admin credentials.")
        exit()

    vault_file = "hidden_vault/encrypted_file_backup.bin"
    if os.path.exists(vault_file):
        shutil.move(vault_file, FIREWALL_RULES["file_path"])
        reset_failed_attempts()
        print(" File restored from hidden vault.")
    else:
        print("️ No evacuated file found.")

# === MAIN ===
if __name__ == "__main__":
    if "--admin" in sys.argv:
        admin_mode()
    else:
        enforce_firewall()

