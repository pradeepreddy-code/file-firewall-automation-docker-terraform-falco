# app.py
from flask import Flask, render_template, request, redirect, url_for, flash
import pyotp
from cryptography.fernet import Fernet
import hashlib
import os
import getpass
import shutil
from datetime import datetime
from config import FIREWALL_RULES

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # For flashing messages

FAILURE_TRACK_FILE = "failure_count.txt"
MAX_ATTEMPTS = 3

# === Utility Functions ===

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
        log_access("ALERT", "File evacuated after multiple failed attempts.")
        with open(src, "wb") as f:
            f.write(b"Decoy file")

def decrypt_file():
    with open(FIREWALL_RULES["key_path"], "rb") as key_file:
        key = key_file.read()
    fernet = Fernet(key)
    with open(FIREWALL_RULES["file_path"], "rb") as enc_file:
        encrypted = enc_file.read()
    decrypted = fernet.decrypt(encrypted)
    return decrypted.decode()

# === Routes ===

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        password = request.form['password']
        mfa_code = request.form['mfa']
        
        if password != FIREWALL_RULES["ACCESS_PASSWORD"]:
            attempts = increment_failed_attempts()
            flash(f"Wrong password. Attempt #{attempts}", 'error')
            if attempts >= MAX_ATTEMPTS:
                evacuate_file()
                reset_failed_attempts()
            return redirect(url_for('index'))
        
        totp = pyotp.TOTP("SFUK2QZX4YZCD6TSHTRQ5JKKO2G552HW")  # Replace with your actual secret!
        if not totp.verify(mfa_code):
            flash("Invalid MFA code!", 'error')
            return redirect(url_for('index'))

        if get_file_hash(FIREWALL_RULES["file_path"]) != FIREWALL_RULES["sha256_checksum"]:
            flash("File integrity check failed!", 'error')
            return redirect(url_for('index'))

        reset_failed_attempts()
        decrypted_content = decrypt_file()
        return render_template('content.html', content=decrypted_content)

    return render_template('index.html')


@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        admin_password = request.form['admin_password']
        if admin_password == FIREWALL_RULES["ADMIN_PASSWORD"]:
            vault_file = "hidden_vault/encrypted_file_backup.bin"
            if os.path.exists(vault_file):
                shutil.move(vault_file, FIREWALL_RULES["file_path"])
                reset_failed_attempts()
                flash("✅ File restored from hidden vault.", "success")
            else:
                flash("⚠️ No backup file found.", "warning")
        else:
            flash("❌ Invalid admin credentials.", "danger")
        return redirect(url_for('admin'))
    return render_template('admin.html')

# === Run Server ===
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

