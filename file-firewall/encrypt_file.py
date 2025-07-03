from cryptography.fernet import Fernet

# Generate a key (only do this once!)
key = Fernet.generate_key()
with open("file.key", "wb") as f:
    f.write(key)

# Encrypt your important file
fernet = Fernet(key)
with open("/Users/pradeepreddynadagouni/Documents/important.txt", "rb") as file:
    original = file.read()

encrypted = fernet.encrypt(original)

with open("encrypted_file.bin", "wb") as enc_file:
    enc_file.write(encrypted)

print("✅ File encrypted successfully!")

