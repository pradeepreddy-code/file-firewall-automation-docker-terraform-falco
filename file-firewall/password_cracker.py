import itertools
import string
import time
from config import FIREWALL_RULES

def brute_force_crack(target_password):
    chars = string.ascii_lowercase + string.digits
    max_length = len(target_password)  # realistic length

    start_time = time.time()

    for length in range(1, max_length + 1):
        for guess in itertools.product(chars, repeat=length):
            guess = ''.join(guess)
            if guess == target_password:
                duration = time.time() - start_time
                print(f"✅ Password cracked: {guess}")
                print(f"⏱️ Time taken: {duration:.2f} seconds")
                return guess

    print("❌ Password could not be cracked.")
    return None

if __name__ == "__main__":
    real_password = FIREWALL_RULES["ACCESS_PASSWORD"]
    brute_force_crack(real_password)

