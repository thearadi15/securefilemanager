import hashlib
import os

USER_CREDENTIALS = "user_data.txt"

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def authenticate(username, password):
    hashed_pass = hash_password(password)
    if os.path.exists(USER_CREDENTIALS):
        with open(USER_CREDENTIALS, "r") as file:
            saved_username, saved_hashed_pass = file.read().split(":")
            return saved_username == username and saved_hashed_pass == hashed_pass
    return False

def register_user(username, password):
    with open(USER_CREDENTIALS, "w") as file:
        file.write(f"{username}:{hash_password(password)}")

# Uncomment this to register a user (Run only once)
# register_user("admin", "password123")
