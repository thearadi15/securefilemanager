import os
import sys
import hashlib
import pyotp
import smtplib
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QFileDialog, QVBoxLayout, QLabel, QLineEdit, QMessageBox, QInputDialog
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# --- Authentication Setup ---
USER_PASSWORD = "secure123"  # Change this!
SECRET_KEY = pyotp.random_base32()  # For 2FA OTP Generation

def send_otp_email(email, otp):
    # Dummy Email Function (You can integrate SMTP here)
    print(f"Sending OTP {otp} to {email}")
    return True

class SecureFileManager(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Secure File Manager")
        self.setGeometry(100, 100, 400, 300)

        self.label = QLabel("Enter Email:", self)
        self.email_input = QLineEdit(self)

        self.register_button = QPushButton("Register", self)
        self.register_button.clicked.connect(self.register_user)

        self.login_button = QPushButton("Login", self)
        self.login_button.clicked.connect(self.login_user)

        self.encrypt_button = QPushButton("Encrypt File", self)
        self.encrypt_button.clicked.connect(self.encrypt_file)
        self.encrypt_button.setEnabled(False)

        self.decrypt_button = QPushButton("Decrypt File", self)
        self.decrypt_button.clicked.connect(self.decrypt_file)
        self.decrypt_button.setEnabled(False)

        self.metadata_button = QPushButton("View File Metadata", self)
        self.metadata_button.clicked.connect(self.view_metadata)
        self.metadata_button.setEnabled(False)

        layout = QVBoxLayout()
        layout.addWidget(self.label)
        layout.addWidget(self.email_input)
        layout.addWidget(self.register_button)
        layout.addWidget(self.login_button)
        layout.addWidget(self.encrypt_button)
        layout.addWidget(self.decrypt_button)
        layout.addWidget(self.metadata_button)
        
        self.setLayout(layout)
        self.registered_users = {}

    def register_user(self):
        email = self.email_input.text()
        if email:
            password, ok = QInputDialog.getText(self, "Register", "Enter Password:", QLineEdit.Password)
            if ok:
                hashed_password = hashlib.sha256(password.encode()).hexdigest()
                self.registered_users[email] = hashed_password
                QMessageBox.information(self, "Success", "User Registered Successfully!")
        else:
            QMessageBox.warning(self, "Error", "Please enter a valid email")

    def login_user(self):
        email = self.email_input.text()
        if email in self.registered_users:
            password, ok = QInputDialog.getText(self, "Login", "Enter Password:", QLineEdit.Password)
            if ok and hashlib.sha256(password.encode()).hexdigest() == self.registered_users[email]:
                self.two_factor_auth()
            else:
                QMessageBox.warning(self, "Error", "Incorrect password")
        else:
            QMessageBox.warning(self, "Error", "Email not registered")

    def two_factor_auth(self):
        otp = pyotp.TOTP(SECRET_KEY).now()
        send_otp_email("user@example.com", otp)
        user_otp, ok = QInputDialog.getText(self, "Two-Factor Authentication", "Enter OTP:")
        if ok and user_otp == otp:
            QMessageBox.information(self, "Success", "Login Successful!")
            self.enable_features()
        else:
            QMessageBox.warning(self, "Error", "Invalid OTP")

    def enable_features(self):
        self.encrypt_button.setEnabled(True)
        self.decrypt_button.setEnabled(True)
        self.metadata_button.setEnabled(True)

    def encrypt_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Encrypt")
        if file_path:
            key = hashlib.sha256(USER_PASSWORD.encode()).digest()
            cipher = AES.new(key, AES.MODE_CBC)
            with open(file_path, 'rb') as f:
                plaintext = f.read()
            ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
            with open(file_path + ".enc", 'wb') as f:
                f.write(cipher.iv + ciphertext)
            QMessageBox.information(self, "Success", "File Encrypted Successfully!")

    def decrypt_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Decrypt")
        if file_path:
            key = hashlib.sha256(USER_PASSWORD.encode()).digest()
            with open(file_path, 'rb') as f:
                iv = f.read(16)
                ciphertext = f.read()
            cipher = AES.new(key, AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
            with open(file_path.replace(".enc", ""), 'wb') as f:
                f.write(plaintext)
            QMessageBox.information(self, "Success", "File Decrypted Successfully!")
    
    def view_metadata(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to View Metadata")
        if file_path:
            file_size = os.path.getsize(file_path)
            file_type = os.path.splitext(file_path)[1]
            metadata_msg = f"File: {file_path}\nSize: {file_size} bytes\nType: {file_type}"
            QMessageBox.information(self, "Metadata", metadata_msg)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = SecureFileManager()
    ex.show()
    sys.exit(app.exec_())
