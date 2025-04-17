import bcrypt
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import json
import getpass
import mysql.connector

class PasswordManager:
    def __init__(self, db_config):
        """
        Initializes the PasswordManager with MySQL database configuration.

        Args:
            db_config (dict): A dictionary containing MySQL connection parameters
                                 like 'host', 'user', 'password', 'database'.
        """
        self.db_config = db_config
        self.conn = self._create_connection()
        self.cursor = self.conn.cursor()
        self._create_table()
        self.key = self._load_or_generate_key()

    def _create_connection(self):
        """Creates a database connection to the MySQL database."""
        try:
            conn = mysql.connector.connect(**self.db_config)
            return conn
        except mysql.connector.Error as e:
            print(f"MySQL connection error: {e}")
            return None

    def _create_table(self):
        """Creates the passwords table if it doesn't exist."""
        try:
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS passwords (
                    service VARCHAR(255) PRIMARY KEY,
                    encrypted_data TEXT NOT NULL
                )
            """)
            self.conn.commit()
        except mysql.connector.Error as e:
            print(f"Error creating table: {e}")

    def _load_or_generate_key(self):
        """Loads the encryption key from file or generates a new one."""
        try:
            with open('key.bin', 'rb') as f:
                return f.read()
        except FileNotFoundError:
            key = get_random_bytes(32)  # AES-256 key
            with open('key.bin', 'wb') as f:
                f.write(key)
            return key

    def _encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
        return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

    def _decrypt(self, encrypted_data):
        data = base64.b64decode(encrypted_data.encode('utf-8'))
        nonce = data[:16]
        tag = data[16:32]
        ciphertext = data[32:]
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

    def hash_password(self, password):
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')

    def verify_password(self, password, hashed):
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

    def add_password(self, service, username, password):
        hashed_pw = self.hash_password(password)
        entry_data = json.dumps({'username': username, 'password': hashed_pw})
        encrypted_entry = self._encrypt(entry_data)
        try:
            self.cursor.execute(
                "INSERT INTO passwords (service, encrypted_data) VALUES (%s, %s) ON DUPLICATE KEY UPDATE encrypted_data = %s",
                (service, encrypted_entry, encrypted_entry)
            )
            self.conn.commit()
            return True
        except mysql.connector.Error as e:
            print(f"Error adding password: {e}")
            return False

    def get_password(self, service):
        try:
            self.cursor.execute("SELECT encrypted_data FROM passwords WHERE service = %s", (service,))
            result = self.cursor.fetchone()
            if result:
                encrypted_entry = result[0]
                decrypted_entry = json.loads(self._decrypt(encrypted_entry))
                return decrypted_entry
            return None
        except mysql.connector.Error as e:
            print(f"Error retrieving password: {e}")
            return None

    def close_connection(self):
        """Closes the database connection."""
        if self.conn and self.conn.is_connected():
            self.cursor.close()
            self.conn.close()

def generate_password(length=16):
    import random
    import string
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

def main():
    # Configure MySQL database details here
    db_config = {
        'host': 'localhost',  # Replace with MySQL server host name
        'user': 'root',  # Replace with MySQL username
        'password': '',  # Replace with MySQL password
        'database': 'projectManagment'  # Replace with MySQL database name
    }
    pm = PasswordManager(db_config)

    while True:
        print("\nPassword Manager Menu:")
        print("1. Store new password")
        print("2. Retrieve password")
        print("3. Generate secure password")
        print("4. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            service = input("Service name: ")
            username = input("Username: ")
            password = getpass.getpass("Password: ")
            if pm.add_password(service, username, password):
                print("Password stored securely!")
            else:
                print("Failed to store password.")

        elif choice == '2':
            service = input("Service name: ")
            entry = pm.get_password(service)
            if entry:
                print(f"\nService: {service}")
                print(f"Username: {entry['username']}")
                print(f"Password: [hashed and securely stored]")
            else:
                print("No entry found for that service.")

        elif choice == '3':
            length = int(input("Password length (default 16): ") or 16)
            password = generate_password(length)
            print(f"Generated password: {password}")

        elif choice == '4':
            pm.close_connection()
            break

if __name__ == "__main__":
    main()