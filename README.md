# Secure Password Manager

This is a command-line password manager that securely stores your website and application passwords in a MySQL database. It utilizes strong encryption (AES-256 GCM) and password hashing (bcrypt) to protect your sensitive information.

## Features

* **Secure Storage:** Passwords are encrypted using AES-256 in GCM mode, providing authenticated encryption.
* **Password Hashing:** Before encryption, user-provided passwords are hashed using bcrypt, a strong and adaptive password hashing algorithm.
* **Database Integration:** Stores password entries (service name, encrypted username and hashed password) in a MySQL database.
* **Key Management:** The AES encryption key is generated and stored locally in a `key.bin` file. If the file doesn't exist, a new key is generated.
* **Add New Password:** Allows you to store the username and password for a specific service. If the service already exists, the existing entry is updated.
* **Retrieve Password Information:** Retrieves the stored username (plaintext) and indicates that the password is securely stored (hashed and encrypted) for a given service. **Note:** For security reasons, the raw hashed password is not directly displayed.
* **Generate Secure Password:** Provides a utility to generate strong, random passwords of a specified length.

## Prerequisites

* **Python 3.x** installed on your system.
* **MySQL Server** installed and running.
* **`mysql-connector-python`** library installed (`pip install mysql-connector-python`).
* **`bcrypt`** library installed (`pip install bcrypt`).
* **`pycryptodome`** library installed (`pip install pycryptodome`).

## Setup

1.  **Clone the repository (or download the Python script):**
    ```bash
    git clone <repository_url>
    cd <repository_directory>
    ```

2.  **Install the required Python libraries:**
    ```bash
    pip install mysql-connector-python bcrypt pycryptodome
    ```

3.  **Configure the Database:**
    * Ensure your MySQL server is running.
    * Create a database for the password manager (e.g., `projectManagment`).
    * Update the `db_config` dictionary in the `main()` function of the `password_manager.py` script with your MySQL connection details:
        ```python
        db_config = {
            'host': 'localhost',  # Replace with your MySQL server host
            'user': 'root',       # Replace with your MySQL username
            'password': '',       # Replace with your MySQL password
            'database': 'projectManagment' # Replace with your database name
        }
        ```

## Usage

1.  **Run the script:**
    ```bash
    python password_manager.py
    ```

2.  **Follow the on-screen menu:**
    * **1. Store new password:** Enter the service name, username, and the password you want to store. The password will be hashed and the username and hash will be encrypted before being stored in the database.
    * **2. Retrieve password:** Enter the service name to retrieve the associated username. The script will indicate that the password is securely stored (hashed and encrypted).
    * **3. Generate secure password:** Enter the desired length for a new random password (or press Enter for the default length of 16).
    * **4. Exit:** Closes the database connection and exits the password manager.

## Security Considerations

* **Key File Security:** The AES encryption key is stored locally in the `key.bin` file. **It is crucial to protect this file from unauthorized access.** If this file is compromised, your stored passwords could be decrypted. Consider using appropriate file system permissions to restrict access.
* **Master Password (Not Implemented):** This version does not implement a master password to protect the key file itself. This is a potential area for future improvement.
* **Database Security:** Ensure your MySQL database is properly secured with strong passwords and appropriate access controls.
* **Hashing vs. Encryption for Passwords:** This implementation hashes the user-provided password using bcrypt *before* encrypting the username and the hash together. This adds an extra layer of security. Even if the encrypted data in the database is compromised, the attacker would still need to break the bcrypt hash to obtain the original password.
* **GCM Mode:** AES in GCM (Galois/Counter Mode) provides both confidentiality (encryption) and integrity (authentication) of the data. This ensures that the encrypted data cannot be tampered with without detection.

## Disclaimer

This is a basic password manager implementation for educational purposes. While it incorporates security measures like strong encryption and hashing, it may not be suitable for highly sensitive environments without further security enhancements and rigorous testing. Use it at your own risk.

## Future Enhancements

* Implement a master password to protect the encryption key.
* Add functionality to delete or update existing password entries.
* Improve error handling and user interface.
* Consider using a more secure method for storing the encryption key (e.g., using a key derivation function based on a master password).
* Explore different database options or local encrypted file storage.
* Implement password strength checking during password creation.
