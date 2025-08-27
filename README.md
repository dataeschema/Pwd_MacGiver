# Pwd MacGiver - Documentation

## 1. General Description

**Pwd MacGiver** is a secure desktop application for managing service credentials. Unlike a simple password generator, it acts as a digital vault where the user can save, modify, and consult sensitive information such as usernames, passwords, servers, and databases.

The application is protected by a **master password**, which is used to encrypt all stored information, ensuring that only the user with access to this password can view the data.

## 2. Key Features

- **Secure Vault:** Stores all credentials in a single database file (`vault.db`).
- **Strong Encryption:** Uses robust cryptography to protect the data.
  - The encryption key is derived from the master password using **PBKDF2** with 200,000 iterations and SHA-256.
  - Sensitive data is encrypted using the **Fernet** symmetric algorithm (128-bit AES in CBC mode).
- **Master Password:** On first use, the application prompts for the creation of a master password. In subsequent uses, it is required for access.
- **Modern GUI:** Developed with **PySide6 (Qt)**, featuring a dark and functional design.
- **Credential Management (CRUD):**
  - **Add:** Allows adding new service credentials.
  - **Modify:** Allows editing an existing service.
  - **Delete:** Allows securely deleting a service.
- **Useful Functionalities:**
  - **Integrated Search:** Filters services in real-time.
  - **Copy to Clipboard:** Double-clicking any cell copies its content to the clipboard.
  - **Visual Notifications:** A temporary banner confirms that data has been copied.
- **Customizable Settings:**
  - Allows adjusting and saving the initial window size.
  - The width of the table columns is also saved and restored in each session.

## 3. Technologies Used

- **Language:** Python 3
- **GUI:** PySide6 (official Qt bindings for Python)
- **Database:** SQLite 3
- **Cryptography:** `cryptography` (one of Python's most recognized cryptographic libraries).

## 4. Detailed Functioning

### Startup and Authentication

1.  **First Run:** If a database does not exist or a master password has not been set, the application will display a dialog to create one. A cryptographic "salt" is generated and saved in the database. This "salt" will be used with the password to derive the encryption key.
2.  **Subsequent Runs:** The application will request the master password. The system uses it, along with the stored "salt", to derive a key. If the resulting key is correct (verified against a saved hash), the vault is unlocked. Otherwise, access is denied.

### Database Structure (`vault.db`)

The SQLite database contains three main tables:
- `meta`: Stores critical metadata such as the cryptographic "salt" and the key verifier hash.
- `config`: Saves application settings, such as window size.
- `services`: Stores the credentials. Fields like `username`, `password`, `server`, and `database` are saved in `BLOB` (binary) format because they contain the encrypted data.

### Main Interface

The main window consists of:
- A **top toolbar** with a search field and action buttons (Add, Modify, Delete, Settings).
- A **central table** listing all services. Passwords are obfuscated with dots (`•••••`) for security.
- A **footer** that displays the total number of stored services.

## 5. Dependencies and Virtual Environment

To run the application from the source code, it is recommended to create a virtual environment to isolate the project dependencies. This project is configured to use `uv`, an extremely fast Python package and environment management tool.

### Steps to Prepare the Environment with `uv`

1.  **Install `uv`:**
    If you don't have `uv` yet, install it by following the [official instructions](https://github.com/astral-sh/uv).

2.  **Create the Virtual Environment and Sync Dependencies:**
    Run the following command in the project root. `uv` will create a virtual environment (`.venv`) and automatically install the dependencies specified in `pyproject.toml`.

    ```bash
    uv sync
    ```

3.  **Activate the Virtual Environment:**
    - On **Windows (CMD)**: `.venv\Scripts\activate`
    - On **Windows (PowerShell)**: `.venv\Scripts\Activate.ps1`
    - On **macOS/Linux**: `source .venv/bin/activate`

Once activated, you will have access to the `PySide6` and `cryptography` libraries needed to run the application.

## 6. How to Use the Application

1.  **Prepare the environment:** Follow the steps in the "Dependencies and Virtual Environment" section.
2.  **Run the script:** `python Pwd_MacGiver.py`, or via uv `uv run Pwd_MacGiver.py`.
3.  **Create/Enter Master Password:** Follow the instructions in the initial dialog.
4.  **Add a Service:**
    - Click the "Add" button.
    - Fill in the fields in the new dialog and click "Ok".
5.  **Copy Data:**
    - Double-click the desired cell (e.g., the password for the "Gmail" service).
    - The data will be copied to the clipboard and a green banner will confirm it.
6.  **Search for a Service:**
    - Type in the search bar. The table will filter automatically.
7.  **Modify or Delete:**
    - Select the row of the service you want to change.
    - Click "Modify" or "Delete".

## 7. Application Packaging

To distribute the application, you can generate a self-contained executable using `PyInstaller`. The window icon (`icon.png`) is loaded directly from the code and must be included as a resource within the package.

### Packaging for Windows

To create a `.exe` executable for Windows:

```bash
pyinstaller Pwd_MacGiver.py --name Pwd_MacGiver --onefile --noconsole --icon .\app.ico --add-data "icon.png;."
```
- **`--add-data "icon.png;."`**: This command is crucial. It includes the `icon.png` file in the root of the package so the application can find it and display it as the window icon. The separator for `add-data` on Windows is `;`.

### Packaging for macOS (Apple Silicon)

The process is similar for macOS, but requires an icon in `.icns` format.

#### 1. Create the Icon File (`.icns`)

Use the `iconutil` utility on a Mac to convert your `icon.png`:
```bash
# 1. Create the iconset directory
mkdir mi_icono.iconset
# 2. Generate the different resolutions
sips -z 16 16 icon.png --out mi_icono.iconset/icon_16x16.png
sips -z 32 32 icon.png --out mi_icono.iconset/icon_32x32.png
sips -z 128 128 icon.png --out mi_icono.iconset/icon_128x128.png
sips -z 256 256 icon.png --out mi_icono.iconset/icon_256x256.png
# 3. Convert to .icns
iconutil -c icns mi_icono.iconset
```

#### 2. Generate the Application (`.app`)

Run `PyInstaller` with the following command:
```bash
pyinstaller Pwd_MacGiver.py --name Pwd_MacGiver --windowed --icon mi_icono.icns --add-data "icon.png:."
```
- **`--add-data "icon.png:."`**: Like on Windows, this command includes `icon.png` in the application package. The separator on macOS is `:`.

## 8. Security Analysis and Proposed Enhancements

The application follows good security practices, but for an enterprise environment, the following enhancements can be applied:

### High-Priority Enhancements
1.  **Automatic Clipboard Clearing:** Clear sensitive data from the clipboard after 30-60 seconds to minimize exposure.
2.  **Increase PBKDF2 Iterations:** Raise the number of iterations (currently 200,000) to a more robust value (e.g., 600,000) to strengthen key derivation against brute-force attacks.
3.  **Auto-Lock on Idle:** Lock the application after a period of inactivity, requiring the master password to unlock it again.

### Medium-Priority Enhancements
4.  **Secure In-Memory Secret Management:** Decrypt credentials only at the moment of use (Just-In-Time) and clear them from memory immediately afterward.
5.  **Master Password Strength Meter:** Add a visual indicator when creating/changing the master password to guide the user.

### Advanced Enhancements
6.  **Database Integrity Verification (HMAC):** Protect the database file against external tampering using a cryptographic signature.
