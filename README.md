# CipherAuth 🔐

CipherAuth is a secure, cross-platform TOTP (Time-based One-Time Password) authenticator applications designed for simplicity and security. Built with Python and a modern UI powered by CustomTkinter, it provides a safe vault for your two-factor authentication tokens.

## 🚀 Available on Microsoft Store

CipherAuth is officially available for Windows via the Microsoft Store. Get it here:
**[Get CipherAuth on Microsoft Store](https://apps.microsoft.com/store/apps)** *(Note: Replace with your actual store link)*

## ✨ Features

- **Encrypted Storage:** All your credentials are encrypted with AES-256.
- **Modern UI:** Clean, dark-themed interface using CustomTkinter.
- **Search:** Quickly find your accounts with the built-in search bar.
- **QR Code Support:** View and scan QR codes for easy setup.
- **Export/Import:** Easily backup and restore your credentials.
- **Password Protected:** Secured by a master password to prevent unauthorized access.

## 🛠️ Development & Compilation

CipherAuth is ready to be compiled for any operating system (Windows, macOS, Linux) without any additional code changes.

### Running from Source

1. Clone the repository.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the application:
   ```bash
   python Python/main.py
   ```

### Compiling with PyInstaller

The project includes a `CipherAuth.spec` file, making it easy to create a standalone executable for your current OS.

1. Install PyInstaller:
   ```bash
   pip install pyinstaller
   ```
2. Build the executable:
   ```bash
   pyinstaller CipherAuth.spec
   ```
3. The compiled application will be available in the `dist/` folder.

## ❓ FAQ

### How do I add a new account?
Click on the **"➕ Add Creds"** button in the footer and fill in the account details.

### How do I back up my tokens?
Use the **"📥 Download"** button to export an encrypted version of your credentials. Keep this file safe!

### Can I use this on Mac or Linux?
Yes! Since it is written in Python, you can run it from source or compile it using PyInstaller on your respective operating system.

### Is my data synced to the cloud?
No. CipherAuth is designed to be fully offline for maximum privacy. Your data stays on your device.

## ⚠️ Important Note

> **Disclaimer:** CipherAuth uses high-level encryption secured by your Master Password. If you forget your Master Password, **we cannot recover your data**. There are no "backdoors" or password recovery options for your security. Please ensure you keep your password in a safe place.

---
*Developed with ❤️ using Python and CustomTkinter.*
