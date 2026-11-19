# 🏢 Enterprise DB Connector (PyOuro Example)

This project demonstrates a classic B2B use-case for PyOuro: **Protecting highly sensitive database credentials and enforcing expiration dates (Time-Bombing)**.

When you distribute a Desktop or On-Premise software to a corporate client, you often need that software to connect to a central database. Distributing the database username and password inside a plaintext `.json` or `.env` file is extremely dangerous.

With PyOuro's **Cryptographic Binding**, the database credentials are AES-GCM encrypted and can *only* be decrypted in RAM if the client has a valid license bound to their specific hardware. 

Furthermore, if the license is of type `DEMO` and it expires, the decryption mathematically cannot happen, providing an uncrackable time-bomb.

## How to Test This Example

### 1. Initialize the Project
```bash
pyouro init --entry-point app.py --payload app.py
```
This generates your developer keys (`.pyouro/private.pem` and `.pyouro/public.pem`).

### 2. Encrypt Your Proprietary Credentials
As a developer, you run the provided encryption script BEFORE shipping your code.
```bash
python encrypt_credentials.py
```
*What happens:* The script derives your global `Master Key` from your `private.pem` and encrypts a dummy Database JSON object into `db_config.enc`. The plaintext file is never saved to disk.

### 3. Build the Application
```bash
pyouro build
```
*(This automatically creates a standalone PyInstaller executable inside the `dist` folder).*

### 4. Run Without a License (The Attacker Scenario)
Run the built application:
```bash
.pyouro/build_stage/dist/ProtectedApp/ProtectedApp.exe
```
*(Path may vary depending on your OS)*

You will see that the application **refuses to run** because `license.sig` is missing.

*Even if an attacker modifies the python bytecode to bypass the license check, they **still** do not have the Master Key. If they try to force the `core.py` to run, it will crash mathematically when trying to decrypt `credentials.json.enc`.*

### 5. Issue a Valid DEMO License
Find your Hardware ID (it will be printed when you run the app), then generate a 30-day demo license:
```bash
pyouro license --hw-id "YOUR_HW_ID_HERE" --type DEMO --expiry 30d
```
This creates `license.sig`. Inside this file, the `Master Key` is secretly encrypted using your specific Hardware ID as the cipher.

### 6. Run With the License (The Client Scenario)
Run the application again.
1. PyOuro verifies your RSA signature.
2. PyOuro verifies the expiry timestamp.
3. PyOuro uses the Hardware ID to successfully decrypt the Master Key hidden in the license.
4. The Master Key is passed to `core.py`.
5. `core.py` decrypts `db_config.enc` **directly into RAM** and parses the JSON.
6. The software connects to the database securely. No plaintext credentials ever touch the disk.

## Security Takeaway
If a client stops paying their subscription, you simply don't issue them a new `license.sig`. Because the database credentials are cryptografically locked behind the Master Key, they cannot simply "patch" your executable to bypass the subscription check. Without the Master Key, the credentials remain mathematically impossible to read.
