# 🧠 AI Model Protector (PyOuro Example)

This project demonstrates the ultimate use-case for PyOuro: **Protecting Proprietary Machine Learning Models (AI Weights)**.

Machine learning models cost thousands of dollars to train, but a standard Python app distributes the weights (`.pt`, `.h5`, `.bin`) as plaintext files on disk, making them trivial to steal.

With PyOuro's **Cryptographic Binding**, the model weights are AES-GCM encrypted and can *only* be decrypted in RAM if the client has a valid license bound to their specific hardware. 

## How to Test This Example

### 1. Initialize the Project
```bash
pyouro init --entry-point app.py --payload app.py
```
This generates your developer keys (`.pyouro/private.pem` and `.pyouro/public.pem`).

### 2. Encrypt Your Proprietary Weights
As a developer, you run the provided encryption script BEFORE shipping your code.
```bash
python encrypt_weights.py
```
*What happens:* The script derives your global `Master Key` from your `private.pem` and encrypts a dummy `weights.bin` into `weights.bin.enc`. The plaintext file is then deleted.

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

*Even if an attacker modifies the python bytecode to bypass the license check, they **still** do not have the Master Key. If they try to force the `core.py` to run, it will crash mathematically when trying to decrypt `weights.bin.enc`.*

### 5. Issue a Valid License
Find your Hardware ID (it will be printed when you run the app), then generate a license:
```bash
pyouro license --hw-id "YOUR_HW_ID_HERE" --type FULL
```
This creates `license.sig`. Inside this file, the `Master Key` is secretly encrypted using your specific Hardware ID as the cipher.

### 6. Run With the License (The Client Scenario)
Run the application again.
1. PyOuro verifies your RSA signature.
2. PyOuro uses the Hardware ID to successfully decrypt the Master Key hidden in the license.
3. The Master Key is passed to `core.py`.
4. `core.py` decrypts the `weights.bin.enc` **directly into RAM** and prints the weights! No plaintext files ever touch the disk.

## Security Takeaway
By combining Cython (which hides the python code) and PyOuro's Cryptographic Binding (which hides the Master Key), you achieve a system where the AI model is mathematically unbreakable without a valid, hardware-bound license.
