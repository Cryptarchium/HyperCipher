import sys

def load_and_run_model(master_key: bytes):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from pathlib import Path
    
    weights_path = Path("weights.bin.enc")
    if not weights_path.exists():
        print("Error: weights.bin.enc not found. Run encrypt_weights.py first.")
        sys.exit(1)
        
    encrypted_payload = weights_path.read_bytes()
    nonce = encrypted_payload[:12]
    ciphertext = encrypted_payload[12:]
    
    print("[AI Core] Decrypting Neural Network weights in RAM...")
    try:
        aesgcm = AESGCM(master_key)
        plaintext_weights = aesgcm.decrypt(nonce, ciphertext, None)
        print("✓ Weights successfully decrypted! No files were written to disk.")
        
        # Simulate loading the weights into memory (e.g. PyTorch/TensorFlow)
        print(f"\n[AI Core] Loaded Weights: {plaintext_weights.decode('utf-8')}")
        print("[AI Core] Running inference... Result: Human detected (99.8%)")
        
    except Exception as e:
        print(f"\n❌ FATAL CRASH: Invalid Master Key. The AES-GCM tag check failed.")
        print("This happens if the license was spoofed or bypassed.")
        sys.exit(1)
