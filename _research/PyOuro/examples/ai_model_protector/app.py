import sys
from pyouro import api
import core

def main():
    print("========================================")
    print("   PyOuro AI Model Protector - DEMO    ")
    print("========================================\n")
    
    if not api.is_protected():
        print("Status: DEVELOPMENT MODE ⚠️ (Not protected by PyOuro)")
        print("To run this demo properly, you must build it with 'pyouro build'.")
        # We can still run, but without the master key
        sys.exit(0)

    print("Status: SECURE 🛡️")
    print(f"Machine Hardware ID: {api.get_hardware_id()}")
    
    try:
        # 1. Verify the license mathematically
        lic = api.verify_license("license.sig")
        print(f"\n✓ License Verified! Type: {lic.get('type')}")
        
        # 2. Extract the Cryptographic Master Key 
        # (This ONLY works if the HW ID matches the AES binding)
        master_key = lic.get("master_key")
        
    except ValueError as e:
        print(f"\n❌ License Error: {e}")
        print("The AI Model cannot be booted without a valid license.")
        sys.exit(1)
        
    # 3. Pass the Master Key to the encrypted payload to decrypt the AI weights
    core.load_and_run_model(master_key)

if __name__ == "__main__":
    main()
