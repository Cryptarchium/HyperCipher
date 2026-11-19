import sys
from pyouro import api
import core

def main():
    print("--- PyOuro Protected Application ---")
    
    if api.is_protected():
        print("Status: SECURE 🛡️")
        print(f"Machine Hardware ID: {api.get_hardware_id()}")
        
        try:
            # Check if there is a valid license in the directory
            lic = api.verify_license("license.sig")
            print(f"License Verified! Expires: {lic.get('expiry', 'Never')}")
            
            # The master key can be used to decrypt databases, models, etc.
            # master_key = lic.get("master_key")
        except ValueError as e:
            print(f"License Error: {e}")
            print("Running in unlicensed / demo mode.")
            sys.exit(1)
            
    else:
        print("Status: DEVELOPMENT MODE ⚠️ (Not protected by PyOuro)")
        
    print("\nExecuting Core Application...")
    core.run_secret_ai_algorithm()

if __name__ == "__main__":
    main()
