import argparse
import logging
import sys
from pyouro.core import init_cmd, license_cmd, doctor_cmd, clean_cmd, rebuild_cmd
from pyouro.builder import build_cmd

def main():
    # Configure logging for the CLI: show INFO and above with a clean format
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s"
    )

    parser = argparse.ArgumentParser(
        description="PyOuro - Cryptographic Trust Anchor for Python applications",
        prog="pyouro"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    subparsers.required = True

    # COMMAND: init
    init_parser = subparsers.add_parser("init", help="Initialize a new PyOuro project")
    init_parser.add_argument("--entry-point", required=True, help="Path to the main entry point (e.g., main.py)")
    init_parser.add_argument("--payload", required=True, help="Path to the core payload file (e.g., core_payload.py)")
    
    # COMMAND: build
    build_parser = subparsers.add_parser("build", help="Compile and seal the project (Standalone)")
    build_parser.add_argument("--compiler", help="Specify C compiler (e.g., mingw32)")

    # COMMAND: clean
    clean_parser = subparsers.add_parser("clean", help="Remove artifacts and regenerate secret order (DANGEROUS)")
    clean_parser.add_argument("--force", action="store_true", help="Skip interactive confirmation (for scripting)")

    # COMMAND: rebuild
    rebuild_parser = subparsers.add_parser("rebuild", help="Perform a clean followed by a full build (DANGEROUS: resets cryptographic materials)")
    rebuild_parser.add_argument("--compiler", help="Specify C compiler (e.g., mingw32)")

    # COMMAND: license
    license_parser = subparsers.add_parser("license", help="Generate a license.sig file")
    license_parser.add_argument("--hw-id", required=True, help="Target Hardware ID")
    license_parser.add_argument("--type", choices=["DEMO", "FULL"], required=True, help="License type")
    license_parser.add_argument("--expiry", help="Expiry duration (e.g., 30d) for DEMO")

    # COMMAND: doctor
    doctor_parser = subparsers.add_parser("doctor", help="Analyze project state and security health")

    args = parser.parse_args()

    if args.command == "init":
        init_cmd.run(args.entry_point, args.payload)
    elif args.command == "build":
        build_cmd.run(compiler_type=getattr(args, "compiler", None))
    elif args.command == "clean":
        clean_cmd.run(force=getattr(args, "force", False))
    elif args.command == "rebuild":
        rebuild_cmd.run(compiler_type=getattr(args, "compiler", None))
    elif args.command == "license":
        license_cmd.run(args.hw_id, args.type, args.expiry)
    elif args.command == "doctor":
        doctor_cmd.run()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
