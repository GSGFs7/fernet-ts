# used by ./compatibility.node.test.ts


import sys
import argparse
from cryptography.fernet import Fernet


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["encrypt", "decrypt", "generate_key"])
    parser.add_argument("--key", help="Fernet key (base64url encoded)")
    parser.add_argument("--data", help="Data to encrypt/decrypt")
    parser.add_argument("--ttl", type=int, help="TTL for decryption")

    args = parser.parse_args()

    try:
        if args.command == "generate_key":
            print(Fernet.generate_key().decode(), end="")
            return

        if not args.key:
            print("Key required", file=sys.stderr)
            sys.exit(1)

        f = Fernet(args.key.encode())

        if args.command == "encrypt":
            data = args.data or sys.stdin.read()
            print(f.encrypt(data.encode()).decode(), end="")
        elif args.command == "decrypt":
            data = args.data or sys.stdin.read()
            # remember padding
            print(f.decrypt(data.strip().encode(), ttl=args.ttl).decode(), end="")
    except Exception as e:
        print(f"ERROR: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
