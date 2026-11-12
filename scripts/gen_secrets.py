#!/usr/bin/env python3
"""
gen_secrets.py — Generate cryptographically secure secrets for SecureVault.

Usage:
    python scripts/gen_secrets.py

Each run prints fresh URL-safe secrets (48 bytes = 384 bits of entropy).
Copy them into your .env file.  Never reuse secrets across variables.
"""
import secrets


def main() -> None:
    print("# SecureVault — Generated Secrets")
    print("# Copy each value into your backend/.env file.")
    print("# Run this script again to generate a new set; old tokens will be invalidated.")
    print()
    print(f"SECUREVAULT_JWT_SECRET={secrets.token_urlsafe(48)}")
    print(f"SECUREVAULT_REFRESH_TOKEN_HASH_SECRET={secrets.token_urlsafe(48)}")
    print(f"SECUREVAULT_STEP_UP_HASH_SECRET={secrets.token_urlsafe(48)}")
    print()
    print("# ⚠  Keep these values secret.  Do NOT commit them to version control.")


if __name__ == "__main__":
    main()
