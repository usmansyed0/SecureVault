#!/usr/bin/env python3
"""
verify_nsc.py — Network Security Config audit + certificate pin validation.

Checks enforced on the release NSC:
  1. No cleartextTrafficPermitted="true".
  2. No local/development domains (10.0.2.2, localhost).
  3. At least two <pin> entries exist (current + backup).
  4. No pin is still a placeholder (starts with REPLACE_WITH_).
  5. Every pin value is valid base64 of exactly 32 bytes (SHA-256).
  6. All configured pins are unique (current != backup).

Usage:
    python scripts/verify_nsc.py          # Run from repo root
    python scripts/verify_nsc.py --help

Run in CI before the Gradle build to fail fast on security regressions.
Hooked into assembleRelease and bundleRelease via the Gradle verifyNsc task.
"""

import argparse
import base64
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# The *release* NSC — cleartext must never be allowed here.
RELEASE_NSC = REPO_ROOT / "android" / "app" / "src" / "main" / "res" / "xml" / "network_security_config.xml"

# The *debug* NSC — cleartext to local dev hosts is acceptable.
DEBUG_NSC = REPO_ROOT / "android" / "app" / "src" / "debug" / "res" / "xml" / "network_security_config.xml"

# Pattern that would indicate cleartext is permitted in *any* config block.
CLEARTEXT_TRUE = re.compile(r'cleartextTrafficPermitted\s*=\s*"true"', re.IGNORECASE)

# Localhost/emulator domains acceptable only in debug NSC.
LOCAL_DOMAINS = re.compile(r'<domain[^>]*>(10\.0\.2\.2|127\.0\.0\.1|localhost)</domain>', re.IGNORECASE)

# Extract all <pin digest="SHA-256">VALUE</pin> entries.
PIN_PATTERN = re.compile(r'<pin\s+digest="SHA-256"\s*>([^<]+)</pin>', re.IGNORECASE)

# Placeholder pattern — pins must not start with REPLACE_WITH_.
PLACEHOLDER_PREFIX = "REPLACE_WITH_"


def check_release_nsc(path: Path) -> list[str]:
    """Return a list of error strings. Empty list = PASS."""
    errors: list[str] = []
    if not path.exists():
        errors.append(f"MISSING: Release NSC not found at {path}")
        return errors

    content = path.read_text(encoding="utf-8")

    # 1. No cleartext traffic.
    if CLEARTEXT_TRUE.search(content):
        errors.append(
            f"FAIL: Release NSC contains cleartextTrafficPermitted=\"true\"\n"
            f"      File: {path}\n"
            f"      Move cleartext exceptions to src/debug/res/xml/network_security_config.xml"
        )

    # 2. No local/development domains.
    if LOCAL_DOMAINS.search(content):
        errors.append(
            f"FAIL: Release NSC contains local development domain (10.0.2.2 / localhost).\n"
            f"      File: {path}\n"
            f"      Move local domains to the debug-only network_security_config.xml"
        )

    # 3–6. Certificate pin validation.
    pin_values = [m.group(1).strip() for m in PIN_PATTERN.finditer(content)]

    if len(pin_values) < 2:
        errors.append(
            f"FAIL: Release NSC must have at least 2 <pin> entries (current + backup).\n"
            f"      Found: {len(pin_values)} pin(s) in {path}"
        )
        return errors  # can't run further pin checks without 2 pins

    for pin in pin_values:
        if pin.startswith(PLACEHOLDER_PREFIX):
            errors.append(
                f"FAIL: Pin is still a placeholder: {pin!r}\n"
                f"      File: {path}\n"
                f"      Replace with real SHA-256 SPKI hash. See DEPLOYMENT.md."
            )
            continue

        try:
            decoded = base64.b64decode(pin, validate=True)
        except Exception:
            errors.append(
                f"FAIL: Pin is not valid base64: {pin!r}\n"
                f"      File: {path}"
            )
            continue

        if len(decoded) != 32:
            errors.append(
                f"FAIL: Pin decodes to {len(decoded)} bytes, expected 32 (SHA-256).\n"
                f"      Pin: {pin!r}\n"
                f"      File: {path}"
            )

    # Check uniqueness only if no individual pin errors (avoids confusing double-reports).
    if not errors and len(set(pin_values)) < len(pin_values):
        errors.append(
            f"FAIL: Duplicate pin values detected — current and backup pins must differ.\n"
            f"      File: {path}"
        )

    return errors


def check_debug_nsc(path: Path) -> list[str]:
    """Warn if debug NSC doesn't exist (it should have the dev cleartext exceptions)."""
    warnings: list[str] = []
    if not path.exists():
        warnings.append(
            f"WARNING: Debug NSC not found at {path}\n"
            f"         Create src/debug/res/xml/network_security_config.xml with dev cleartext rules."
        )
    return warnings


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify SecureVault release Network Security Config is cleartext-free and pins are valid."
    )
    parser.add_argument(
        "--release-nsc",
        type=Path,
        default=RELEASE_NSC,
        help="Path to the release network_security_config.xml",
    )
    parser.add_argument(
        "--debug-nsc",
        type=Path,
        default=DEBUG_NSC,
        help="Path to the debug network_security_config.xml",
    )
    parser.add_argument(
        "--allow-placeholder-pins",
        action="store_true",
        help="Skip pin placeholder check (for CI on feature branches without real pins).",
    )
    args = parser.parse_args()

    print(f"Checking release NSC: {args.release_nsc}")
    errors = check_release_nsc(args.release_nsc)

    # Filter out placeholder errors if explicitly allowed (e.g. debug/non-release CI).
    if args.allow_placeholder_pins:
        errors = [e for e in errors if PLACEHOLDER_PREFIX not in e]

    print(f"Checking debug NSC:   {args.debug_nsc}")
    warnings = check_debug_nsc(args.debug_nsc)

    for w in warnings:
        print(f"\n{w}")

    if errors:
        print("\n" + "=" * 70)
        print("NETWORK SECURITY CONFIG AUDIT — FAILED")
        print("=" * 70)
        for err in errors:
            print(f"\n{err}")
        print("\nFix the above issues before merging to main.")
        return 1

    print("\nPASS: Network Security Config audit PASSED -- release build is HTTPS-only.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
