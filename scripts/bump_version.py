#!/usr/bin/env python3
"""
SecureVault Version Bump Utility.

Synchronizes semantic version numbers across:
- Android: `android/app/build.gradle.kts` (versionCode, versionName)
- Backend: `backend/pyproject.toml` (version)

Usage:
    python scripts/bump_version.py --type patch
    python scripts/bump_version.py --type minor
    python scripts/bump_version.py --type major
    python scripts/bump_version.py --version 1.0.0
    python scripts/bump_version.py --dry-run --type patch
"""

import argparse
import re
import sys
from pathlib import Path

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
ANDROID_GRADLE = WORKSPACE_ROOT / "android" / "app" / "build.gradle.kts"
BACKEND_PYPROJECT = WORKSPACE_ROOT / "backend" / "pyproject.toml"


def parse_semver(version_str: str) -> tuple[int, int, int]:
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)$", version_str.strip())
    if not match:
        raise ValueError(f"Invalid semantic version string: '{version_str}'. Expected 'X.Y.Z'.")
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def bump_semver(current: str, bump_type: str) -> str:
    major, minor, patch = parse_semver(current)
    if bump_type == "major":
        return f"{major + 1}.0.0"
    elif bump_type == "minor":
        return f"{major}.{minor + 1}.0"
    elif bump_type == "patch":
        return f"{major}.{minor}.{patch + 1}"
    else:
        raise ValueError(f"Unsupported bump type: {bump_type}")


def update_android_version(new_version: str, dry_run: bool) -> tuple[int, int, str]:
    content = ANDROID_GRADLE.read_text(encoding="utf-8")
    
    code_match = re.search(r"versionCode\s*=\s*(\d+)", content)
    name_match = re.search(r'versionName\s*=\s*"([^"]+)"', content)

    if not code_match or not name_match:
        raise RuntimeError("Failed to locate versionCode or versionName in android/app/build.gradle.kts")

    old_code = int(code_match.group(1))
    old_name = name_match.group(1)
    new_code = old_code + 1

    new_content = re.sub(
        r"versionCode\s*=\s*\d+",
        f"versionCode = {new_code}",
        content,
        count=1
    )
    new_content = re.sub(
        r'versionName\s*=\s*"[^"]+"',
        f'versionName = "{new_version}"',
        new_content,
        count=1
    )

    if not dry_run:
        ANDROID_GRADLE.write_text(new_content, encoding="utf-8")

    return old_code, new_code, old_name


def update_backend_version(new_version: str, dry_run: bool) -> str:
    content = BACKEND_PYPROJECT.read_text(encoding="utf-8")
    
    match = re.search(r'version\s*=\s*"([^"]+)"', content)
    if not match:
        raise RuntimeError("Failed to locate version in backend/pyproject.toml")

    old_version = match.group(1)
    new_content = re.sub(
        r'version\s*=\s*"[^"]+"',
        f'version = "{new_version}"',
        content,
        count=1
    )

    if not dry_run:
        BACKEND_PYPROJECT.write_text(new_content, encoding="utf-8")

    return old_version


def main():
    parser = argparse.ArgumentParser(description="SecureVault Version Bump Utility")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--type", choices=["major", "minor", "patch"], help="Increment type")
    group.add_argument("--version", help="Explicit target semantic version (e.g. 1.0.0)")
    parser.add_argument("--dry-run", action="store_true", help="Print changes without modifying files")

    args = parser.parse_args()

    # Determine current version from backend/pyproject.toml
    content = BACKEND_PYPROJECT.read_text(encoding="utf-8")
    match = re.search(r'version\s*=\s*"([^"]+)"', content)
    if not match:
        sys.exit("Error: Could not determine current version from backend/pyproject.toml")
    current_version = match.group(1)

    if args.version:
        parse_semver(args.version)  # Validate
        target_version = args.version
    else:
        target_version = bump_semver(current_version, args.type)

    print(f"Current version : {current_version}")
    print(f"Target version  : {target_version}")
    if args.dry_run:
        print("[DRY RUN MODE — No files will be modified]")

    old_code, new_code, old_android = update_android_version(target_version, args.dry_run)
    old_backend = update_backend_version(target_version, args.dry_run)

    print(f"\n[Android build.gradle.kts]")
    print(f"  versionCode: {old_code} -> {new_code}")
    print(f"  versionName: {old_android} -> {target_version}")

    print(f"\n[Backend pyproject.toml]")
    print(f"  version: {old_backend} -> {target_version}")

    print("\nVersion synchronization complete.")


if __name__ == "__main__":
    main()
