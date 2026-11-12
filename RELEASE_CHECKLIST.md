# SecureVault Production Release Checklist & Runbook

This runbook guides engineering and operations teams through tagging, compiling, verifying, and distributing production releases of **SecureVault** on the Google Play Store and backend infrastructure.

---

## 1. Pre-Flight Verification & Quality Gates

Ensure all automated gates pass cleanly prior to cutting a release branch:

- [ ] **Working Tree Cleanliness:**
  ```bash
  git status
  # Must be clean, no untracked or modified files
  ```
- [ ] **Android Unit & Crypto Tests:**
  ```bash
  cd android
  ./gradlew testDebugUnitTest
  # 135+ tests must pass with 0 errors
  ```
- [ ] **Backend Test Suite & Migrations:**
  ```bash
  cd backend
  pytest tests
  # All endpoint, auth, and step-up tests must pass
  ```
- [ ] **Desktop Client Verification:**
  ```bash
  cd desktop
  pytest tests
  ```
- [ ] **Zero Cleartext Secret Audit:**
  - Verify no `println` or `Log.d` outputs raw tokens, VRK bytes, master passwords, or PINs.
  - Verify `SafeSecurityLogger` uses only alphanumeric snake_case event names.

---

## 2. Version Synchronization & Tagging

Use the automated version synchronizer:

```bash
# For patch release:
python scripts/bump_version.py --type patch

# For minor feature release:
python scripts/bump_version.py --type minor

# For major milestone release:
python scripts/bump_version.py --type major
```

Verify that:
1. `android/app/build.gradle.kts` incremented `versionCode` and updated `versionName`.
2. `backend/pyproject.toml` updated `version`.

Commit and tag:
```bash
git commit -am "chore(release): bump version to vX.Y.Z"
git tag -a vX.Y.Z -m "SecureVault Production Release vX.Y.Z"
git push origin main --tags
```

---

## 3. Android App Bundle (AAB) & Signing

SecureVault enforces **Play App Signing** with an isolated upload key.

1. **Keystore Configuration:**
   Ensure `keystore.properties` is present in the `android/` directory (never committed to git):
   ```properties
   storeFile=/path/to/securevault-upload.jks
   storePassword=YOUR_SECURE_STORE_PASSWORD
   keyAlias=securevault-upload
   keyPassword=YOUR_SECURE_KEY_PASSWORD
   ```

2. **Compile Release Bundle:**
   ```bash
   cd android
   ./gradlew bundleRelease
   ```
   Output artifact: `android/app/build/outputs/bundle/release/app-release.aab`.

3. **R8/ProGuard Verification:**
   - Verify `mapping.txt` is generated in `android/app/build/outputs/mapping/release/`.
   - Ensure no warnings regarding missing Room schemas, BouncyCastle reflection, or Autofill classes.

---

## 4. Google Play Console Staged Rollout

Never deploy directly to 100% of production users. Follow the tiered staged rollout schedule:

### Stage 1: Closed Internal Testing (100% internal, 48 hours)
- Upload `.aab` to Internal Testing track.
- Verify install and unlock on at least 3 physical test devices:
  - Android 8.0 (API 26 — minimum SDK)
  - Android 12/13 (API 31/33 — themed icons & data extraction rules)
  - Android 14/15 (API 34/35/36 — target SDK, Credential Manager & StrongBox)
- Verify zero-knowledge device loss recovery flow on a secondary device.
- Confirm Google Play Pre-Launch Report shows 0 crashes and 0 accessibility regressions.

### Stage 2: Staged Production Rollout (5% — 24 hours)
- Promote release to Production with a **5% rollout**.
- Monitor Google Play Console **Android Vitals**:
  - User-perceived crash rate must remain strictly **< 1.09%**.
  - User-perceived ANR rate must remain strictly **< 0.47%**.
- Check backend Sentry / CloudWatch error logs for auth step-up or sync spikes.

### Stage 3: Progressive Expansion (20% → 50% — 48 hours)
- Increase rollout to **20%** if error rates remain nominal for 24 hours.
- Increase rollout to **50%** after 48 hours of healthy telemetry.

### Stage 4: Full Release (100%)
- Complete rollout to 100%.

---

## 5. Rollback & Emergency Response Protocol

If a critical flaw, cryptographic regression, or elevated crash rate is detected:

1. **Halt Rollout Immediately:**
   - In Google Play Console → Release dashboard → **Halt rollout**.
   - Prevents any new users from downloading the affected version.

2. **Session Revocation (if server/device binding compromised):**
   - Trigger server-side revocation generation bump:
     ```sql
     UPDATE users SET revocation_generation = revocation_generation + 1 WHERE id = '...';
     ```
   - All active refresh tokens and device sessions are invalidated instantly.

3. **Hotfix Deployment:**
   - Create hotfix branch from release tag: `git checkout -b hotfix/vX.Y.(Z+1) vX.Y.Z`.
   - Implement fix, increment patch version, run test suite, and submit expedited review in Play Console.

---

## 6. Play Store Assets & Compliance Verification

- [x] Adaptive icon XMLs configured in `res/mipmap-anydpi-v26/`.
- [x] 512×512 store icon generated in `store_assets/icon_512.png`.
- [x] Public web account deletion URL active at `https://securevault.app/docs/account-deletion.html`.
- [x] Privacy Policy hosted on public HTTPS URL.
- [x] Data Safety form filled out accurately:
  - Personal info (email only for Google sign-in).
  - Encrypted files & vault records (marked End-to-End Encrypted).
  - Advertising ID: Not collected.
  - Financial data: Not collected.
