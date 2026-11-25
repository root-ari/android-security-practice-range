# Fix — TheftOverwriteProvider Path Traversal

Companion to [theftoverwrite-provider.md](./theftoverwrite-provider.md). This
file is the actual patched implementation, broken into the three independent
issues found, so each fix can be understood (and reused) on its own.

## Vulnerable original

\`\`\`java
public class TheftOverwriteProvider extends ContentProvider {
    @Override
    public ParcelFileDescriptor openFile(@NonNull Uri uri, @NonNull String mode) throws FileNotFoundException {
        File file = new File(Environment.getExternalStorageDirectory(), uri.getLastPathSegment());
        return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_WRITE);
    }
    // ... other CRUD methods stubbed out
}
\`\`\`

Three separate problems, each needing its own fix:

| # | Problem | Consequence |
|---|---|---|
| 1 | `uri.getLastPathSegment()` trusted with no validation | Path traversal (`..%2F..%2F...`) escapes the intended folder |
| 2 | Caller's requested `mode` argument ignored | Always opens `MODE_READ_WRITE` regardless of what was asked |
| 3 | No permission required, `exported="true"` | Any zero-permission app on the device can call it |

---

## Fix 1 — Canonicalize and verify containment

\`\`\`java
@Override
public ParcelFileDescriptor openFile(@NonNull Uri uri, @NonNull String mode) throws FileNotFoundException {
    File baseDir = Environment.getExternalStorageDirectory();
    File requestedFile = new File(baseDir, uri.getLastPathSegment());

    File canonicalBase;
    File canonicalRequested;
    try {
        canonicalBase = baseDir.getCanonicalFile();
        canonicalRequested = requestedFile.getCanonicalFile();
    } catch (IOException e) {
        throw new FileNotFoundException("Unable to resolve path");
    }

    if (!canonicalRequested.getPath().startsWith(canonicalBase.getPath() + File.separator)) {
        throw new SecurityException("Path traversal attempt blocked: " + uri);
    }

    return ParcelFileDescriptor.open(canonicalRequested, parseMode(mode));
}
\`\`\`

**Why canonicalization, not just a `..` string check:** a naive filter that just
rejects strings containing `".."` is bypassable with percent-encoding tricks
(`%2e%2e`), double-encoding, or symlinks. `getCanonicalFile()` forces Java to
fully resolve the real, final filesystem path before any comparison happens —
the only check that can't be smuggled past.

**Why `+ File.separator` in the comparison:** without it, a sibling folder
like `/data/data/oversecured.ovaa_evil` would incorrectly pass a bare
`startsWith("/data/data/oversecured.ovaa")` check. This is a common way
people reintroduce the same bug while "fixing" it.

## Fix 2 — Honor the caller's requested mode

\`\`\`java
private int parseMode(String mode) {
    switch (mode) {
        case "r":   return ParcelFileDescriptor.MODE_READ_ONLY;
        case "w":   return ParcelFileDescriptor.MODE_WRITE_ONLY | ParcelFileDescriptor.MODE_CREATE | ParcelFileDescriptor.MODE_TRUNCATE;
        case "wa":  return ParcelFileDescriptor.MODE_WRITE_ONLY | ParcelFileDescriptor.MODE_CREATE | ParcelFileDescriptor.MODE_APPEND;
        case "rw":  return ParcelFileDescriptor.MODE_READ_WRITE | ParcelFileDescriptor.MODE_CREATE;
        case "rwt": return ParcelFileDescriptor.MODE_READ_WRITE | ParcelFileDescriptor.MODE_CREATE | ParcelFileDescriptor.MODE_TRUNCATE;
        default: throw new IllegalArgumentException("Invalid mode: " + mode);
    }
}
\`\`\`

Least privilege: a caller that only declared `"r"` should never silently
receive write access.

## Fix 3 — Require a signature-level permission

\`\`\`xml
<!-- AndroidManifest.xml -->
<permission android:name="oversecured.ovaa.permission.THEFT_PROVIDER"
    android:protectionLevel="signature" />

<provider android:name=".providers.TheftOverwriteProvider"
    android:authorities="oversecured.ovaa.theftoverwrite"
    android:exported="true"
    android:readPermission="oversecured.ovaa.permission.THEFT_PROVIDER"
    android:writePermission="oversecured.ovaa.permission.THEFT_PROVIDER" />
\`\`\`

`protectionLevel="signature"` means only apps signed with the **same
developer certificate** can hold this permission — a third-party attacker
app, signed with its own keystore, can declare `<uses-permission>` for this
all it wants and will never actually be granted it.

## Best fix — don't expose a raw file provider at all

OVAA's own manifest already shows the correct alternative, right next to the
vulnerable one:

\`\`\`xml
<provider android:name="androidx.core.content.FileProvider"
    android:authorities="oversecured.ovaa.fileprovider"
    android:exported="false"
    android:grantUriPermissions="true">
    <meta-data android:name="android.support.FILE_PROVIDER_PATHS" android:resource="@xml/provider_paths" />
</provider>
\`\`\`

`FileProvider` + `grantUriPermissions` stays `exported="false"` and only
grants access to **one specific, pre-declared URI at a time**, temporarily,
to whichever app it's explicitly handed to via an `Intent` — never a blanket
"any path, any app" door like `TheftOverwriteProvider`.

## Verifying the fix

Re-run the exploit app from [exploit/](./exploit/) against the patched APK:

- `readVictimFile(...)` should now throw `SecurityException: Path traversal attempt blocked`
- Direct `content://.../login_data.xml` (no traversal) should still work as
  originally intended, for any legitimate use case that required export in
  the first place — confirming the fix doesn't just block everything
  indiscriminately

## Takeaway for future targets

This bug class is not Android-version-dependent — it's a pure application
logic flaw, exploitable on any OS version if the developer never wrote the
canonicalization check. Storage format downstream (SharedPreferences,
DataStore, Room/SQLite) doesn't matter either — all of them are just files
on disk that this primitive reaches equally. Treat "exported provider +
no visible path validation in `openFile()`" as the trigger to test for this,
regardless of how old or new the target app is.
