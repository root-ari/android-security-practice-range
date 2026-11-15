# OVAA — Oversecured Vulnerable Android App

Purpose-built vulnerable app mirroring real-world Android bug bounty
findings. Source: https://github.com/oversecured/ovaa

## Findings
- [ ] Exported Content Provider SQL Injection
- [ ] Exported Activity Auth Bypass
- [ ] WebView / JS Bridge Token Leak via Deep Link

## Setup
./gradlew assembleDebug (or build via Android Studio)
adb install app-debug.apk
