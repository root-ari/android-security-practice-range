# Android Security Practice Range

Personal training range for Android application security — exploiting
intentionally vulnerable apps and CTF-style challenges to build real
Android bug bounty skills.

## Targets Covered
| App | Focus | Status |
|---|---|---|
| [OVAA](./targets/ovaa) | Bounty-realistic bugs (providers, activities, WebView) | 🚧 in progress |
| [InjuredAndroid](./targets/injuredandroid) | CTF flags across multiple vuln classes | ⬜ not started |
| [InsecureBankv2](./targets/insecurebankv2) | API-layer IDOR/BOLA against real backend | ⬜ not started |
| [DIVA](./targets/diva) | Focused drills per vulnerability type | ⬜ not started |

## Core Methodologies
- [Exported Component Exploitation](./methodology/exported-components.md)
- [WebView / JS Bridge Exploitation](./methodology/webview-jsbridge.md)
- [API-Layer IDOR / BOLA](./methodology/api-idor-bola.md)

## Tooling
Drozer · Frida · Objection · Burp Suite · jadx · apktool — [setup notes](./tools-setup.md)

> All targets are intentionally vulnerable practice applications, not
> live production systems. No findings here represent disclosed bounty
> reports.
