# Ad Bear

Firefox-only MV3 extension for network monitoring, DNS filtering, and threat intel.

## Features

- **Connection Tracking** — real-time TCP/UDP connections with service fingerprinting (port/protocol), risk assessment, and state monitoring
- **DNS Monitor** — live query stream, per-domain stats, top blocked/allowed, resolve times, impact severity breakdown
- **DNS Filtering** — block ads, trackers, malware, phishing using 90+ blocklist sources (StevenBlack, OISD, HaGeZi, uBO, AdGuard, etc.) with quick template presets
- **Topology Graph** — canvas-based force-directed graph of connections with grouping (process/service/risk) and PNG export
- **Risk Rules** — regex-based classification (trackers, ads, malware, auth, financial, CDN, big tech, direct IP)
- **Network Profiles** — auto-detects network (Home/Work/Public WiFi), switches DNS filtering, alert mode, and blocklist feed behavior
- **Alerts** — port alerts (suspicious/high-risk ports), risk alerts, auto-blocking in strict mode
- **Query Log** — searchable, filterable log with 10,000 entry cap and clear action
- **History** — periodic snapshots with bar chart visualization, stored in IndexedDB
- **Context Menus** — right-click any IP/domain to copy, favorite, or block
- **Export** — CSV/JSON export of connections

## Install

1. Open Firefox → `about:debugging#/runtime/this-firefox`
2. "Load Temporary Add-on" → select `manifest.json`
3. Or package as `.zip` and upload to AMO

## Storage

| Scope | Backend | Keys |
|---|---|---|
| Background | `browser.storage.local` | `blocklist`, `blockedIps`, `whitelist`, `filteringEnabled` |
| Sidebar/Popup | `localStorage` | `ipwatch_profiles`, `ipwatch_favorites`, `ipwatch_blocklist`, `ipwatch_settings`, etc. |
| History | IndexedDB (`ipwatch_db`) | Connection snapshots (capped at 500) |

## Blocklist limit

100,000 domains per update call. Blocklist sources are parsed server-side from hosts/AdBlock format.

## Permissions

- `webRequest` + `webRequestBlocking` + `webNavigation` — intercept and block requests
- `dns` — DNS resolution with custom servers
- `storage` — persist blocklist/filtering state
- `nativeMessaging` — optional companion host for GeoIP/bandwidth
- `tabs` — tab identification
- `<all_urls>` — monitor all network activity

## License

MPL 2.0
