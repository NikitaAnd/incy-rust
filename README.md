<div align="center">

# INCY

**Cross-platform proxy client built on [Xray-core](https://github.com/XTLS/Xray-core)**

[![Website](https://img.shields.io/badge/incy.cc-6c5ce7?style=flat-square&logo=safari&logoColor=white)](https://incy.cc)
[![Docs](https://img.shields.io/badge/Documentation-346DDB?style=flat-square&logo=gitbook&logoColor=white)](https://docs.incy.cc)
[![Report a bug](https://img.shields.io/badge/Report_a_bug-feedback.incy.cc-2ea44f?style=flat-square&logo=github&logoColor=white)](https://feedback.incy.cc)
[![iOS](https://img.shields.io/badge/iOS-App_Store-0D96F6?style=flat-square&logo=app-store&logoColor=white)](https://apps.apple.com/ru/app/incy/id6756943388)
[![Android](https://img.shields.io/badge/Android-Google_Play-414141?style=flat-square&logo=google-play&logoColor=white)](https://play.google.com/store/apps/details?id=llc.itdev.incy)
[![Telegram](https://img.shields.io/badge/Telegram-incy__public-26A5E4?style=flat-square&logo=telegram&logoColor=white)](https://t.me/incy_public)

</div>

## Downloads

### Mobile & TV

| Platform | Link |
|:---------|:-----|
| iOS / Apple TV / macOS | [App Store](https://apps.apple.com/ru/app/incy/id6756943388) |
| Android / Android TV | [Google Play](https://play.google.com/store/apps/details?id=llc.itdev.incy) |
| Android APK (sideload) | [Download APK](https://github.com/INCY-DEV/incy-platforms/releases/download/latest/Incy.apk) |

### Desktop

> [!WARNING]
> The installers below are the existing INCY desktop releases; they are **not**
> builds of the independent Rust implementation in this repository. The original
> PC client sources were not available, so the Rust project is a new client, not
> a source-compatible port. The Rust client is experimental and currently has no
> published installers. See the build instructions below; install Xray-core
> separately.

| Platform | Installer | Portable |
|:---------|:----------|:---------|
| Windows (x64 / ARM64) | [Setup](https://github.com/INCY-DEV/incy-platforms/releases/download/latest/incy-windows-setup.exe) | [ZIP](https://github.com/INCY-DEV/incy-platforms/releases/download/latest/incy-windows-portable.zip) |
| macOS (Apple Silicon) | [DMG](https://github.com/INCY-DEV/incy-platforms/releases/download/latest/incy-macos-arm64.dmg) | — |
| macOS (Intel) | [DMG](https://github.com/INCY-DEV/incy-platforms/releases/download/latest/incy-macos-intel.dmg) | — |
| Linux (x64) | [DEB](https://github.com/INCY-DEV/incy-platforms/releases/download/latest/incy-linux-x64.deb) · [RPM](https://github.com/INCY-DEV/incy-platforms/releases/download/latest/incy-linux-x64.rpm) · [Arch](https://github.com/INCY-DEV/incy-platforms/releases/download/latest/incy-linux-x64.pkg.tar.zst) | [ZIP](https://github.com/INCY-DEV/incy-platforms/releases/download/latest/incy-linux-x64-portable.zip) |
| Linux (ARM64) | [DEB](https://github.com/INCY-DEV/incy-platforms/releases/download/latest/incy-linux-arm64.deb) · [RPM](https://github.com/INCY-DEV/incy-platforms/releases/download/latest/incy-linux-arm64.rpm) | [ZIP](https://github.com/INCY-DEV/incy-platforms/releases/download/latest/incy-linux-arm64-portable.zip) |

## Android updates with Obtainium

Android releases use **`android-vX.Y.Z`** (title **`Android vX.Y.Z`**).
Desktop releases use **`desktop-vX.Y.Z`**. Their versions are independent.

[Add INCY to Obtainium](https://apps.obtainium.imranr.dev/redirect?r=obtainium://app/%7B%22id%22%3A%22llc.itdev.incy%22%2C%22url%22%3A%22https%3A%2F%2Fgithub.com%2FINCY-DEV%2Fincy-platforms%22%2C%22author%22%3A%22INCY-DEV%22%2C%22name%22%3A%22INCY%22%2C%22additionalSettings%22%3A%22%7B%5C%22filterReleaseTitlesByRegEx%5C%22%3A%5C%22%5EAndroid%20v%5B0-9%5D%2B%5C%5C%5C%5C.%5B0-9%5D%2B%5C%5C%5C%5C.%5B0-9%5D%2B%24%5C%22%2C%5C%22apkFilterRegEx%5C%22%3A%5C%22%5E%5BIi%5Dncy%5C%5C%5C%5C.apk%24%5C%22%2C%5C%22versionExtractionRegEx%5C%22%3A%5C%22%5B0-9%5D%2B%5C%5C%5C%5C.%5B0-9%5D%2B%5C%5C%5C%5C.%5B0-9%5D%2B%5C%22%2C%5C%22verifyLatestTag%5C%22%3Afalse%2C%5C%22fallbackToOlderReleases%5C%22%3Atrue%2C%5C%22includePrereleases%5C%22%3Afalse%7D%22%7D) · [Import configuration](obtainium.json)

For an existing Obtainium entry, use these settings:

| Setting | Value |
|:--------|:------|
| Source | `https://github.com/INCY-DEV/incy-platforms` |
| Filter release titles by regular expression | `^Android v[0-9]+\.[0-9]+\.[0-9]+$` |
| Filter APKs by regular expression | `^[Ii]ncy\.apk$` |
| Version string extraction | `[0-9]+\.[0-9]+\.[0-9]+` |
| Verify Latest Tag | **Off** — `latest` combines independently versioned platforms |
| Fallback to older releases | **On** |

New Android releases contain only the signed APK and its checksum. Existing
mixed releases remain available for old download links; the title filter
excludes them. Direct download links above and in [RELEASE.json](RELEASE.json)
are updated independently for each platform. For automated publishing, see
[RELEASING.md](RELEASING.md).

The download buttons use the permanent `latest` tag. [RELEASE.json](RELEASE.json)
keeps version-specific URLs for application updates.


## Rust desktop client (experimental)

The Rust workspace is an independent desktop implementation built with Rust,
`egui` and Xray-core. The existing release scripts and metadata are retained,
but they still describe the upstream desktop release and do not package this
new client. Build from the repository root:

```sh
cargo build --release -p nikitavpnclient
cargo test --workspace
```

The GitHub Actions artifacts bundle the official Xray-core executable inside
NikitaVPNClient and extract it to a private application-data directory on first
launch. Normal users do not need to download Xray separately. A local development
build without `INCY_XRAY_BINARY` still needs `xray` on `PATH`, beside the app, or
selected in Settings. On Linux, a graphical session with X11 or Wayland is
required. State is stored locally under the platform's application-data directory
(or `INCY_DATA_DIR`). The CLI also offers
`nikitavpnclient list`, `nikitavpnclient import-link <URI>`,
`nikitavpnclient import-config <PATH>`, `nikitavpnclient config <PROFILE_UUID>`,
and `nikitavpnclient data-path`; generated config output contains credentials
and must be kept private. CI builds Linux x86_64, Windows x86_64 and macOS ARM64
artifacts through the **Build NikitaVPNClient** GitHub Actions workflow.

### Implemented in the Rust client

- Native desktop UI with local profile management, search, five color themes,
  share-link/full-JSON import, HTTPS subscriptions with background refresh, and
  connect/disconnect. The app also has a cross-platform system-tray menu to show
  the window, toggle the selected profile, or quit; closing the window hides it
  when tray initialization succeeds.
- VLESS, VMess, Trojan, Shadowsocks, SOCKS5, Hysteria2 and WireGuard link
  parsing; Xray JSON generation and loopback-only SOCKS/HTTP inbounds.
- Xray process supervision, optional per-user system proxy on Windows, macOS
  and GNOME, HTTPS tunnel probe, domain/IP routing rules, per-process proxy/direct
  rules for apps that connect to the local HTTP/SOCKS proxy, domestic/remote DNS,
  and Xray TLS ClientHello fragmentation settings.
- Private local state/config files, atomic state replacement with backup,
  HTTPS-only subscription redirects, validation and credential-safe errors.

### Not implemented yet

Kill switch, TUN mode, transparent per-application capture, QR import/export,
and complete parity with the existing INCY desktop client are not implemented.
Per-process Xray rules only affect apps that explicitly use the local SOCKS/HTTP
proxy; they do not capture arbitrary app traffic. The tray menu is implemented,
but availability depends on a desktop environment that supports
StatusNotifierItem (Linux) or the native tray (Windows/macOS). System proxy mode
is not a kill switch: applications can bypass it, and network traffic is not
guaranteed to stop if Xray exits. Imported Xray JSON is preserved
and passed to Xray at runtime, but is restricted to loopback-bound inbound
listeners and must still pass the installed Xray version's config validation.
KDE-specific proxy integration and runtime testing across Windows/macOS desktops
are also pending. Do not rely on this experimental build as a security boundary.

| Feature | Mobile & TV | Existing desktop release | Rust desktop |
|:--|:-:|:-:|:-:|
| **Subscriptions** — HTTPS URL and automatic refresh | ✅ | ✅ | ✅ background refresh |
| **Routing rules** — domains/IP to proxy, direct or block | ✅ | ✅ | ✅ basic Xray rules |
| **Full config import** — arbitrary Xray JSON | ✅ | ✅ | ✅ loopback-only listeners |
| **TLS fragmentation** | ✅ | ✅ | ✅ Xray TLS ClientHello |
| **Kill switch / TUN** | ✅ | ✅ | — |
| **Per-app proxy** | Android | ✅ | ✅ Xray rules for apps using local proxy; no transparent capture |
| **Tray / QR / TV pairing** | ✅ | ✅ | ✅ tray / — QR |
| **Themes** | ✅ | ✅ | ✅ graphite/light/midnight/ocean/forest |

The Rust client has no telemetry. Servers, credentials and subscriptions are
stored locally; do not share the state file or generated Xray config.

## Documentation

Setup guides, configuration reference and troubleshooting —
**[docs.incy.cc](https://docs.incy.cc)**

## Bug reports & feature requests

> [!IMPORTANT]
> All reports go through **[feedback.incy.cc](https://feedback.incy.cc)** — the
> only place we track them. Anything sent to chat, DMs or GitHub issues will get
> lost.

Include the app version, your platform, and what you expected to happen instead.
For tunnel problems, attach the logs from Settings.

Questions, setup help and general discussion — [@incy_public](https://t.me/incy_public).

## Support the project

INCY is free, collects nothing and sells nothing. If it is useful to you, a
donation keeps it that way.

- **[@incyhelperbot](https://t.me/incyhelperbot)** — cards, Telegram Stars, and support
- **[OxaPay](https://pay.oxapay.com/16388144)** — BTC, ETH, USDT and others

## Legal

INCY does not provide VPN services. Users are responsible for their own servers and must comply with local laws.
