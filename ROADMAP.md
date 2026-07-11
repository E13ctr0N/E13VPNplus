# E13VPN+ Roadmap

## Release policy

- `0.9.7` through `0.9.9` stabilize the current client while keeping the existing installer flow unchanged.
- VPN engine upgrades are pinned and handled separately from application dependency updates.
- The installer flow, installer description, and installation UX are not changed before `1.0.0`.
- `1.0.0` starts only after `0.9.9` and includes the redesigned installer with an application description shown before installation.

## 0.9.7 - Stabilization

- Fix system proxy and route ownership so E13VPN+ does not overwrite resources owned by other applications.
- Make start, cancellation, stop, retry, and termination events session-aware.
- Prevent writable runtime DLLs from being reused without integrity verification.
- Remove plaintext runtime VPN configurations after the engine has loaded them and during recovery cleanup.
- Fix subscription import and store persistence races and show import results on the VPN screen.
- Prevent global IPv6 traffic from silently bypassing TUN.
- Resolve current npm audit findings without changing bundled VPN engine versions.
- Add focused tests for the changed lifecycle, routing, and persistence behavior.

## 0.9.8 - Maintainability

- Remove the unused tun2socks runtime path, binary, downloader, and stale comments after Xray TUN regression testing.
- Remove unused plugins and decide whether the incomplete Lite build should be completed or deleted.
- Split the Rust application module into process, Windows integration, configuration, and Tauri command modules.
- Centralize frontend store access and log buffering.
- Pin sing-box, Xray, WinTUN, and libcronet versions and hashes in one engine manifest.

## 0.9.9 - Release hardening

- Add Windows CI for frontend build, Rust formatting, clippy, tests, and dependency audit.
- Validate generated configurations with the bundled sing-box and Xray binaries.
- Add persistent sanitized diagnostic logs and a support-ready diagnostics export.
- Finalize subscription refresh behavior and migration tests.
- Update screenshots, release documentation, license metadata, and the default GitHub branch.

## 1.0.0 - Installer redesign

- Redesign the installer flow.
- Show a clear E13VPN+ application description before installation.
- Review installation scope, elevation behavior, upgrade/repair behavior, and uninstall cleanup.
- Add installer-specific acceptance tests and release documentation.
