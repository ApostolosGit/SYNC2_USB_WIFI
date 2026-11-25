# SYNC2_USB_WIFI — 6.0 LAB

Requested: one repository, one release number (6.0) for INO, Android APK and Python.
Scope: isolated synthetic TCP laboratory tests; no operational radar firmware or new real-radar connection. The previous repositories and versions are untouched.

- INO: the existing synthetic generator, version banner 6.0. The prior private Wi-Fi password was not transferred; a public LAB demonstration value replaces it.
- PY: full desktop GUI derived from v40.0 and the v50.0 FULL LAB work, version 6.0. Legacy USB/LAN and file analysis remain as in the previous source. New TCP path is synthetic only.
- Android: app versionName 6.0 and versionCode 15; separate LAB package. Recorder remains open through the existing automatic reconnect attempt; explicit user disconnect or exhausted retry stops it. New capture_index detects missing rows in the offline LAB audit; sequence reversal invalidates the active synthetic interval.
- Wire format AC5T and CSV compatibility marker LAB TCP v5 remain unchanged; these identify a protocol/schema, not the release version. This avoids an incompatible change solely for branding.
- Build: shared CI for PY, INO, Android tests, debug APK, and one combined ZIP. The APK and ZIP are published only after successful checks.
- Remaining: complete gap-aware Replay/Charts for new LAB CSV, physical device testing, Windows GUI tests, and independently qualified validation. Not an operational release or real-radar firmware. No claim of operational readiness.

## 6.0 LAB — Replay R1 (25/11/2026)

Requested: complete compilation/tests and add Replay/Charts for the new TCP CSV.
- Initial 6.0 build: all three checks and packaging passed (run 45654258068). Initial archive is kept unchanged.
- Python: dedicated synthetic timeline from the same continuity-aware audit. Existing Replay and chart buttons route the LAB format to its own playback and charts. Forward/reverse, pause, step, seek, speed, source-time display, per-event sector mask, explicit GAP/INVALID/AMBIGUOUS. No cross-gap timing. Legacy file path unchanged.
- Android: dedicated offline LAB replay dialog and charts, with the same explicit event categories. The legacy offline capture stays unchanged; the new synthetic file opens its own player.
- Both: chart missing IDs by sector, missing IDs per evaluated interval, source NORTH interval scatter, separate continuity counts. Only exact synthetic NORTH/sector fixtures are accepted. Old CSV without capture_index retains an explicit uncertainty warning; no claim of physical source failure. Maximum 250,000 replay events; no silent truncation.
- New automated regression tests cover clean interval, missing ID, gap, deleted indexed row, ambiguous ordering, partial interval, and legacy index warning (Python). Hardware and GUI interaction have not been physically tested. This is not the full legacy target/track replay for TCP real-radar streams.
- App release number stays 6.0; Android internal versionCode becomes 16. Separate replay-r1 archive protects the first build. AC5T wire/schema marker unchanged.

### Replay R1 review
Fixed JSON report serialization by keeping timeline events out of the summary object. Added a regression test for JSON round-trip. The final archive is named Replay R1 FINAL to distinguish it from the first CI attempt; versionName remains 6.0.
