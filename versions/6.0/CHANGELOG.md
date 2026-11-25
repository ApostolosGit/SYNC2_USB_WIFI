# SYNC2_USB_WIFI — 6.0 LAB

Requested: one repository, one release number (6.0) for INO, Android APK and Python.
Scope: isolated synthetic TCP laboratory tests; no operational radar firmware or new real-radar connection. The previous repositories and versions are untouched.

- INO: the existing synthetic generator, version banner 6.0. The prior private Wi-Fi password was not transferred; a public LAB demonstration value replaces it.
- PY: full desktop GUI derived from v40.0 and the v50.0 FULL LAB work, version 6.0. Legacy USB/LAN and file analysis remain as in the previous source. New TCP path is synthetic only.
- Android: app versionName 6.0 and versionCode 15; separate LAB package. Recorder remains open through the existing automatic reconnect attempt; explicit user disconnect or exhausted retry stops it. New capture_index detects missing rows in the offline LAB audit; sequence reversal invalidates the active synthetic interval.
- Wire format AC5T and CSV compatibility marker LAB TCP v5 remain unchanged; these identify a protocol/schema, not the release version. This avoids an incompatible change solely for branding.
- Build: shared CI for PY, INO, Android tests, debug APK, and one combined ZIP. The APK and ZIP are published only after successful checks.
- Remaining: complete gap-aware Replay/Charts for new LAB CSV, physical device testing, Windows GUI tests, and independently qualified validation. Not an operational release or real-radar firmware. No claim of operational readiness.
