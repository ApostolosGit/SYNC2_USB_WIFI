# 7.0 LAB validation candidate
Base: 6.0 Replay R1 FINAL (d9ef4a3840b66b47bcc296dfde775ef0572cabe0).

Requested: unified v7 numbering, preserve existing applications, add offline integrity and interoperability checks.
Changes:
- Version labels 7.0; Android versionCode 17.
- Offline audit in both clients now accepts only exact synthetic fixture payloads, including report-only mode.
- Capture-index upper bound avoids overflow; Python metadata range aligned with signed Kotlin Long.
- Common synthetic CSV test resource used by both Python and Android, including explicit GAP, invalid fixture, clean and incomplete intervals.
- 33,001-frame offline regression in both languages.
- Separate CI build and archive; 6.0 sources and artifacts unchanged.

Scope: INO remains a synthetic generator, not external CLOCK/DATA capture. No operational integration or field approval. Existing LAB protocol/schema marker remains v5 for compatibility. The 250,000-event replay limit is unchanged; streaming audit is separate. Physical endurance, GUI and reconnect behavior require independent lab testing. Actual input integration is not implemented. No claim of field readiness.
