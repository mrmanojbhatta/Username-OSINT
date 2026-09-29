# Changelog

## 4.0.0
- Modular public username OSINT scanner.
- External site database.
- SQLite cache/case storage.
- Concurrent scanning and host rate limiting.
- Multi-state verification and confidence.
- Evidence snapshots and SHA-256.
- Interactive HTML and JSON reports.
- Site validator and offline tests.


## 4.0.0 database expansion

- Expanded `data/sites.json` to 2,336 public username/profile endpoint definitions.
- Kept the original curated entries marked `verified` where appropriate.
- Marked the expanded catalog `needs_validation` rather than claiming unverified endpoints are production-accurate.
- Added broad Wikimedia language-project user-page coverage.
- Validated JSON structure, unique names/domains, username templates, and CLI site validation.
