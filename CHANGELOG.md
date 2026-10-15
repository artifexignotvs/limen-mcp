# Changelog

## 0.2.0

- Add strict, bounded, redacted baseline snapshots with explicit scope labels.
- Compare added, resolved, unchanged and severity-shifted observation counts without assuming ordinal identity.
- Add `--fail-on-new` for regression gates while retaining existing default thresholds and JSON fields.
- Export SARIF 2.1.0 with rule help, aggregate fingerprints, safe artifact anchors and execution status.
- Reject malformed or incompatible baselines without echoing their contents.
- Document identity limits, privacy tradeoffs and code-scanning integration.
- Add Docker tag mutability and SHA-256 reference checks without pulling images or claiming publisher trust.

## 0.1.0

- Initial public release.
