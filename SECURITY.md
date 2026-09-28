# Security Policy

KMJ OmniDesk is currently pre-alpha and is not approved for production remote access.

## Security invariants

- Never commit production credentials, private signing keys, access tokens, customer secrets, or machine credentials.
- Remote input/control must remain behind explicit authenticated authorization.
- Network and licensing failures must not silently widen permissions.
- Production licensing authority belongs to KMJ Main Platform; clients must not contain a master unlock secret.
- Session cryptography and identity decisions require dedicated threat-model review before release.
- Relay operators must not be treated as trusted endpoints for session plaintext.
- Logs must avoid session secrets, credentials, clipboard contents, and transferred-file contents by default.

## Reporting

Security findings should be reported privately to KMJ TECHNO rather than disclosed in public issue trackers before coordinated review.
