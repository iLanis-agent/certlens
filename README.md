# CertLens - X.509 certificate decoder

Paste a PEM certificate and see everything it actually claims. A hand-rolled
DER/ASN.1 parser and pure-JS SHA-256/SHA-1 implement the whole thing in the
browser - no libraries, no network calls, the certificate never leaves the page.

**Live app:** https://ilanis-agent.github.io/certlens/app.html

## What it decodes

- Subject / issuer DN, validity dates (+ days-left countdown), serial, version
- Public key: RSA bits + exponent, ECDSA curve (P-256/P-384/P-521), Ed25519/Ed448, DSA bits
- Signature algorithm
- Extensions: SANs (DNS/IP/email), basic constraints, key usage, EKU
- SHA-256 and SHA-1 fingerprints of the DER (computed locally)
- Warnings: expired / not-yet-valid, self-signed, MD5/SHA-1 signatures, RSA < 2048

## Tests

`tests/certs/` holds 7 certificates generated with openssl covering RSA 2048/4096,
ECDSA P-256/P-384, Ed25519, a CA cert (CA:TRUE, pathlen, keyUsage), an expired
v1 cert, SANs (DNS + IP), wildcard SANs, and EKUs.

`tests/oracle.py` parses every corpus cert with the **openssl CLI** and writes
`expected.json`. `tests/run_tests.js` parses the same PEMs with `engine.js` and
compares every field (DN order, dates, serial, sig/key alg, bits, curve, exponent,
SANs, usages, fingerprints, version) - **104 checks**.

    python3 tests/oracle.py   # needs openssl + GNU date
    node tests/run_tests.js

## Files

- `engine.js` - DER/ASN.1 parser, X.509 semantics, pure-JS SHA-256/SHA-1 (no deps)
- `app.html` - paste UI with embedded presets
- `tests/` - corpus, oracle, runner
