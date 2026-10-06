#!/usr/bin/env python3
"""CertLens oracle: parses every corpus cert with the openssl CLI and writes
expected.json (subject/issuer/DN order, dates, serial, sig alg, key alg/size,
curve, SANs, basicConstraints, keyUsage, EKU, fingerprints)."""
import json, re, subprocess, os

BASE = os.path.dirname(__file__)
CERTS = ['rsa2048','rsa4096','ecdsa256','ed25519','ca','expired','ecdsa384eku']

def sh(*a):
    return subprocess.run(a, capture_output=True, text=True, check=True).stdout

def parse(text, pattern, flags=0):
    m = re.search(pattern, text, flags)
    return m.group(1) if m else None

out = []
for name in CERTS:
    f = f'{BASE}/certs/{name}.pem'
    txt = sh('openssl','x509','-in',f,'-noout','-text')
    subject = sh('openssl','x509','-in',f,'-noout','-subject').strip().split('subject=',1)[1]
    issuer = sh('openssl','x509','-in',f,'-noout','-issuer').strip().split('issuer=',1)[1]
    dates = sh('openssl','x509','-in',f,'-noout','-dates')
    serial = sh('openssl','x509','-in',f,'-noout','-serial').strip().split('=',1)[1]
    sha256 = sh('openssl','x509','-in',f,'-noout','-fingerprint','-sha256').strip().split('=',1)[1].replace(':','')
    sha1 = sh('openssl','x509','-in',f,'-noout','-fingerprint','-sha1').strip().split('=',1)[1].replace(':','')
    sigalg = parse(txt, r'Signature Algorithm: (\S+)')
    keyalg = parse(txt, r'Public Key Algorithm: (\S+)')
    bits = parse(txt, r'Public-Key: \((\d+) bit\)')
    curve = parse(txt, r'NIST CURVE: (\S+)')
    exp = parse(txt, r'Exponent: (\d+)')
    san = parse(txt, r'X509v3 Subject Alternative Name:[^\n]*\n\s+([^\n]+)')
    bc = parse(txt, r'X509v3 Basic Constraints:[^\n]*\n\s+([^\n]+)')
    ku = parse(txt, r'X509v3 Key Usage:[^\n]*\n\s+([^\n]+)')
    eku = parse(txt, r'X509v3 Extended Key Usage:[^\n]*\n\s+([^\n]+)')
    version = parse(txt, r'Version: (\d+)')
    # ISO dates for comparison
    def iso(line):
        d = parse(dates, line+r'=(.+)')
        p = subprocess.run(['date','-u','-d',d,'+%s'],capture_output=True,text=True,check=True).stdout.strip()
        return int(p)*1000
    out.append(dict(name=name, subject=subject, issuer=issuer, serial=serial,
        sha256=sha256, sha1=sha1, sigalg=sigalg, keyalg=keyalg,
        bits=int(bits) if bits else None, curve=curve, exponent=int(exp) if exp else None,
        san=san, bc=bc, ku=ku, eku=eku, version=int(version) if version else None,
        notBefore=iso('notBefore'), notAfter=iso('notAfter')))
json.dump(out, open(f'{BASE}/expected.json','w'), indent=1)
print(f'{len(out)} certs -> expected.json')
for e in out: print(e['name'], e['sigalg'], e['keyalg'], e['bits'], e['curve'], 'san:', e['san'])
