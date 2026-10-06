/* CertLens node runner: engine parse vs openssl-derived expected.json */
'use strict';
const fs = require('fs');
const path = require('path');
const CL = require(path.join(__dirname, '..', 'engine.js'));
const expected = JSON.parse(fs.readFileSync(path.join(__dirname, 'expected.json'), 'utf8'));

let checks = 0, fails = [];
function chk(c, m) { checks++; if (!c) fails.push(m); }

function dnParts(s) { // "C = US, ST = California" -> [["C","US"],...]
  return s.split(/,\s*/).map(p => { const i = p.indexOf('='); return [p.slice(0, i).trim(), p.slice(i + 1).trim()]; });
}
const KU_MAP = {'Digital Signature':'digitalSignature','Non Repudiation':'nonRepudiation','Key Encipherment':'keyEncipherment','Data Encipherment':'dataEncipherment','Key Agreement':'keyAgreement','Certificate Sign':'keyCertSign','CRL Sign':'cRLSign','Encipher Only':'encipherOnly','Decipher Only':'decipherOnly'};
const EKU_MAP = {'TLS Web Server Authentication':'serverAuth','TLS Web Client Authentication':'clientAuth','Code Signing':'codeSigning','E-mail Protection':'emailProtection','Time Stamping':'timeStamping','OCSP Signing':'OCSPSigning'};

for (const e of expected) {
  const pem = fs.readFileSync(path.join(__dirname, 'certs', e.name + '.pem'), 'utf8');
  const c = CL.parseCert(pem);
  chk(JSON.stringify(c.subject) === JSON.stringify(dnParts(e.subject).map(([k, v]) => ({k, v}))),
    `${e.name}: subject ${c.subjectStr} != ${e.subject}`);
  chk(JSON.stringify(c.issuer) === JSON.stringify(dnParts(e.issuer).map(([k, v]) => ({k, v}))),
    `${e.name}: issuer ${c.issuerStr} != ${e.issuer}`);
  chk(c.serial === e.serial, `${e.name}: serial ${c.serial} != ${e.serial}`);
  chk(c.notBefore === e.notBefore, `${e.name}: notBefore ${c.notBefore} != ${e.notBefore}`);
  chk(c.notAfter === e.notAfter, `${e.name}: notAfter ${c.notAfter} != ${e.notAfter}`);
  chk(c.sha256 === e.sha256, `${e.name}: sha256 mismatch`);
  chk(c.sha1 === e.sha1, `${e.name}: sha1 mismatch`);
  chk(c.sigAlg.toLowerCase() === e.sigalg.toLowerCase(), `${e.name}: sigalg ${c.sigAlg} != ${e.sigalg}`);
  chk(c.key.alg.toLowerCase() === e.keyalg.toLowerCase(), `${e.name}: keyalg ${c.key.alg} != ${e.keyalg}`);
  if (e.bits) chk(c.key.bits === e.bits, `${e.name}: bits ${c.key.bits} != ${e.bits}`);
  if (e.curve) chk(c.key.curve === e.curve, `${e.name}: curve ${c.key.curve} != ${e.curve}`);
  if (e.exponent) chk(c.key.exponent === e.exponent, `${e.name}: exponent ${c.key.exponent} != ${e.exponent}`);
  if (e.version) chk(c.version === e.version, `${e.name}: version ${c.version} != ${e.version}`);
  if (e.san) {
    const dns = [...e.san.matchAll(/DNS:([^,]+)/g)].map(m => m[1].trim());
    const ips = [...e.san.matchAll(/IP Address:([^,]+)/g)].map(m => m[1].trim());
    chk(JSON.stringify(c.san && c.san.dns) === JSON.stringify(dns), `${e.name}: SAN dns ${JSON.stringify(c.san && c.san.dns)} != ${JSON.stringify(dns)}`);
    chk(JSON.stringify(c.san && c.san.ips) === JSON.stringify(ips), `${e.name}: SAN ips mismatch`);
  }
  if (e.bc) {
    const ca = /CA:TRUE/.test(e.bc);
    const pl = /pathlen:(\d+)/.exec(e.bc);
    chk(c.basicConstraints && c.basicConstraints.ca === ca, `${e.name}: basicConstraints ca mismatch`);
    if (pl) chk(c.basicConstraints.pathlen === parseInt(pl[1], 10), `${e.name}: pathlen mismatch`);
  }
  if (e.ku) {
    const ku = e.ku.split(/,\s*/).map(x => KU_MAP[x.trim()]);
    chk(JSON.stringify(c.keyUsage) === JSON.stringify(ku), `${e.name}: keyUsage ${JSON.stringify(c.keyUsage)} != ${JSON.stringify(ku)}`);
  }
  if (e.eku) {
    const eku = e.eku.split(/,\s*/).map(x => EKU_MAP[x.trim()]);
    chk(JSON.stringify(c.eku) === JSON.stringify(eku), `${e.name}: eku ${JSON.stringify(c.eku)} != ${JSON.stringify(eku)}`);
  }
  chk(c.selfSigned === (c.issuerStr === c.subjectStr), `${e.name}: selfSigned flag inconsistent`);
}

console.log(`${checks} checks, ${fails.length} failures`);
if (fails.length) { fails.forEach(f => console.log('FAIL', f)); process.exit(1); }
console.log('ALL PASS');
