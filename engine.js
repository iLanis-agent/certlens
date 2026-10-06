/* CertLens engine - X.509 certificate decoder with a hand-rolled DER/ASN.1 parser
   and pure-JS SHA-256/SHA-1. Runs in browser (window.CL) and node.
   Verified field-by-field against the openssl CLI by tests/oracle.py. */
(function(root, factory){
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.CL = factory();
})(typeof self !== 'undefined' ? self : this, function(){
'use strict';

/* ---------------- base64/PEM ---------------- */
function pemToDer(pem){
  var m = /-----BEGIN CERTIFICATE-----([^-]+)-----END CERTIFICATE-----/.exec(String(pem).replace(/\r/g,''));
  if(!m) throw new Error('no PEM certificate block found');
  var b64 = m[1].replace(/\s+/g,'');
  var bin;
  if (typeof atob === 'function') bin = atob(b64);
  else bin = Buffer.from(b64, 'base64').toString('binary');
  var der = new Uint8Array(bin.length);
  for (var i=0;i<bin.length;i++) der[i]=bin.charCodeAt(i);
  return der;
}

/* ---------------- DER reader ---------------- */
function Reader(buf){ this.b=buf; this.p=0; }
Reader.prototype.readTLV = function(){
  var start=this.p;
  if(this.p>=this.b.length) throw new Error('DER: unexpected end');
  var tag=this.b[this.p++];
  var len=this.b[this.p++];
  if(len&0x80){
    var n=len&0x7f;
    if(n===0||n>3) throw new Error('DER: bad long-form length');
    len=0;
    for(var i=0;i<n;i++) len=(len<<8)|this.b[this.p++];
  }
  if(this.p+len>this.b.length) throw new Error('DER: length overruns buffer');
  var val=this.b.subarray(this.p, this.p+len);
  this.p+=len;
  return {tag:tag, len:len, val:val, start:start, end:this.p};
};
Reader.prototype.expect=function(tag){
  var t=this.readTLV();
  if(t.tag!==tag) throw new Error('DER: expected tag 0x'+tag.toString(16)+', got 0x'+t.tag.toString(16));
  return t;
};
function subReader(tlv){ return new Reader(tlv.val); }

/* helpers */
function oidStr(bytes){
  var first=bytes[0];
  var parts=[Math.floor(first/40), first%40];
  var acc=0;
  for(var i=1;i<bytes.length;i++){
    acc=(acc<<7)|(bytes[i]&0x7f);
    if(!(bytes[i]&0x80)){ parts.push(acc); acc=0; }
  }
  return parts.join('.');
}
function intHex(bytes){
  var s='';
  for(var i=0;i<bytes.length;i++) s+=('0'+bytes[i].toString(16)).slice(-2);
  s=s.replace(/^0+(?=[0-9a-f])/, '');
  return (s||'0').toUpperCase();
}
function intBytesTrim(bytes){
  var i=0;
  while(i<bytes.length-1 && bytes[i]===0) i++;
  return bytes.subarray(i);
}
function timeStr(bytes){
  var s='';
  for(var i=0;i<bytes.length;i++) s+=String.fromCharCode(bytes[i]);
  var m;
  if(m=/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s)){ /* UTCTime */
    var y=parseInt(m[1],10); y += (y<50)?2000:1900;
    return Date.UTC(y, m[2]-1, m[3], m[4], m[5], m[6]);
  }
  if(m=/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s)) /* GeneralizedTime */
    return Date.UTC(+m[1], m[2]-1, m[3], m[4], m[5], m[6]);
  throw new Error('DER: unparseable time '+s);
}
function strVal(tlv){
  var s='';
  if(tlv.tag===0x0C){ /* UTF8String */
    var bytes=tlv.val, i=0;
    while(i<bytes.length){
      var c=bytes[i++];
      if(c<0x80){ s+=String.fromCharCode(c); }
      else if((c&0xE0)===0xC0){ s+=String.fromCharCode(((c&0x1F)<<6)|(bytes[i++]&0x3F)); }
      else if((c&0xF0)===0xE0){ s+=String.fromCharCode(((c&0x0F)<<12)|((bytes[i++]&0x3F)<<6)|(bytes[i++]&0x3F)); }
      else if((c&0xF8)===0xF0){ var cp=((c&0x07)<<18)|((bytes[i++]&0x3F)<<12)|((bytes[i++]&0x3F)<<6)|(bytes[i++]&0x3F); s+=String.fromCodePoint(cp); }
    }
    return s;
  }
  for(var i=0;i<tlv.val.length;i++) s+=String.fromCharCode(tlv.val[i]); /* Printable/IA5/T61-ish */
  return s;
}

/* ---------------- OIDs ---------------- */
var DN_OIDS={'2.5.4.3':'CN','2.5.4.6':'C','2.5.4.7':'L','2.5.4.8':'ST','2.5.4.10':'O','2.5.4.11':'OU','1.2.840.113549.1.9.1':'email','2.5.4.5':'serialNumber','0.9.2342.19200300.100.1.25':'DC','0.9.2342.19200300.100.1.1':'UID'};
var SIG_OIDS={'1.2.840.113549.1.1.11':'sha256WithRSAEncryption','1.2.840.113549.1.1.12':'sha384WithRSAEncryption','1.2.840.113549.1.1.13':'sha512WithRSAEncryption','1.2.840.113549.1.1.5':'sha1WithRSAEncryption','1.2.840.113549.1.1.4':'md5WithRSAEncryption','1.2.840.113549.1.1.10':'rsassaPss','1.2.840.10045.4.3.2':'ecdsa-with-SHA256','1.2.840.10045.4.3.3':'ecdsa-with-SHA384','1.2.840.10045.4.3.4':'ecdsa-with-SHA512','1.3.101.112':'Ed25519','1.3.101.113':'Ed448'};
var KEY_OIDS={'1.2.840.113549.1.1.1':'rsaEncryption','1.2.840.10045.2.1':'id-ecPublicKey','1.3.101.112':'Ed25519','1.3.101.113':'Ed448','1.2.840.10040.4.1':'dsa'};
var CURVE_OIDS={'1.2.840.10045.3.1.7':'P-256','1.3.132.0.34':'P-384','1.3.132.0.35':'P-521','1.3.132.0.10':'secp256k1'};
var EKU_OIDS={'1.3.6.1.5.5.7.3.1':'serverAuth','1.3.6.1.5.5.7.3.2':'clientAuth','1.3.6.1.5.5.7.3.3':'codeSigning','1.3.6.1.5.5.7.3.4':'emailProtection','1.3.6.1.5.5.7.3.8':'timeStamping','1.3.6.1.5.5.7.3.9':'OCSPSigning'};

function parseName(tlv){
  var out=[], r=subReader(tlv);
  while(true){
    var set;
    try{ set=r.readTLV(); }catch(e){ break; }
    var sr=subReader(set);
    var seq=sr.expect(0x30);
    var qr=subReader(seq);
    var oid=oidStr(qr.expect(0x06).val);
    var val=strVal(qr.readTLV());
    out.push({k:DN_OIDS[oid]||oid, v:val});
  }
  return out;
}
function dnToString(parts){
  return parts.map(function(p){return p.k+'='+p.v;}).join(', ');
}

function parseBitString(tlv){
  return tlv.val.subarray(1); /* drop unused-bits count byte */
}

function parseExtensions(tlv){
  /* tlv is [3] EXPLICIT containing SEQUENCE OF Extension */
  var r=subReader(tlv);
  var seq=r.expect(0x30);
  var er=subReader(seq);
  var out=[];
  while(true){
    var ext;
    try{ ext=er.readTLV(); }catch(e){ break; }
    var xr=subReader(ext);
    var oid=oidStr(xr.expect(0x06).val);
    var critical=false, next=xr.readTLV();
    if(next.tag===0x01){ critical=next.val[0]!==0; next=xr.readTLV(); }
    out.push({oid:oid, critical:critical, value:next.val});
  }
  return out;
}

function parseSAN(bytes){
  var r=new Reader(bytes);
  var seq=r.expect(0x30);
  var sr=subReader(seq);
  var dns=[], ips=[], emails=[];
  while(true){
    var g;
    try{ g=sr.readTLV(); }catch(e){ break; }
    if(g.tag===0x82) dns.push(strVal(g));
    else if(g.tag===0x87) ips.push(Array.from(g.val).join('.'));
    else if(g.tag===0x81) emails.push(strVal(g));
  }
  return {dns:dns, ips:ips, emails:emails};
}
function parseBasicConstraints(bytes){
  var r=new Reader(bytes);
  var seq=r.expect(0x30);
  var sr=subReader(seq);
  var ca=false, pathlen=null;
  try{
    var t=sr.readTLV();
    if(t.tag===0x01){ ca=t.val[0]!==0;
      try{ var p=sr.readTLV(); pathlen=parseInt(intHex(p.val)||'0',16); }catch(e){}
    } else if(t.tag===0x02){ pathlen=parseInt(intHex(t.val)||'0',16); }
  }catch(e){}
  return {ca:ca, pathlen:pathlen};
}
var KU_BITS=['digitalSignature','nonRepudiation','keyEncipherment','dataEncipherment','keyAgreement','keyCertSign','cRLSign','encipherOnly','decipherOnly'];
function parseKeyUsage(bytes){
  var r=new Reader(bytes);
  var bs=parseBitString(r.expect(0x03));
  var out=[];
  for(var i=0;i<bs.length*8 && i<9;i++){
    var byte=bs[i>>3], bit=7-(i&7);
    if(byte&(1<<bit)) out.push(KU_BITS[i]);
  }
  return out;
}
function parseEKU(bytes){
  var r=new Reader(bytes);
  var seq=r.expect(0x30);
  var sr=subReader(seq), out=[];
  while(true){
    var o;
    try{ o=sr.readTLV(); }catch(e){ break; }
    out.push(EKU_OIDS[oidStr(o.val)]||oidStr(o.val));
  }
  return out;
}

/* ---------------- SHA-256 / SHA-1 (pure JS) ---------------- */
function sha256(bytes){
  var K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  var H=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
  var l=bytes.length, bitLen=l*8;
  var padded=[], i;
  for(i=0;i<l;i++) padded.push(bytes[i]);
  padded.push(0x80);
  while(padded.length%64!==56) padded.push(0);
  for(i=7;i>=0;i--) padded.push((bitLen/Math.pow(256,i))&0xff);
  var w=new Array(64);
  for(var off=0;off<padded.length;off+=64){
    for(i=0;i<16;i++) w[i]=((padded[off+i*4]<<24)|(padded[off+i*4+1]<<16)|(padded[off+i*4+2]<<8)|padded[off+i*4+3])>>>0;
    for(i=16;i<64;i++){
      var s0=(rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>>3))>>>0;
      var s1=(rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>>10))>>>0;
      w[i]=(w[i-16]+s0+w[i-7]+s1)>>>0;
    }
    var a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
    for(i=0;i<64;i++){
      var S1=(rotr(e,6)^rotr(e,11)^rotr(e,25))>>>0;
      var ch=((e&f)^((~e)&g))>>>0;
      var t1=(h+S1+ch+K[i]+w[i])>>>0;
      var S0=(rotr(a,2)^rotr(a,13)^rotr(a,22))>>>0;
      var maj=((a&b)^(a&c)^(b&c))>>>0;
      var t2=(S0+maj)>>>0;
      h=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0;
    }
    H[0]=(H[0]+a)>>>0;H[1]=(H[1]+b)>>>0;H[2]=(H[2]+c)>>>0;H[3]=(H[3]+d)>>>0;
    H[4]=(H[4]+e)>>>0;H[5]=(H[5]+f)>>>0;H[6]=(H[6]+g)>>>0;H[7]=(H[7]+h)>>>0;
  }
  return H.map(function(x){return ('0000000'+x.toString(16)).slice(-8);}).join('').toUpperCase();
}
function rotr(x,n){ return ((x>>>n)|(x<<(32-n)))>>>0; }
function sha1(bytes){
  var h0=0x67452301,h1=0xEFCDAB89,h2=0x98BADCFE,h3=0x10325476,h4=0xC3D2E1F0;
  var l=bytes.length, bitLen=l*8;
  var padded=[], i;
  for(i=0;i<l;i++) padded.push(bytes[i]);
  padded.push(0x80);
  while(padded.length%64!==56) padded.push(0);
  for(i=7;i>=0;i--) padded.push((bitLen/Math.pow(256,i))&0xff);
  var w=new Array(80);
  for(var off=0;off<padded.length;off+=64){
    for(i=0;i<16;i++) w[i]=((padded[off+i*4]<<24)|(padded[off+i*4+1]<<16)|(padded[off+i*4+2]<<8)|padded[off+i*4+3])>>>0;
    for(i=16;i<80;i++) w[i]=rotl(w[i-3]^w[i-8]^w[i-14]^w[i-16],1);
    var a=h0,b=h1,c=h2,d=h3,e=h4;
    for(i=0;i<80;i++){
      var f,k;
      if(i<20){f=(b&c)|((~b)&d);k=0x5A827999;}
      else if(i<40){f=b^c^d;k=0x6ED9EBA1;}
      else if(i<60){f=(b&c)|(b&d)|(c&d);k=0x8F1BBCDC;}
      else {f=b^c^d;k=0xCA62C1D6;}
      var t=(rotl(a,5)+f+e+k+w[i])>>>0;
      e=d;d=c;c=rotl(b,30);b=a;a=t;
    }
    h0=(h0+a)>>>0;h1=(h1+b)>>>0;h2=(h2+c)>>>0;h3=(h3+d)>>>0;h4=(h4+e)>>>0;
  }
  return [h0,h1,h2,h3,h4].map(function(x){return ('0000000'+x.toString(16)).slice(-8);}).join('').toUpperCase();
}
function rotl(x,n){ return ((x<<n)|(x>>>(32-n)))>>>0; }

/* ---------------- X.509 parse ---------------- */
function parseCert(pem){
  var der=pemToDer(pem);
  var r=new Reader(der);
  var cert=r.expect(0x30);
  var cr=subReader(cert);
  var tbs=cr.expect(0x30);
  var sigAlgTlv=cr.expect(0x30);
  cr.expect(0x03); /* signatureValue */

  var t=subReader(tbs);
  var version=1;
  var next=t.readTLV();
  if(next.tag===0xA0){ var vr=subReader(next); version=parseInt(intHex(vr.expect(0x02).val),16)+1; next=t.readTLV(); }
  var serial=intHex(next.val);

  t.expect(0x30); /* tbs signature */
  var issuer=parseName(t.expect(0x30));

  var validity=t.expect(0x30);
  var vr2=subReader(validity);
  var notBefore=timeStr(vr2.readTLV().val);
  var notAfter=timeStr(vr2.readTLV().val);

  var subject=parseName(t.expect(0x30));

  var spki=t.expect(0x30);
  var sr=subReader(spki);
  var algSeq=sr.expect(0x30);
  var ar=subReader(algSeq);
  var keyAlgOid=oidStr(ar.expect(0x06).val);
  var curveOid=null;
  try{ var param=ar.readTLV(); if(param.tag===0x06) curveOid=oidStr(param.val); }catch(e){}
  var pubBits=parseBitString(sr.expect(0x03));

  var keyAlg=KEY_OIDS[keyAlgOid]||keyAlgOid;
  var keyInfo={alg:keyAlg};
  if(keyAlgOid==='1.2.840.113549.1.1.1'){
    var kr=new Reader(pubBits);
    var kseq=kr.expect(0x30);
    var ksr=subReader(kseq);
    var modulus=intBytesTrim(ksr.expect(0x02).val);
    var exponent=parseInt(intHex(ksr.expect(0x02).val),16);
    keyInfo.bits=modulus.length*8;
    keyInfo.exponent=exponent;
  } else if(keyAlgOid==='1.2.840.10045.2.1'){
    keyInfo.curve=CURVE_OIDS[curveOid]||curveOid;
    keyInfo.bits=(pubBits.length-1)*4; /* uncompressed point: 0x04 + 2 coords */
  } else if(keyAlgOid==='1.3.101.112'||keyAlgOid==='1.3.101.113'){
    keyInfo.bits=pubBits.length*8;
  }

  var exts=[];
  var rest=subReader(tbs);
  /* walk tbs again to find [3] */
  var t2=subReader(tbs);
  while(true){
    var tlv;
    try{ tlv=t2.readTLV(); }catch(e){ break; }
    if(tlv.tag===0xA3) exts=parseExtensions(tlv);
  }

  var out={version:version, serial:serial,
    sigAlg:SIG_OIDS[oidStr(subReader(sigAlgTlv).expect(0x06).val)]||oidStr(subReader(sigAlgTlv).expect(0x06).val),
    issuer:issuer, issuerStr:dnToString(issuer),
    subject:subject, subjectStr:dnToString(subject),
    notBefore:notBefore, notAfter:notAfter,
    key:keyInfo,
    sha256:sha256(der), sha1:sha1(der),
    derBytes:der.length};

  exts.forEach(function(x){
    try{
      if(x.oid==='2.5.29.17') out.san=parseSAN(x.value);
      else if(x.oid==='2.5.29.19') out.basicConstraints=parseBasicConstraints(x.value);
      else if(x.oid==='2.5.29.15') out.keyUsage=parseKeyUsage(x.value);
      else if(x.oid==='2.5.29.37') out.eku=parseEKU(x.value);
    }catch(e){ /* tolerate odd extensions */ }
  });

  out.selfSigned = out.issuerStr===out.subjectStr;
  var now=Date.now();
  out.daysLeft=Math.floor((out.notAfter-now)/86400000);
  out.expired=out.notAfter<now;
  out.notYetValid=out.notBefore>now;
  return out;
}

return {pemToDer:pemToDer, parseCert:parseCert, sha256:sha256, sha1:sha1};
});
