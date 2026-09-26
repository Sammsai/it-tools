export interface Ed25519KeyPairResult {
  // OpenSSH Format
  publicKeyOpenSSH: string;
  privateKeyOpenSSH: string;

  // PEM Formats
  publicKeyPem: string;
  privateKeyPem: string;

  // Raw representations
  publicKeyHex: string;
  publicKeyBase64: string;
  privateKeyHex: string;
  privateKeyBase64: string;

  // Fingerprints
  fingerprintSha256: string;
  fingerprintMd5: string;
}

export type Ed25519KeyPair = Ed25519KeyPairResult;

export interface GenerateEd25519Options {
  seed?: Uint8Array | string;
  comment?: string;
}

// Curve25519 / Ed25519 Parameters (RFC 8032)
const P = 2n ** 255n - 19n;
const D = mod(-121665n * modInverse(121666n, P));

function mod(n: bigint, m: bigint = P): bigint {
  return ((n % m) + m) % m;
}

function modPow(base: bigint, exp: bigint, m: bigint = P): bigint {
  let res = 1n;
  let b = base % m;
  let e = exp;
  while (e > 0n) {
    if (e % 2n === 1n) {
      res = (res * b) % m;
    }
    b = (b * b) % m;
    e /= 2n;
  }
  return res;
}

function modInverse(a: bigint, m: bigint = P): bigint {
  return modPow(a, m - 2n, m);
}

// Base point B = (Bx, By) on Ed25519
const By = mod(4n * modInverse(5n, P));

function recoverX(y: bigint, signBit: bigint): bigint {
  const u = mod(y * y - 1n);
  const v = mod(D * y * y + 1n);
  let x = modPow(u * modInverse(v), (P + 3n) / 8n, P);
  if (mod(x * x * v - u) !== 0n) {
    const I = modPow(2n, (P - 1n) / 4n, P);
    x = mod(x * I);
  }
  if ((x % 2n) !== signBit) {
    x = mod(-x);
  }
  return x;
}

const Bx = recoverX(By, 0n);

class Point {
  X: bigint;
  Y: bigint;
  Z: bigint;
  T: bigint;

  constructor(X: bigint, Y: bigint, Z: bigint, T: bigint) {
    this.X = X;
    this.Y = Y;
    this.Z = Z;
    this.T = T;
  }

  static zero(): Point {
    return new Point(0n, 1n, 1n, 0n);
  }

  static base(): Point {
    return new Point(Bx, By, 1n, mod(Bx * By));
  }

  add(other: Point): Point {
    const A = mod((this.Y - this.X) * (other.Y - other.X));
    const B = mod((this.Y + this.X) * (other.Y + other.X));
    const C = mod(2n * this.T * D * other.T);
    const D2 = mod(2n * this.Z * other.Z);
    const E = mod(B - A);
    const F = mod(D2 - C);
    const G = mod(D2 + C);
    const H = mod(B + A);
    return new Point(mod(E * F), mod(G * H), mod(F * G), mod(E * H));
  }

  double(): Point {
    const A = mod(this.X * this.X);
    const B = mod(this.Y * this.Y);
    const C = mod(2n * this.Z * this.Z);
    const D2 = mod(-A);
    const E = mod((this.X + this.Y) * (this.X + this.Y) - A - B);
    const G = mod(D2 + B);
    const F = mod(G - C);
    const H = mod(D2 - B);
    return new Point(mod(E * F), mod(G * H), mod(F * G), mod(E * H));
  }

  multiply(scalar: bigint): Point {
    let res = Point.zero();
    let temp: Point = this;
    let s = scalar;
    while (s > 0n) {
      if (s & 1n) {
        res = res.add(temp);
      }
      temp = temp.double();
      s >>= 1n;
    }
    return res;
  }

  toAffine(): { x: bigint; y: bigint } {
    const invZ = modInverse(this.Z);
    return {
      x: mod(this.X * invZ),
      y: mod(this.Y * invZ),
    };
  }

  encode(): Uint8Array {
    const { x, y } = this.toAffine();
    const out = new Uint8Array(32);
    let tempY = y;
    for (let i = 0; i < 32; i++) {
      out[i] = Number(tempY & 0xffn);
      tempY >>= 8n;
    }
    if (x & 1n) {
      out[31] |= 0x80;
    }
    return out;
  }
}

export function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

export function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.replace(/[^0-9a-fA-F]/g, '');
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    bytes[i / 2] = Number.parseInt(cleanHex.substring(i, i + 2), 16);
  }
  return bytes;
}

const B64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

export function bytesToBase64(bytes: Uint8Array): string {
  let result = '';
  const len = bytes.length;
  for (let i = 0; i < len; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < len ? bytes[i + 1] : 0;
    const b2 = i + 2 < len ? bytes[i + 2] : 0;

    result += B64_CHARS[b0 >> 2];
    result += B64_CHARS[((b0 & 3) << 4) | (b1 >> 4)];
    result += i + 1 < len ? B64_CHARS[((b1 & 15) << 2) | (b2 >> 6)] : '=';
    result += i + 2 < len ? B64_CHARS[b2 & 63] : '=';
  }
  return result;
}

export function base64ToBytes(base64: string): Uint8Array {
  const cleanB64 = base64.replace(/[^A-Za-z0-9+/=]/g, '');
  let pad = 0;
  if (cleanB64.endsWith('==')) pad = 2;
  else if (cleanB64.endsWith('=')) pad = 1;

  const len = Math.max(0, Math.floor((cleanB64.length * 3) / 4) - pad);
  const bytes = new Uint8Array(len);
  let byteIndex = 0;

  for (let i = 0; i < cleanB64.length; i += 4) {
    const c0 = B64_CHARS.indexOf(cleanB64[i]);
    const c1 = B64_CHARS.indexOf(cleanB64[i + 1]);
    const c2 = cleanB64[i + 2] === '=' ? 0 : B64_CHARS.indexOf(cleanB64[i + 2]);
    const c3 = cleanB64[i + 3] === '=' ? 0 : B64_CHARS.indexOf(cleanB64[i + 3]);

    if (byteIndex < len) bytes[byteIndex++] = (c0 << 2) | (c1 >> 4);
    if (byteIndex < len) bytes[byteIndex++] = ((c1 & 15) << 4) | (c2 >> 2);
    if (byteIndex < len) bytes[byteIndex++] = ((c2 & 3) << 6) | c3;
  }
  return bytes;
}

export function encodeUtf8(str: string): Uint8Array {
  const utf8: number[] = [];
  for (let i = 0; i < str.length; i++) {
    let charcode = str.charCodeAt(i);
    if (charcode < 0x80) {
      utf8.push(charcode);
    }
    else if (charcode < 0x800) {
      utf8.push(0xc0 | (charcode >> 6), 0x80 | (charcode & 0x3f));
    }
    else if (charcode < 0xd800 || charcode >= 0xe000) {
      utf8.push(0xe0 | (charcode >> 12), 0x80 | ((charcode >> 6) & 0x3f), 0x80 | (charcode & 0x3f));
    }
    else {
      i++;
      charcode = 0x10000 + (((charcode & 0x3ff) << 10) | (str.charCodeAt(i) & 0x3ff));
      utf8.push(0xf0 | (charcode >> 18), 0x80 | ((charcode >> 12) & 0x3f), 0x80 | (charcode & 0x3f));
    }
  }
  return new Uint8Array(utf8);
}

// RFC 1321 pure TypeScript MD5 implementation
export function md5(data: Uint8Array): Uint8Array {
  function cmn(q: number, a: number, b: number, x: number, s: number, t: number) {
    a = (((a + q) | 0) + ((x + t) | 0)) | 0;
    return (((a << s) | (a >>> (32 - s))) + b) | 0;
  }
  function ff(a: number, b: number, c: number, d: number, x: number, s: number, t: number) {
    return cmn((b & c) | (~b & d), a, b, x, s, t);
  }
  function gg(a: number, b: number, c: number, d: number, x: number, s: number, t: number) {
    return cmn((b & d) | (c & ~d), a, b, x, s, t);
  }
  function hh(a: number, b: number, c: number, d: number, x: number, s: number, t: number) {
    return cmn(b ^ c ^ d, a, b, x, s, t);
  }
  function ii(a: number, b: number, c: number, d: number, x: number, s: number, t: number) {
    return cmn(c ^ (b | ~d), a, b, x, s, t);
  }

  const n = data.length;
  const wordCount = (((n + 8) >>> 6) + 1) << 4;
  const words = new Int32Array(wordCount);

  for (let i = 0; i < n; i++) {
    words[i >> 2] |= (data[i] & 0xff) << ((i % 4) << 3);
  }
  words[n >> 2] |= 0x80 << ((n % 4) << 3);
  words[wordCount - 2] = (n * 8) | 0;
  words[wordCount - 1] = Math.floor((n * 8) / 0x100000000);

  let a = 1732584193;
  let b = -271733879;
  let c = -1732584194;
  let d = 271733878;

  for (let i = 0; i < wordCount; i += 16) {
    const olda = a;
    const oldb = b;
    const oldc = c;
    const oldd = d;

    a = ff(a, b, c, d, words[i + 0], 7, -680876936);
    d = ff(d, a, b, c, words[i + 1], 12, -389564586);
    c = ff(c, d, a, b, words[i + 2], 17, 606105819);
    b = ff(b, c, d, a, words[i + 3], 22, -1044525330);
    a = ff(a, b, c, d, words[i + 4], 7, -176418897);
    d = ff(d, a, b, c, words[i + 5], 12, 1200080426);
    c = ff(c, d, a, b, words[i + 6], 17, -1473231341);
    b = ff(b, c, d, a, words[i + 7], 22, -45705983);
    a = ff(a, b, c, d, words[i + 8], 7, 1770035416);
    d = ff(d, a, b, c, words[i + 9], 12, -1958414417);
    c = ff(c, d, a, b, words[i + 10], 17, -42063);
    b = ff(b, c, d, a, words[i + 11], 22, -1990404162);
    a = ff(a, b, c, d, words[i + 12], 7, 1804603682);
    d = ff(d, a, b, c, words[i + 13], 12, -40341101);
    c = ff(c, d, a, b, words[i + 14], 17, -1502002290);
    b = ff(b, c, d, a, words[i + 15], 22, 1236535329);

    a = gg(a, b, c, d, words[i + 1], 5, -165796510);
    d = gg(d, a, b, c, words[i + 6], 9, -1069501632);
    c = gg(c, d, a, b, words[i + 11], 14, 643717713);
    b = gg(b, c, d, a, words[i + 0], 20, -373897302);
    a = gg(a, b, c, d, words[i + 5], 5, -701558691);
    d = gg(d, a, b, c, words[i + 10], 9, 38016083);
    c = gg(c, d, a, b, words[i + 15], 14, -660478335);
    b = gg(b, c, d, a, words[i + 4], 20, -405537848);
    a = gg(a, b, c, d, words[i + 9], 5, 568446438);
    d = gg(d, a, b, c, words[i + 14], 9, -1019803690);
    c = gg(c, d, a, b, words[i + 3], 14, -187363961);
    b = gg(b, c, d, a, words[i + 8], 20, 1163531501);
    a = gg(a, b, c, d, words[i + 13], 5, -1444681467);
    d = gg(d, a, b, c, words[i + 2], 9, -51403784);
    c = gg(c, d, a, b, words[i + 7], 14, 1735328473);
    b = gg(b, c, d, a, words[i + 12], 20, -1926607734);

    a = hh(a, b, c, d, words[i + 5], 4, -378558);
    d = hh(d, a, b, c, words[i + 8], 11, -2022574463);
    c = hh(c, d, a, b, words[i + 11], 16, 1839030562);
    b = hh(b, c, d, a, words[i + 14], 23, -35309556);
    a = hh(a, b, c, d, words[i + 1], 4, -1530992060);
    d = hh(d, a, b, c, words[i + 4], 11, 1272893353);
    c = hh(c, d, a, b, words[i + 7], 16, -155497632);
    b = hh(b, c, d, a, words[i + 10], 23, -1094730640);
    a = hh(a, b, c, d, words[i + 13], 4, 681279174);
    d = hh(d, a, b, c, words[i + 0], 11, -358537222);
    c = hh(c, d, a, b, words[i + 3], 16, -722521979);
    b = hh(b, c, d, a, words[i + 6], 23, 76029189);
    a = hh(a, b, c, d, words[i + 9], 4, -640364487);
    d = hh(d, a, b, c, words[i + 12], 11, -421815835);
    c = hh(c, d, a, b, words[i + 15], 16, 530742520);
    b = hh(b, c, d, a, words[i + 2], 23, -995338651);

    a = ii(a, b, c, d, words[i + 0], 6, -198630844);
    d = ii(d, a, b, c, words[i + 7], 10, 1126891415);
    c = ii(c, d, a, b, words[i + 14], 15, -1416354905);
    b = ii(b, c, d, a, words[i + 5], 21, -57434055);
    a = ii(a, b, c, d, words[i + 12], 6, 1700485571);
    d = ii(d, a, b, c, words[i + 3], 10, -1894986606);
    c = ii(c, d, a, b, words[i + 10], 15, -1051523);
    b = ii(b, c, d, a, words[i + 1], 21, -2054922799);
    a = ii(a, b, c, d, words[i + 8], 6, 1873313359);
    d = ii(d, a, b, c, words[i + 15], 10, -30611744);
    c = ii(c, d, a, b, words[i + 6], 15, -1560198380);
    b = ii(b, c, d, a, words[i + 13], 21, 1309151649);
    a = ii(a, b, c, d, words[i + 4], 6, -145523070);
    d = ii(d, a, b, c, words[i + 11], 10, -1120210379);
    c = ii(c, d, a, b, words[i + 2], 15, 718787259);
    b = ii(b, c, d, a, words[i + 9], 21, -343485551);

    a = (a + olda) | 0;
    b = (b + oldb) | 0;
    c = (c + oldc) | 0;
    d = (d + oldd) | 0;
  }

  const out = new Uint8Array(16);
  const outWords = [a, b, c, d];
  for (let i = 0; i < 4; i++) {
    const w = outWords[i];
    out[i * 4] = w & 0xff;
    out[i * 4 + 1] = (w >>> 8) & 0xff;
    out[i * 4 + 2] = (w >>> 16) & 0xff;
    out[i * 4 + 3] = (w >>> 24) & 0xff;
  }
  return out;
}

export async function sha512(data: Uint8Array): Promise<Uint8Array> {
  const gCrypto = typeof globalThis !== 'undefined'
    ? (globalThis as unknown as { crypto?: { subtle?: { digest?: (alg: string, d: Uint8Array) => Promise<ArrayBuffer> } } }).crypto
    : undefined;

  if (gCrypto?.subtle?.digest) {
    const hash = await gCrypto.subtle.digest('SHA-512', data);
    return new Uint8Array(hash);
  }
  throw new Error('WebCrypto subtle.digest is required for SHA-512');
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const gCrypto = typeof globalThis !== 'undefined'
    ? (globalThis as unknown as { crypto?: { subtle?: { digest?: (alg: string, d: Uint8Array) => Promise<ArrayBuffer> } } }).crypto
    : undefined;

  if (gCrypto?.subtle?.digest) {
    const hash = await gCrypto.subtle.digest('SHA-256', data);
    return new Uint8Array(hash);
  }
  throw new Error('WebCrypto subtle.digest is required for SHA-256');
}

export async function getPublicKeyFromSeed(seed: Uint8Array): Promise<Uint8Array> {
  if (seed.length !== 32) {
    throw new Error(`Seed must be 32 bytes, got ${seed.length}`);
  }

  const hash = await sha512(seed);
  const s = new Uint8Array(32);
  s.set(hash.subarray(0, 32));
  s[0] &= 248;
  s[31] &= 127;
  s[31] |= 64;

  let scalar = 0n;
  for (let i = 31; i >= 0; i--) {
    scalar = (scalar << 8n) | BigInt(s[i]);
  }

  return Point.base().multiply(scalar).encode();
}

function writeUint32BE(value: number): Uint8Array {
  const bytes = new Uint8Array(4);
  bytes[0] = (value >>> 24) & 0xff;
  bytes[1] = (value >>> 16) & 0xff;
  bytes[2] = (value >>> 8) & 0xff;
  bytes[3] = value & 0xff;
  return bytes;
}

function concatUint8Arrays(arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((acc, curr) => acc + curr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

function writeSshString(data: Uint8Array | string): Uint8Array {
  const bytes = typeof data === 'string' ? encodeUtf8(data) : data;
  return concatUint8Arrays([writeUint32BE(bytes.length), bytes]);
}

export function buildOpenSshPublicBlob(pubKey: Uint8Array): Uint8Array {
  return concatUint8Arrays([
    writeSshString('ssh-ed25519'),
    writeSshString(pubKey),
  ]);
}

export function encodeOpenSshPublicKey(pubKey: Uint8Array, comment: string = ''): string {
  const blob = buildOpenSshPublicBlob(pubKey);
  const b64 = bytesToBase64(blob);
  const trimmedComment = comment.trim();
  return trimmedComment ? `ssh-ed25519 ${b64} ${trimmedComment}` : `ssh-ed25519 ${b64}`;
}

export function encodeOpenSshPrivateKey(
  seed: Uint8Array,
  pubKey: Uint8Array,
  comment: string = '',
): string {
  const pubBlob = buildOpenSshPublicBlob(pubKey);

  // Random 32-bit check integer
  const checkintBytes = new Uint8Array(4);
  const gCrypto = typeof globalThis !== 'undefined'
    ? (globalThis as unknown as { crypto?: { getRandomValues?: (arr: Uint8Array) => void } }).crypto
    : undefined;

  if (gCrypto?.getRandomValues) {
    gCrypto.getRandomValues(checkintBytes);
  }
  else {
    const r = Math.floor(Math.random() * 0xffffffff);
    checkintBytes.set(writeUint32BE(r));
  }

  // Expanded private key for OpenSSH: 32 bytes seed + 32 bytes pubKey
  const privKeyCombined = concatUint8Arrays([seed, pubKey]);

  let privBlock = concatUint8Arrays([
    checkintBytes,
    checkintBytes,
    writeSshString('ssh-ed25519'),
    writeSshString(pubKey),
    writeSshString(privKeyCombined),
    writeSshString(comment.trim()),
  ]);

  // OpenSSH cipher 'none' block size is 8 bytes
  const padLen = (8 - (privBlock.length % 8)) % 8 || 8;
  const padding = new Uint8Array(padLen);
  for (let i = 0; i < padLen; i++) {
    padding[i] = i + 1;
  }
  privBlock = concatUint8Arrays([privBlock, padding]);

  const body = concatUint8Arrays([
    encodeUtf8('openssh-key-v1\0'),
    writeSshString('none'),
    writeSshString('none'),
    writeSshString(''),
    writeUint32BE(1),
    writeSshString(pubBlob),
    writeSshString(privBlock),
  ]);

  const b64 = bytesToBase64(body);
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 70) {
    lines.push(b64.slice(i, i + 70));
  }

  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${lines.join('\n')}\n-----END OPENSSH PRIVATE KEY-----\n`;
}

export function encodePkcs8Pem(seed: Uint8Array): string {
  // PKCS#8 prefix for Ed25519 (RFC 8410):
  // SEQUENCE (46 bytes)
  //   INTEGER 0
  //   SEQUENCE (id-Ed25519: 1.3.101.112)
  //   OCTET STRING (CurvePrivateKey 32 bytes)
  const prefix = hexToBytes('302e020100300506032b657004220420');
  const der = concatUint8Arrays([prefix, seed]);
  const b64 = bytesToBase64(der);
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 64) {
    lines.push(b64.slice(i, i + 64));
  }
  return `-----BEGIN PRIVATE KEY-----\n${lines.join('\n')}\n-----END PRIVATE KEY-----\n`;
}

export function encodeSpkiPem(pubKey: Uint8Array): string {
  // SubjectPublicKeyInfo prefix for Ed25519 (RFC 8410):
  // SEQUENCE (42 bytes)
  //   SEQUENCE (id-Ed25519: 1.3.101.112)
  //   BIT STRING (32 bytes public key)
  const prefix = hexToBytes('302a300506032b6570032100');
  const der = concatUint8Arrays([prefix, pubKey]);
  const b64 = bytesToBase64(der);
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 64) {
    lines.push(b64.slice(i, i + 64));
  }
  return `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----\n`;
}

export async function calculateSshFingerprintSha256(pubKey: Uint8Array): Promise<string> {
  const blob = buildOpenSshPublicBlob(pubKey);
  const hash = await sha256(blob);
  const b64 = bytesToBase64(hash).replace(/=+$/, '');
  return `SHA256:${b64}`;
}

export async function calculateSshFingerprintMd5(pubKey: Uint8Array): Promise<string> {
  const blob = buildOpenSshPublicBlob(pubKey);
  const hash = await md5(blob);
  const hex = bytesToHex(hash);
  const formatted = hex.match(/.{2}/g)?.join(':') ?? hex;
  return `MD5:${formatted}`;
}

export function generateRandomSeed(): Uint8Array {
  const seed = new Uint8Array(32);
  const gCrypto = typeof globalThis !== 'undefined'
    ? (globalThis as unknown as { crypto?: { getRandomValues?: (arr: Uint8Array) => void } }).crypto
    : undefined;

  if (gCrypto?.getRandomValues) {
    gCrypto.getRandomValues(seed);
  }
  else {
    for (let i = 0; i < 32; i++) {
      seed[i] = Math.floor(Math.random() * 256);
    }
  }
  return seed;
}

export async function generateEd25519KeyPair(options: GenerateEd25519Options = {}): Promise<Ed25519KeyPairResult> {
  let seedBytes: Uint8Array;
  if (!options.seed) {
    seedBytes = generateRandomSeed();
  }
  else if (typeof options.seed === 'string') {
    const clean = options.seed.trim();
    if (/^[0-9a-fA-F]{64}$/.test(clean)) {
      seedBytes = hexToBytes(clean);
    }
    else {
      // UTF-8 string, hash with SHA-256 to produce 32-byte deterministic seed
      seedBytes = await sha256(encodeUtf8(clean));
    }
  }
  else {
    seedBytes = options.seed;
  }

  const pubKey = await getPublicKeyFromSeed(seedBytes);
  const comment = options.comment ?? '';

  const [fingerprintSha256, fingerprintMd5] = await Promise.all([
    calculateSshFingerprintSha256(pubKey),
    calculateSshFingerprintMd5(pubKey),
  ]);

  return {
    publicKeyOpenSSH: encodeOpenSshPublicKey(pubKey, comment),
    privateKeyOpenSSH: encodeOpenSshPrivateKey(seedBytes, pubKey, comment),
    publicKeyPem: encodeSpkiPem(pubKey),
    privateKeyPem: encodePkcs8Pem(seedBytes),
    publicKeyHex: bytesToHex(pubKey),
    publicKeyBase64: bytesToBase64(pubKey),
    privateKeyHex: bytesToHex(seedBytes),
    privateKeyBase64: bytesToBase64(seedBytes),
    fingerprintSha256,
    fingerprintMd5,
  };
}
