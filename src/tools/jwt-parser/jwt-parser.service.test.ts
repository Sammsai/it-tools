import { describe, expect, it } from 'vitest';
import {
  base64UrlDecode,
  base64UrlEncode,
  decodeJwt,
  formatTimestamp,
  generateJwtFromParts,
  parseJwt,
  splitJwt,
  verifyJwtSignature,
} from './jwt-parser.service';

const SAMPLE_HS256 = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

describe('jwt-parser.service', () => {
  it('should encode and decode base64url correctly', () => {
    const original = 'Hello World! Special chars: +/=';
    const encoded = base64UrlEncode(original);
    expect(encoded).not.toContain('+');
    expect(encoded).not.toContain('/');
    expect(encoded).not.toContain('=');

    const decoded = base64UrlDecode(encoded);
    expect(decoded).toBe(original);
  });

  it('should split JWT into 3 parts', () => {
    const res = splitJwt(SAMPLE_HS256);
    expect(res.isValidFormat).toBe(true);
    expect(res.headerPart).toBe('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');
    expect(res.payloadPart).toBe('eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ');
    expect(res.signaturePart).toBe('SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c');
  });

  it('should return invalid for malformed JWT strings', () => {
    expect(splitJwt('invalid.token').isValidFormat).toBe(true);
    expect(splitJwt('single-part').isValidFormat).toBe(false);
    expect(splitJwt('a.b.c.d').isValidFormat).toBe(false);
  });

  it('should parse header and payload correctly', () => {
    const parsed = parseJwt(SAMPLE_HS256);
    expect(parsed).not.toBeNull();
    expect(parsed?.alg).toBe('HS256');
    expect(parsed?.typ).toBe('JWT');
    expect(parsed?.header).toEqual({ alg: 'HS256', typ: 'JWT' });
    expect(parsed?.payload.sub).toBe('1234567890');
    expect(parsed?.payload.name).toBe('John Doe');
  });

  it('should compute and verify valid HS256 signature', () => {
    const verifyResult = verifyJwtSignature({
      jwt: SAMPLE_HS256,
      secret: 'your-256-bit-secret',
    });
    expect(verifyResult.status).toBe('valid');
    expect(verifyResult.message).toBe('Signature Verified');
  });

  it('should detect invalid HS256 signature with wrong secret', () => {
    const verifyResult = verifyJwtSignature({
      jwt: SAMPLE_HS256,
      secret: 'wrong-secret',
    });
    expect(verifyResult.status).toBe('invalid');
    expect(verifyResult.message).toBe('Invalid Signature');
  });

  it('should generate valid JWT from header and payload JSON', () => {
    const header = JSON.stringify({ alg: 'HS256', typ: 'JWT' });
    const payload = JSON.stringify({ sub: '1234567890', name: 'John Doe', iat: 1516239022 });

    const jwt = generateJwtFromParts({
      headerJson: header,
      payloadJson: payload,
      secret: 'your-256-bit-secret',
    });

    expect(jwt).toBe(SAMPLE_HS256);
  });

  it('should support unsigned token generation (alg: "none")', () => {
    const header = JSON.stringify({ alg: 'none', typ: 'JWT' });
    const payload = JSON.stringify({ sub: 'admin' });

    const jwt = generateJwtFromParts({
      headerJson: header,
      payloadJson: payload,
    });

    expect(jwt.endsWith('.')).toBe(true);
    const verification = verifyJwtSignature({ jwt, secret: '' });
    expect(verification.status).toBe('unsigned');
  });

  it('should format timestamp with relative and UTC string', () => {
    const ts = formatTimestamp(1516239022);
    expect(ts).not.toBeNull();
    expect(ts?.formatted).toBe('2018-01-18 01:30:22 UTC');
    expect(ts?.isPast).toBe(true);
    expect(ts?.relative).toContain('ago');
  });

  it('should support legacy decodeJwt function', () => {
    const res = decodeJwt({ jwt: SAMPLE_HS256 });
    expect(res.header.length).toBeGreaterThan(0);
    expect(res.payload.length).toBeGreaterThan(0);
    expect(res.header.find(c => c.claim === 'alg')?.value).toBe('HS256');
    expect(res.payload.find(c => c.claim === 'name')?.value).toBe('John Doe');
  });
});
