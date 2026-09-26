import { describe, expect, it } from 'vitest';
import {
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  calculateSshFingerprintMd5,
  calculateSshFingerprintSha256,
  encodeOpenSshPrivateKey,
  encodeOpenSshPublicKey,
  encodePkcs8Pem,
  encodeSpkiPem,
  generateEd25519KeyPair,
  getPublicKeyFromSeed,
  hexToBytes,
} from './ed25519-key-pair-generator.service';

describe('ed25519-key-pair-generator service', () => {
  // Test vector 1 from RFC 8032 Section 7.1
  const seed1Hex = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
  const expectedPub1Hex = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';

  // Test vector 2 from RFC 8032 Section 7.1
  const seed2Hex = '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb';
  const expectedPub2Hex = '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c';

  it('correctly derives public key matching RFC 8032 test vector 1', async () => {
    const seed1 = hexToBytes(seed1Hex);
    const pub1 = await getPublicKeyFromSeed(seed1);
    expect(bytesToHex(pub1)).toBe(expectedPub1Hex);
  });

  it('correctly derives public key matching RFC 8032 test vector 2', async () => {
    const seed2 = hexToBytes(seed2Hex);
    const pub2 = await getPublicKeyFromSeed(seed2);
    expect(bytesToHex(pub2)).toBe(expectedPub2Hex);
  });

  it('encodes OpenSSH public key with and without comment', () => {
    const pub = hexToBytes(expectedPub1Hex);
    const sshPubNoComment = encodeOpenSshPublicKey(pub);
    expect(sshPubNoComment.startsWith('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA')).toBe(true);

    const sshPubWithComment = encodeOpenSshPublicKey(pub, 'test-user@host');
    expect(sshPubWithComment.endsWith(' test-user@host')).toBe(true);
    expect(sshPubWithComment.startsWith('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA')).toBe(true);
  });

  it('encodes OpenSSH private key with valid header and footer', () => {
    const seed = hexToBytes(seed1Hex);
    const pub = hexToBytes(expectedPub1Hex);
    const privPem = encodeOpenSshPrivateKey(seed, pub, 'my-key');

    expect(privPem.startsWith('-----BEGIN OPENSSH PRIVATE KEY-----')).toBe(true);
    expect(privPem.trimEnd().endsWith('-----END OPENSSH PRIVATE KEY-----')).toBe(true);
  });

  it('encodes PKCS#8 private key and SPKI public key in PEM format', () => {
    const seed = hexToBytes(seed1Hex);
    const pub = hexToBytes(expectedPub1Hex);

    const pkcs8 = encodePkcs8Pem(seed);
    expect(pkcs8.startsWith('-----BEGIN PRIVATE KEY-----')).toBe(true);
    expect(pkcs8.trimEnd().endsWith('-----END PRIVATE KEY-----')).toBe(true);

    const spki = encodeSpkiPem(pub);
    expect(spki.startsWith('-----BEGIN PUBLIC KEY-----')).toBe(true);
    expect(spki.trimEnd().endsWith('-----END PUBLIC KEY-----')).toBe(true);
  });

  it('computes OpenSSH fingerprints in SHA256 and MD5 format', async () => {
    const pub = hexToBytes(expectedPub1Hex);
    const fpSha256 = await calculateSshFingerprintSha256(pub);
    const fpMd5 = await calculateSshFingerprintMd5(pub);

    expect(fpSha256).toMatch(/^SHA256:[A-Za-z0-9+/]+$/);
    expect(fpMd5).toMatch(/^MD5:([0-9a-f]{2}:){15}[0-9a-f]{2}$/);
  });

  it('converts between bytes, hex, and base64 correctly', () => {
    const bytes = new Uint8Array([0, 1, 2, 254, 255]);
    const hex = bytesToHex(bytes);
    expect(hex).toBe('000102feff');
    expect(hexToBytes(hex)).toEqual(bytes);

    const b64 = bytesToBase64(bytes);
    expect(base64ToBytes(b64)).toEqual(bytes);
  });

  it('generates a complete key pair result with random seed', async () => {
    const result = await generateEd25519KeyPair({ comment: 'user@example.com' });

    expect(result.publicKeyOpenSSH).toContain('ssh-ed25519 ');
    expect(result.publicKeyOpenSSH).toContain(' user@example.com');
    expect(result.privateKeyOpenSSH).toContain('-----BEGIN OPENSSH PRIVATE KEY-----');
    expect(result.publicKeyPem).toContain('-----BEGIN PUBLIC KEY-----');
    expect(result.privateKeyPem).toContain('-----BEGIN PRIVATE KEY-----');
    expect(result.publicKeyHex).toHaveLength(64);
    expect(result.privateKeyHex).toHaveLength(64);
    expect(result.publicKeyBase64).toBeTruthy();
    expect(result.privateKeyBase64).toBeTruthy();
    expect(result.fingerprintSha256).toMatch(/^SHA256:/);
    expect(result.fingerprintMd5).toMatch(/^MD5:/);
  });

  it('generates deterministic key pair when given a seed hex', async () => {
    const result1 = await generateEd25519KeyPair({ seed: seed1Hex, comment: 'custom' });
    const result2 = await generateEd25519KeyPair({ seed: seed1Hex, comment: 'custom' });

    expect(result1.publicKeyHex).toBe(expectedPub1Hex);
    expect(result2.publicKeyHex).toBe(expectedPub1Hex);
    expect(result1.privateKeyHex).toBe(seed1Hex);
    expect(result1.publicKeyOpenSSH).toBe(result2.publicKeyOpenSSH);
    expect(result1.publicKeyPem).toBe(result2.publicKeyPem);
    expect(result1.privateKeyPem).toBe(result2.privateKeyPem);
  });
});
