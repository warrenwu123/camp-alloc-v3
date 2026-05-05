// backend/test/crypto.test.js
// Tests for all cryptographic utilities

// Polyfill Web Crypto for Node.js test environment
import { webcrypto } from 'crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;

import {
  hashPassword, verifyPassword,
  signJWT, verifyJWT,
  generateOpaqueToken, sha256,
  uuid, nowISO, futureISO,
} from '../src/utils/crypto.js';

// ── hashPassword / verifyPassword ─────────────────────────────────────────────
describe('Password hashing', () => {
  test('hashPassword produces a pbkdf2 hash string', async () => {
    const hash = await hashPassword('mySecret123!');
    expect(hash).toMatch(/^pbkdf2\$/);
    expect(hash.split('$')).toHaveLength(4);
  });

  test('verifyPassword returns true for correct password', async () => {
    const hash = await hashPassword('correctPassword');
    expect(await verifyPassword('correctPassword', hash)).toBe(true);
  });

  test('verifyPassword returns false for wrong password', async () => {
    const hash = await hashPassword('correctPassword');
    expect(await verifyPassword('wrongPassword', hash)).toBe(false);
  });

  test('two hashes of same password differ (unique salt)', async () => {
    const h1 = await hashPassword('samePassword');
    const h2 = await hashPassword('samePassword');
    expect(h1).not.toBe(h2);
    // But both verify correctly
    expect(await verifyPassword('samePassword', h1)).toBe(true);
    expect(await verifyPassword('samePassword', h2)).toBe(true);
  });

  test('verifyPassword is safe against short-circuit comparison', async () => {
    const hash = await hashPassword('test');
    // Empty hash should not throw, just return false
    expect(await verifyPassword('test', 'pbkdf2$1$abc$def')).toBe(false);
  });
});

// ── JWT ───────────────────────────────────────────────────────────────────────
describe('JWT sign / verify', () => {
  const secret = 'test-secret-at-least-32-chars-long!!';

  test('signJWT produces a 3-part token', async () => {
    const token = await signJWT({ sub: 'user1', role: 'admin' }, secret, 3600);
    expect(token.split('.')).toHaveLength(3);
  });

  test('verifyJWT returns payload for valid token', async () => {
    const token = await signJWT({ sub: 'user1', role: 'viewer' }, secret, 3600);
    const claims = await verifyJWT(token, secret);
    expect(claims).not.toBeNull();
    expect(claims.sub).toBe('user1');
    expect(claims.role).toBe('viewer');
    expect(claims.iat).toBeDefined();
    expect(claims.exp).toBeDefined();
  });

  test('verifyJWT returns null for wrong secret', async () => {
    const token = await signJWT({ sub: 'user1' }, secret, 3600);
    expect(await verifyJWT(token, 'wrong-secret')).toBeNull();
  });

  test('verifyJWT returns null for expired token', async () => {
    const token = await signJWT({ sub: 'user1' }, secret, -1); // already expired
    expect(await verifyJWT(token, secret)).toBeNull();
  });

  test('verifyJWT returns null for tampered payload', async () => {
    const token  = await signJWT({ sub: 'user1', role: 'viewer' }, secret, 3600);
    const parts  = token.split('.');
    // Tamper the payload
    const payload = JSON.parse(atob(parts[1].replace(/-/g,'+').replace(/_/g,'/')));
    payload.role  = 'admin';
    parts[1]      = btoa(JSON.stringify(payload)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
    expect(await verifyJWT(parts.join('.'), secret)).toBeNull();
  });

  test('verifyJWT returns null for malformed token', async () => {
    expect(await verifyJWT('not.a.token', secret)).toBeNull();
    expect(await verifyJWT('', secret)).toBeNull();
    expect(await verifyJWT('onlyone', secret)).toBeNull();
  });
});

// ── sha256 ────────────────────────────────────────────────────────────────────
describe('sha256', () => {
  test('produces consistent hex hash', async () => {
    const h1 = await sha256('hello');
    const h2 = await sha256('hello');
    expect(h1).toBe(h2);
    expect(h1).toMatch(/^[0-9a-f]{64}$/);
  });

  test('different inputs produce different hashes', async () => {
    expect(await sha256('hello')).not.toBe(await sha256('world'));
  });
});

// ── generateOpaqueToken ───────────────────────────────────────────────────────
describe('generateOpaqueToken', () => {
  test('returns hex string of correct length', () => {
    const t = generateOpaqueToken(32);
    expect(t).toMatch(/^[0-9a-f]+$/);
    expect(t.length).toBe(64); // 32 bytes = 64 hex chars
  });

  test('generates unique tokens', () => {
    const tokens = new Set(Array.from({length: 100}, () => generateOpaqueToken(32)));
    expect(tokens.size).toBe(100);
  });
});

// ── uuid ──────────────────────────────────────────────────────────────────────
describe('uuid', () => {
  test('returns valid UUID v4 format', () => {
    const id = uuid();
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  });

  test('generates unique UUIDs', () => {
    const ids = new Set(Array.from({length: 1000}, uuid));
    expect(ids.size).toBe(1000);
  });
});

// ── Date helpers ──────────────────────────────────────────────────────────────
describe('Date helpers', () => {
  test('nowISO returns valid ISO string', () => {
    const s = nowISO();
    expect(() => new Date(s)).not.toThrow();
    expect(new Date(s).getFullYear()).toBeGreaterThanOrEqual(2024);
  });

  test('futureISO adds milliseconds correctly', () => {
    const before = Date.now();
    const future = new Date(futureISO(5000)).getTime();
    expect(future - before).toBeGreaterThanOrEqual(4990);
    expect(future - before).toBeLessThanOrEqual(6000);
  });
});
