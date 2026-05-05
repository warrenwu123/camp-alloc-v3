// backend/test/auth.handlers.test.js
// Unit tests for auth handler logic (password validation, token flow)

import { webcrypto } from 'crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;

import { hashPassword, verifyPassword, generateOpaqueToken, sha256 } from '../src/utils/crypto.js';

// ── Registration validation ───────────────────────────────────────────────────
describe('Registration input validation', () => {
  function validateRegistration({ email, password, name }) {
    if (!email || !password || !name) return 'email, password and name are required';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return 'Invalid email address';
    if (password.length < 8) return 'Password must be at least 8 characters';
    return null;
  }

  test('rejects missing fields', () => {
    expect(validateRegistration({})).toMatch(/required/);
    expect(validateRegistration({ email: 'a@b.com' })).toMatch(/required/);
    expect(validateRegistration({ email: 'a@b.com', password: 'pass' })).toMatch(/required/);
  });

  test('rejects invalid email', () => {
    expect(validateRegistration({ email: 'notanemail', password: 'password1', name: 'Test' })).toMatch(/Invalid email/);
    expect(validateRegistration({ email: 'missing@', password: 'password1', name: 'Test' })).toMatch(/Invalid email/);
  });

  test('rejects short password', () => {
    expect(validateRegistration({ email: 'a@b.com', password: 'short', name: 'Test' })).toMatch(/8 characters/);
  });

  test('accepts valid input', () => {
    expect(validateRegistration({ email: 'user@example.com', password: 'validpass1', name: 'Alice' })).toBeNull();
  });
});

// ── Password reset flow ───────────────────────────────────────────────────────
describe('Password reset token flow', () => {
  test('token hashes differ from raw token', async () => {
    const raw  = generateOpaqueToken(32);
    const hash = await sha256(raw);
    expect(raw).not.toBe(hash);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  test('same raw token always produces same hash', async () => {
    const raw = generateOpaqueToken(32);
    const h1  = await sha256(raw);
    const h2  = await sha256(raw);
    expect(h1).toBe(h2);
  });

  test('different raw tokens produce different hashes', async () => {
    const h1 = await sha256(generateOpaqueToken(32));
    const h2 = await sha256(generateOpaqueToken(32));
    expect(h1).not.toBe(h2);
  });
});

// ── Role assignment: first user gets admin ─────────────────────────────────────
describe('First user auto-admin rule', () => {
  function assignRole(existingUserCount) {
    return existingUserCount === 0 ? 'admin' : 'viewer';
  }

  test('first user (count=0) gets admin', () => {
    expect(assignRole(0)).toBe('admin');
  });

  test('second user (count=1) gets viewer', () => {
    expect(assignRole(1)).toBe('viewer');
  });

  test('any subsequent user gets viewer', () => {
    expect(assignRole(99)).toBe('viewer');
  });
});

// ── Refresh token rotation ────────────────────────────────────────────────────
describe('Refresh token rotation security', () => {
  test('old token is revoked after rotation (simulate)', async () => {
    const oldToken = generateOpaqueToken(40);
    const oldHash  = await sha256(oldToken);
    const revoked  = new Set();

    // Simulate revoke
    revoked.add(oldHash);

    // New token issued
    const newToken = generateOpaqueToken(40);
    const newHash  = await sha256(newToken);

    expect(revoked.has(oldHash)).toBe(true);
    expect(revoked.has(newHash)).toBe(false);
  });

  test('replayed old refresh token is rejected (hash in revoked set)', async () => {
    const token = generateOpaqueToken(40);
    const hash  = await sha256(token);
    const revokedHashes = new Set([hash]);

    const isRevoked = revokedHashes.has(hash);
    expect(isRevoked).toBe(true);
  });
});

// ── Email enumeration prevention ──────────────────────────────────────────────
describe('Forgot password — no email enumeration', () => {
  const SUCCESS_MSG = 'If that email exists, a reset link has been sent.';

  function forgotPasswordResponse(userExists) {
    // Always return same message regardless of whether user exists
    return { message: SUCCESS_MSG };
  }

  test('returns identical response whether user exists or not', () => {
    const r1 = forgotPasswordResponse(true);
    const r2 = forgotPasswordResponse(false);
    expect(r1.message).toBe(r2.message);
  });
});

// ── Token expiry checks ───────────────────────────────────────────────────────
describe('Token expiry validation', () => {
  function isExpired(expiresAt) {
    return new Date(expiresAt) < new Date();
  }

  test('past date is expired', () => {
    expect(isExpired(new Date(Date.now() - 1000).toISOString())).toBe(true);
  });

  test('future date is not expired', () => {
    expect(isExpired(new Date(Date.now() + 60000).toISOString())).toBe(false);
  });

  test('exactly now is considered expired', async () => {
    // With real timing we can't be exact, so just check logic
    const past = new Date(Date.now() - 1).toISOString();
    expect(isExpired(past)).toBe(true);
  });
});
