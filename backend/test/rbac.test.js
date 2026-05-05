// backend/test/rbac.test.js
// Tests for role-based access control logic

import { webcrypto } from 'crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;

import { hasRole, ROLES } from '../src/middleware/auth.js';

describe('RBAC — hasRole()', () => {
  test('admin has all roles', () => {
    expect(hasRole('admin', ROLES.ADMIN)).toBe(true);
    expect(hasRole('admin', ROLES.EDITOR)).toBe(true);
    expect(hasRole('admin', ROLES.VIEWER)).toBe(true);
  });

  test('editor has editor and viewer, not admin', () => {
    expect(hasRole('editor', ROLES.ADMIN)).toBe(false);
    expect(hasRole('editor', ROLES.EDITOR)).toBe(true);
    expect(hasRole('editor', ROLES.VIEWER)).toBe(true);
  });

  test('viewer has only viewer', () => {
    expect(hasRole('viewer', ROLES.ADMIN)).toBe(false);
    expect(hasRole('viewer', ROLES.EDITOR)).toBe(false);
    expect(hasRole('viewer', ROLES.VIEWER)).toBe(true);
  });

  test('unknown role has no permissions', () => {
    expect(hasRole('superadmin', ROLES.VIEWER)).toBe(false);
    expect(hasRole('', ROLES.VIEWER)).toBe(false);
    expect(hasRole(undefined, ROLES.VIEWER)).toBe(false);
  });
});

// ── requireAuth middleware tests (with mock env + ctx) ────────────────────────
import { requireAuth, requireRole } from '../src/middleware/auth.js';
import { signJWT } from '../src/utils/crypto.js';

const JWT_SECRET = 'test-secret-for-rbac-at-least-32-chars!';

function mockEnv() { return { JWT_SECRET }; }

function mockRequest(token) {
  return {
    headers: new Map([['Authorization', token ? `Bearer ${token}` : '']]),
  };
}
mockRequest.prototype = { headers: { get: function(k) { return this._h.get(k) || null; } } };

function makeReq(token) {
  return { headers: { get: (k) => k === 'Authorization' ? (token ? `Bearer ${token}` : '') : null } };
}

function makeCtx(overrides = {}) {
  return {
    db: {
      prepare: (q) => ({
        bind: (...args) => ({ all: async () => ({ results: overrides.sessionResult || [] }), run: async () => {} }),
        all:  async () => ({ results: overrides.userResult || [] }),
      }),
    },
    user: null,
    env: mockEnv(),
    ...overrides,
  };
}

describe('requireAuth middleware', () => {
  test('returns 401 with no token', async () => {
    const mw  = requireAuth(mockEnv());
    const res = await mw(makeReq(null), makeCtx());
    expect(res).not.toBeNull();
    const body = await res.json();
    expect(body.error).toMatch(/Missing/i);
    expect(res.status).toBe(401);
  });

  test('returns 401 for invalid token', async () => {
    const mw  = requireAuth(mockEnv());
    const res = await mw(makeReq('not.a.valid.jwt'), makeCtx());
    expect(res.status).toBe(401);
  });

  test('returns 401 for expired token', async () => {
    const expired = await signJWT({ sub: 'u1', sid: 's1', role: 'viewer' }, JWT_SECRET, -1);
    const mw  = requireAuth(mockEnv());
    const res = await mw(makeReq(expired), makeCtx());
    expect(res.status).toBe(401);
  });

  test('returns 401 when session not found in DB', async () => {
    const token = await signJWT({ sub: 'u1', sid: 's1', role: 'viewer' }, JWT_SECRET, 3600);
    const mw = requireAuth(mockEnv());
    // sessionResult is empty → session not found
    const res = await mw(makeReq(token), makeCtx({ sessionResult: [], userResult: [] }));
    expect(res.status).toBe(401);
  });

  test('passes through and sets ctx.user when valid', async () => {
    const token = await signJWT({ sub: 'u1', sid: 's1', role: 'editor', email: 'a@b.com' }, JWT_SECRET, 3600);
    const ctx = {
      db: {
        prepare: (q) => ({
          bind: (...args) => ({
            all: async () => ({
              results: q.includes('sessions')
                ? [{ id: 's1', user_id: 'u1', expires_at: new Date(Date.now()+9999999).toISOString() }]
                : [{ id: 'u1', email: 'a@b.com', name: 'Alice', role: 'editor', is_active: 1 }]
            }),
            run: async () => {},
          }),
        }),
      },
      user: null,
      env: mockEnv(),
    };
    const mw  = requireAuth(mockEnv());
    const res = await mw(makeReq(token), ctx);
    expect(res).toBeNull();          // null = passed through
    expect(ctx.user).not.toBeNull();
    expect(ctx.user.role).toBe('editor');
    expect(ctx.user.id).toBe('u1');
  });
});

describe('requireRole middleware', () => {
  test('rejects viewer trying editor route', async () => {
    const token = await signJWT({ sub: 'u1', sid: 's1', role: 'viewer', email: 'v@b.com' }, JWT_SECRET, 3600);
    const ctx = {
      db: {
        prepare: (q) => ({
          bind: () => ({
            all: async () => ({
              results: q.includes('sessions')
                ? [{ id: 's1', user_id: 'u1', expires_at: new Date(Date.now()+9999999).toISOString() }]
                : [{ id: 'u1', email: 'v@b.com', name: 'Viewer', role: 'viewer', is_active: 1 }]
            }),
            run: async () => {},
          }),
        }),
      },
      user: null,
      env: mockEnv(),
    };
    const mw  = requireRole(mockEnv(), ROLES.EDITOR);
    const res = await mw(makeReq(token), ctx);
    expect(res.status).toBe(403);
  });
});
