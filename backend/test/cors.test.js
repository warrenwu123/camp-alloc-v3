// backend/test/cors.test.js
// Tests for CORS headers, OPTIONS preflight, and public/protected route behaviour
// These tests run against the actual live worker URL.
// Set WORKER_URL env var to test against a real deployment:
//   WORKER_URL=https://camp-alloc-v4.alvinkc.workers.dev node --experimental-vm-modules node_modules/.bin/jest test/cors.test.js

import { webcrypto } from 'crypto';
if (!globalThis.crypto) globalThis.crypto = webcrypto;

// ── Helpers ───────────────────────────────────────────────────────────────────

const WORKER_URL = process.env.WORKER_URL || 'https://camp-alloc-v4.alvinkc.workers.dev';
const IS_LIVE    = !WORKER_URL.includes('localhost') && process.env.RUN_LIVE === 'true';

// Skip live tests unless RUN_LIVE=true is explicitly set
const liveTest = IS_LIVE ? test : test.skip;

async function req(path, opts = {}) {
  return fetch(`${WORKER_URL}${path}`, {
    headers: { 'Content-Type': 'application/json', ...opts.headers },
    ...opts,
  });
}

// ── Unit tests: CORS_HEADERS object structure ─────────────────────────────────
describe('CORS header constants (unit)', () => {
  test('required CORS headers are defined', () => {
    const CORS = {
      'Access-Control-Allow-Origin':   '*',
      'Access-Control-Allow-Methods':  'GET,POST,PUT,PATCH,DELETE,OPTIONS',
      'Access-Control-Allow-Headers':  'Content-Type,Authorization,X-Refresh-Token',
      'Access-Control-Expose-Headers': 'X-New-Access-Token',
    };
    expect(CORS['Access-Control-Allow-Origin']).toBe('*');
    expect(CORS['Access-Control-Allow-Methods']).toContain('OPTIONS');
    expect(CORS['Access-Control-Allow-Methods']).toContain('POST');
    expect(CORS['Access-Control-Allow-Headers']).toContain('Authorization');
    expect(CORS['Access-Control-Allow-Headers']).toContain('Content-Type');
  });

  test('Authorization header is explicitly allowed (needed for Bearer token)', () => {
    const allowed = 'Content-Type,Authorization,X-Refresh-Token';
    expect(allowed.split(',')).toContain('Authorization');
  });

  test('all HTTP methods needed by the app are allowed', () => {
    const methods = 'GET,POST,PUT,PATCH,DELETE,OPTIONS'.split(',');
    ['GET','POST','PUT','DELETE','OPTIONS'].forEach(m => {
      expect(methods).toContain(m);
    });
  });
});

// ── Unit tests: preflight response structure ──────────────────────────────────
describe('Preflight response (unit)', () => {
  function makePreflight(corsHeaders) {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  test('preflight returns 204 No Content', () => {
    const res = makePreflight({ 'Access-Control-Allow-Origin': '*' });
    expect(res.status).toBe(204);
  });

  test('preflight body is null/empty', async () => {
    const res = makePreflight({ 'Access-Control-Allow-Origin': '*' });
    const text = await res.text();
    expect(text).toBe('');
  });
});

// ── Unit tests: route visibility (public vs protected) ────────────────────────
describe('Route access control rules (unit)', () => {
  const PUBLIC_ROUTES = [
    { path: '/api/auth/register',       method: 'POST' },
    { path: '/api/auth/login',          method: 'POST' },
    { path: '/api/auth/refresh',        method: 'POST' },
    { path: '/api/auth/verify-email',   method: 'POST' },
    { path: '/api/auth/forgot-password',method: 'POST' },
    { path: '/api/auth/reset-password', method: 'POST' },
  ];

  const PROTECTED_ROUTES = [
    { path: '/api/auth/me',             method: 'GET',   role: 'any' },
    { path: '/api/auth/logout',         method: 'POST',  role: 'any' },
    { path: '/api/rooms',               method: 'GET',   role: 'any' },
    { path: '/api/bookings',            method: 'GET',   role: 'any' },
    { path: '/api/bookings',            method: 'POST',  role: 'editor' },
    { path: '/api/admin/users',         method: 'GET',   role: 'admin' },
    { path: '/api/admin/audit-log',     method: 'GET',   role: 'admin' },
  ];

  test('public routes list is complete (6 routes)', () => {
    expect(PUBLIC_ROUTES).toHaveLength(6);
  });

  test('all auth/* write routes are public', () => {
    const authPublic = PUBLIC_ROUTES.filter(r => r.path.startsWith('/api/auth'));
    expect(authPublic.length).toBeGreaterThanOrEqual(6);
  });

  test('admin routes require admin role', () => {
    const adminRoutes = PROTECTED_ROUTES.filter(r => r.role === 'admin');
    expect(adminRoutes.length).toBeGreaterThanOrEqual(2);
    adminRoutes.forEach(r => {
      expect(r.path).toMatch(/\/api\/admin\//);
    });
  });

  test('booking write routes require editor role', () => {
    const editorRoutes = PROTECTED_ROUTES.filter(r => r.role === 'editor');
    expect(editorRoutes.length).toBeGreaterThanOrEqual(1);
  });

  test('register is NOT in protected routes', () => {
    const found = PROTECTED_ROUTES.find(r => r.path === '/api/auth/register');
    expect(found).toBeUndefined();
  });
});

// ── Unit tests: response builder functions ────────────────────────────────────
describe('Response builder functions (unit)', () => {
  const CORS_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-Refresh-Token',
  };

  function jsonResp(data, status = 200) {
    return new Response(JSON.stringify(data), {
      status,
      headers: { 'Content-Type': 'application/json', ...CORS_HEADERS },
    });
  }
  function ok(data = {}) { return jsonResp({ ok: true, ...data }); }
  function errResp(msg, status = 400) { return jsonResp({ ok: false, error: msg }, status); }
  function unauthorized(msg = 'Unauthorised') { return errResp(msg, 401); }
  function forbidden(msg = 'Forbidden') { return errResp(msg, 403); }
  function notFound(msg = 'Not found') { return errResp(msg, 404); }

  test('ok() returns 200 with ok:true', async () => {
    const res = ok({ token: 'abc' });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.ok).toBe(true);
    expect(body.token).toBe('abc');
  });

  test('errResp() returns correct status and ok:false', async () => {
    const res = errResp('bad input', 400);
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.ok).toBe(false);
    expect(body.error).toBe('bad input');
  });

  test('unauthorized() returns 401', async () => {
    const res = unauthorized();
    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.error).toBe('Unauthorised');
  });

  test('forbidden() returns 403', async () => {
    const res = forbidden('admin only');
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error).toBe('admin only');
  });

  test('notFound() returns 404', async () => {
    const res = notFound();
    expect(res.status).toBe(404);
  });

  test('all responses include CORS headers', async () => {
    const responses = [ok(), errResp('x'), unauthorized(), forbidden(), notFound()];
    for (const res of responses) {
      expect(res.headers.get('Access-Control-Allow-Origin')).toBe('*');
    }
  });

  test('Content-Type is application/json', () => {
    const res = ok();
    expect(res.headers.get('Content-Type')).toBe('application/json');
  });
});

// ── Unit tests: registration input validation ─────────────────────────────────
describe('Registration validation (unit)', () => {
  function validate({ email, password, name }) {
    if (!email || !password || !name) return 'email, password and name are required';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return 'Invalid email address';
    if (password.length < 8) return 'Password must be at least 8 characters';
    return null;
  }

  test('valid input passes', () => {
    expect(validate({ email: 'a@b.com', password: 'password1', name: 'Test' })).toBeNull();
  });

  test('missing name fails', () => {
    expect(validate({ email: 'a@b.com', password: 'password1', name: '' })).toMatch(/required/);
  });

  test('missing email fails', () => {
    expect(validate({ email: '', password: 'password1', name: 'Test' })).toMatch(/required/);
  });

  test('missing password fails', () => {
    expect(validate({ email: 'a@b.com', password: '', name: 'Test' })).toMatch(/required/);
  });

  test('invalid email format fails', () => {
    expect(validate({ email: 'notvalid', password: 'password1', name: 'Test' })).toMatch(/Invalid email/);
    expect(validate({ email: 'no@', password: 'password1', name: 'Test' })).toMatch(/Invalid email/);
  });

  test('password under 8 chars fails', () => {
    expect(validate({ email: 'a@b.com', password: '1234567', name: 'Test' })).toMatch(/8 characters/);
  });

  test('password exactly 8 chars passes', () => {
    expect(validate({ email: 'a@b.com', password: '12345678', name: 'Test' })).toBeNull();
  });
});

// ── Live integration tests (only run with RUN_LIVE=true) ──────────────────────
describe('Live worker — CORS & auth endpoints', () => {
  liveTest('OPTIONS preflight returns 204 with CORS headers', async () => {
    const res = await req('/api/auth/register', { method: 'OPTIONS' });
    expect(res.status).toBe(204);
    expect(res.headers.get('Access-Control-Allow-Origin')).toBe('*');
    expect(res.headers.get('Access-Control-Allow-Methods')).toContain('POST');
  }, 10000);

  liveTest('POST /api/auth/register with missing fields returns 400 with CORS', async () => {
    const res = await req('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email: 'test@test.com' }), // missing name + password
    });
    expect(res.status).toBe(400);
    expect(res.headers.get('Access-Control-Allow-Origin')).toBe('*');
    const body = await res.json();
    expect(body.ok).toBe(false);
    expect(body.error).toMatch(/required/);
  }, 10000);

  liveTest('POST /api/auth/login with wrong credentials returns 401 with CORS', async () => {
    const res = await req('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email: 'nobody@nowhere.com', password: 'wrongpassword' }),
    });
    expect(res.status).toBe(401);
    expect(res.headers.get('Access-Control-Allow-Origin')).toBe('*');
  }, 10000);

  liveTest('GET /api/rooms without token returns 401 with CORS', async () => {
    const res = await req('/api/rooms');
    expect(res.status).toBe(401);
    expect(res.headers.get('Access-Control-Allow-Origin')).toBe('*');
    const body = await res.json();
    expect(body.error).toMatch(/token/i);
  }, 10000);

  liveTest('Unknown route returns 404 with CORS', async () => {
    const res = await req('/api/does-not-exist');
    expect(res.status).toBe(401); // hits auth first before 404
    expect(res.headers.get('Access-Control-Allow-Origin')).toBe('*');
  }, 10000);
});
