// backend/src/utils/crypto.js
// All cryptographic helpers using Web Crypto API (available in CF Workers)

const enc = new TextEncoder();
const dec = new TextDecoder();

// ── UUID ──────────────────────────────────────────────────────────────────────
export function uuid() {
  return crypto.randomUUID();
}

// ── Password hashing (PBKDF2-SHA256) ─────────────────────────────────────────
// Format stored: pbkdf2$<iterations>$<salt_b64>$<hash_b64>

const PBKDF2_ITERATIONS = 100_000;  // CF Workers max is 100k

export async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PBKDF2_ITERATIONS },
    keyMaterial, 256
  );
  const saltB64 = btoa(String.fromCharCode(...salt));
  const hashB64 = btoa(String.fromCharCode(...new Uint8Array(bits)));
  return `pbkdf2$${PBKDF2_ITERATIONS}$${saltB64}$${hashB64}`;
}

export async function verifyPassword(password, stored) {
  const [, iters, saltB64, hashB64] = stored.split('$');
  const salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));
  const expected = Uint8Array.from(atob(hashB64), c => c.charCodeAt(0));
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: +iters },
    keyMaterial, 256
  );
  const actual = new Uint8Array(bits);
  // Constant-time comparison
  if (actual.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < actual.length; i++) diff |= actual[i] ^ expected[i];
  return diff === 0;
}

// ── HMAC-SHA256 (used for opaque token hashing) ───────────────────────────────
export async function sha256(text) {
  const buf  = await crypto.subtle.digest('SHA-256', enc.encode(text));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
}

// ── JWT (HS256) ───────────────────────────────────────────────────────────────
function b64urlEncode(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}
function b64urlDecode(s) {
  s = s.replace(/-/g,'+').replace(/_/g,'/');
  while (s.length % 4) s += '=';
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}

async function hmacKey(secret) {
  return crypto.subtle.importKey(
    'raw', enc.encode(secret), { name:'HMAC', hash:'SHA-256' }, false, ['sign','verify']
  );
}

export async function signJWT(payload, secret, expiresInSeconds = 3600) {
  const header  = { alg: 'HS256', typ: 'JWT' };
  const now     = Math.floor(Date.now() / 1000);
  const claims  = { ...payload, iat: now, exp: now + expiresInSeconds };
  const h       = b64urlEncode(enc.encode(JSON.stringify(header)));
  const p       = b64urlEncode(enc.encode(JSON.stringify(claims)));
  const key     = await hmacKey(secret);
  const sig     = await crypto.subtle.sign('HMAC', key, enc.encode(`${h}.${p}`));
  return `${h}.${p}.${b64urlEncode(sig)}`;
}

export async function verifyJWT(token, secret) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [h, p, s] = parts;
    const key   = await hmacKey(secret);
    const valid = await crypto.subtle.verify('HMAC', key, b64urlDecode(s), enc.encode(`${h}.${p}`));
    if (!valid) return null;
    const claims = JSON.parse(dec.decode(b64urlDecode(p)));
    if (Date.now() / 1000 > claims.exp) return null;
    return claims;
  } catch { return null; }
}

// ── Opaque secure token (for refresh / email / reset) ─────────────────────────
export function generateOpaqueToken(bytes = 32) {
  const arr = crypto.getRandomValues(new Uint8Array(bytes));
  return Array.from(arr).map(b => b.toString(16).padStart(2,'0')).join('');
}

export function nowISO() { return new Date().toISOString(); }
export function futureISO(ms) { return new Date(Date.now() + ms).toISOString(); }
