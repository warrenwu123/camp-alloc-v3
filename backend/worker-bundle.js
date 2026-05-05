// ═══════════════════════════════════════════════════════════════════════
// CampAlloc — Cloudflare Worker (BUNDLED SINGLE FILE)
// Paste this entire file into the Cloudflare Worker editor and click Deploy.
//
// Required D1 binding:  DB  → camp-alloc-db
// Required secrets (Worker Settings → Variables):
//   JWT_SECRET      — 32+ random chars for signing access tokens
//   APP_PASSWORD    — (legacy, can be any string)
//   EMAIL_FROM      — sender email address
//   SENDGRID_KEY    — SendGrid API key (optional, logs if missing)
//   FRONTEND_URL    — your GitHub Pages URL
// ═══════════════════════════════════════════════════════════════════════
// backend/src/utils/response.js
// Shared response helpers and CORS configuration

const CORS_HEADERS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-Refresh-Token',
  'Access-Control-Expose-Headers':'X-New-Access-Token',
};

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS, ...extraHeaders },
  });
}

function ok(data = {}, extraHeaders = {}) {
  return json({ ok: true, ...data }, 200, extraHeaders);
}

function err(message, status = 400, detail = {}) {
  return json({ ok: false, error: message, ...detail }, status);
}

function unauthorized(msg = 'Unauthorised') { return err(msg, 401); }
function forbidden(msg = 'Forbidden')       { return err(msg, 403); }
function notFound(msg = 'Not found')        { return err(msg, 404); }

function preflight() {
  return new Response(null, { status: 204, headers: CORS_HEADERS });
}
// backend/src/utils/crypto.js
// All cryptographic helpers using Web Crypto API (available in CF Workers)

const enc = new TextEncoder();
const dec = new TextDecoder();

// ── UUID ──────────────────────────────────────────────────────────────────────
function uuid() {
  return crypto.randomUUID();
}

// ── Password hashing (PBKDF2-SHA256) ─────────────────────────────────────────
// Format stored: pbkdf2$<iterations>$<salt_b64>$<hash_b64>

const PBKDF2_ITERATIONS = 200_000;

async function hashPassword(password) {
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

async function verifyPassword(password, stored) {
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
async function sha256(text) {
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

async function signJWT(payload, secret, expiresInSeconds = 3600) {
  const header  = { alg: 'HS256', typ: 'JWT' };
  const now     = Math.floor(Date.now() / 1000);
  const claims  = { ...payload, iat: now, exp: now + expiresInSeconds };
  const h       = b64urlEncode(enc.encode(JSON.stringify(header)));
  const p       = b64urlEncode(enc.encode(JSON.stringify(claims)));
  const key     = await hmacKey(secret);
  const sig     = await crypto.subtle.sign('HMAC', key, enc.encode(`${h}.${p}`));
  return `${h}.${p}.${b64urlEncode(sig)}`;
}

async function verifyJWT(token, secret) {
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
function generateOpaqueToken(bytes = 32) {
  const arr = crypto.getRandomValues(new Uint8Array(bytes));
  return Array.from(arr).map(b => b.toString(16).padStart(2,'0')).join('');
}

function nowISO() { return new Date().toISOString(); }
function futureISO(ms) { return new Date(Date.now() + ms).toISOString(); }
// backend/src/utils/email.js
// Email sending via SendGrid HTTP API

async function sendEmail(env, { to, subject, html }) {
  if (!env.SENDGRID_KEY) {
    // Dev mode — just log
    console.log(`[EMAIL DEV] To: ${to} | Subject: ${subject}`);
    return;
  }
  const res = await fetch('https://api.sendgrid.com/v3/mail/send', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.SENDGRID_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      personalizations: [{ to: [{ email: to }] }],
      from: { email: env.EMAIL_FROM || 'noreply@campalloc.com', name: 'CampAlloc' },
      subject,
      content: [{ type: 'text/html', value: html }],
    }),
  });
  if (!res.ok) {
    const body = await res.text();
    console.error('SendGrid error:', res.status, body);
    throw new Error('Failed to send email');
  }
}

function verificationEmail(name, verifyUrl) {
  return {
    subject: 'Verify your CampAlloc email',
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:auto">
        <h2 style="color:#f0a500">CampAlloc — Email Verification</h2>
        <p>Hi ${name},</p>
        <p>Click the button below to verify your email address. This link expires in <strong>24 hours</strong>.</p>
        <a href="${verifyUrl}" style="display:inline-block;background:#f0a500;color:#000;padding:12px 28px;border-radius:6px;text-decoration:none;font-weight:bold;margin:16px 0">Verify Email</a>
        <p style="color:#888;font-size:12px">If you didn't register, you can ignore this email.</p>
      </div>`,
  };
}

function passwordResetEmail(name, resetUrl) {
  return {
    subject: 'Reset your CampAlloc password',
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:auto">
        <h2 style="color:#f0a500">CampAlloc — Password Reset</h2>
        <p>Hi ${name},</p>
        <p>Click the button below to reset your password. This link expires in <strong>1 hour</strong>.</p>
        <a href="${resetUrl}" style="display:inline-block;background:#f0a500;color:#000;padding:12px 28px;border-radius:6px;text-decoration:none;font-weight:bold;margin:16px 0">Reset Password</a>
        <p style="color:#888;font-size:12px">If you didn't request this, you can ignore this email.</p>
      </div>`,
  };
}
// backend/src/db/users.js
// D1 query helpers for user + auth tables

const Users = {
  async findByEmail(db, email) {
    const { results } = await db.prepare(
      'SELECT * FROM users WHERE email = ?1 LIMIT 1'
    ).bind(email.toLowerCase()).all();
    return results[0] || null;
  },

  async findById(db, id) {
    const { results } = await db.prepare(
      'SELECT * FROM users WHERE id = ?1 LIMIT 1'
    ).bind(id).all();
    return results[0] || null;
  },

  async create(db, { id, email, passwordHash, name, role = 'viewer', createdAt }) {
    await db.prepare(`
      INSERT INTO users (id, email, password_hash, name, role, email_verified, is_active, created_at, updated_at)
      VALUES (?1, ?2, ?3, ?4, ?5, 0, 1, ?6, ?6)
    `).bind(id, email.toLowerCase(), passwordHash, name, role, createdAt).run();
  },

  async updateEmailVerified(db, userId) {
    await db.prepare(
      "UPDATE users SET email_verified = 1, updated_at = ?1 WHERE id = ?2"
    ).bind(new Date().toISOString(), userId).run();
  },

  async updatePassword(db, userId, passwordHash) {
    await db.prepare(
      "UPDATE users SET password_hash = ?1, updated_at = ?2 WHERE id = ?3"
    ).bind(passwordHash, new Date().toISOString(), userId).run();
  },

  async updateRole(db, userId, role) {
    await db.prepare(
      "UPDATE users SET role = ?1, updated_at = ?2 WHERE id = ?3"
    ).bind(role, new Date().toISOString(), userId).run();
  },

  async listAll(db) {
    const { results } = await db.prepare(
      'SELECT id, email, name, role, email_verified, is_active, created_at FROM users ORDER BY created_at DESC'
    ).all();
    return results;
  },

  async countAll(db) {
    const { results } = await db.prepare('SELECT COUNT(*) as n FROM users').all();
    return results[0]?.n || 0;
  },
};

const Sessions = {
  async create(db, { id, userId, createdAt, expiresAt, ipAddress, userAgent }) {
    await db.prepare(`
      INSERT INTO sessions (id, user_id, created_at, expires_at, ip_address, user_agent)
      VALUES (?1, ?2, ?3, ?4, ?5, ?6)
    `).bind(id, userId, createdAt, expiresAt, ipAddress || '', userAgent || '').run();
  },

  async findById(db, id) {
    const { results } = await db.prepare('SELECT * FROM sessions WHERE id = ?1').bind(id).all();
    return results[0] || null;
  },

  async deleteById(db, id) {
    await db.prepare('DELETE FROM sessions WHERE id = ?1').bind(id).run();
  },

  async deleteByUserId(db, userId) {
    await db.prepare('DELETE FROM sessions WHERE user_id = ?1').bind(userId).run();
  },
};

const RefreshTokens = {
  async create(db, { id, tokenHash, userId, sessionId, createdAt, expiresAt }) {
    await db.prepare(`
      INSERT INTO refresh_tokens (id, token_hash, user_id, session_id, created_at, expires_at, revoked)
      VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0)
    `).bind(id, tokenHash, userId, sessionId, createdAt, expiresAt).run();
  },

  async findByHash(db, tokenHash) {
    const { results } = await db.prepare(
      'SELECT * FROM refresh_tokens WHERE token_hash = ?1 AND revoked = 0 LIMIT 1'
    ).bind(tokenHash).all();
    return results[0] || null;
  },

  async revoke(db, id) {
    await db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE id = ?1').bind(id).run();
  },

  async revokeAllForUser(db, userId) {
    await db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?1').bind(userId).run();
  },
};

const EmailVerifications = {
  async create(db, { id, userId, tokenHash, createdAt, expiresAt }) {
    // Invalidate previous unused tokens for this user
    await db.prepare(
      'UPDATE email_verifications SET used = 1 WHERE user_id = ?1 AND used = 0'
    ).bind(userId).run();
    await db.prepare(`
      INSERT INTO email_verifications (id, user_id, token_hash, created_at, expires_at, used)
      VALUES (?1, ?2, ?3, ?4, ?5, 0)
    `).bind(id, userId, tokenHash, createdAt, expiresAt).run();
  },

  async findByHash(db, tokenHash) {
    const { results } = await db.prepare(
      'SELECT * FROM email_verifications WHERE token_hash = ?1 AND used = 0 LIMIT 1'
    ).bind(tokenHash).all();
    return results[0] || null;
  },

  async markUsed(db, id) {
    await db.prepare('UPDATE email_verifications SET used = 1 WHERE id = ?1').bind(id).run();
  },
};

const PasswordResets = {
  async create(db, { id, userId, tokenHash, createdAt, expiresAt }) {
    await db.prepare(
      'UPDATE password_resets SET used = 1 WHERE user_id = ?1 AND used = 0'
    ).bind(userId).run();
    await db.prepare(`
      INSERT INTO password_resets (id, user_id, token_hash, created_at, expires_at, used)
      VALUES (?1, ?2, ?3, ?4, ?5, 0)
    `).bind(id, userId, tokenHash, createdAt, expiresAt).run();
  },

  async findByHash(db, tokenHash) {
    const { results } = await db.prepare(
      'SELECT * FROM password_resets WHERE token_hash = ?1 AND used = 0 LIMIT 1'
    ).bind(tokenHash).all();
    return results[0] || null;
  },

  async markUsed(db, id) {
    await db.prepare('UPDATE password_resets SET used = 1 WHERE id = ?1').bind(id).run();
  },
};

const AuditLog = {
  async insert(db, { userId, action, targetType = '', targetId = '', detail = {}, ipAddress = '' }) {
    await db.prepare(`
      INSERT INTO audit_log (user_id, action, target_type, target_id, detail, ip_address, created_at)
      VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
    `).bind(
      userId || null, action, targetType, targetId,
      JSON.stringify(detail), ipAddress, new Date().toISOString()
    ).run();
  },

  async list(db, { limit = 100, offset = 0, userId } = {}) {
    let q = 'SELECT a.*, u.email as user_email FROM audit_log a LEFT JOIN users u ON a.user_id = u.id';
    const binds = [];
    if (userId) { q += ' WHERE a.user_id = ?1'; binds.push(userId); }
    q += ` ORDER BY a.created_at DESC LIMIT ${limit} OFFSET ${offset}`;
    const stmt = binds.length ? db.prepare(q).bind(...binds) : db.prepare(q);
    const { results } = await stmt.all();
    return results;
  },
};
// backend/src/db/camp.js
// D1 query helpers for rooms and bookings

const Rooms = {
  async getAll(db) {
    const { results } = await db.prepare('SELECT * FROM rooms ORDER BY id').all();
    return results.map(r => ({ id: r.id, num: r.num, clean: !!r.clean, repair: !!r.repair }));
  },
  async update(db, { id, clean, repair }) {
    await db.prepare('UPDATE rooms SET clean=?1, repair=?2 WHERE id=?3')
      .bind(clean ? 1 : 0, repair ? 1 : 0, id).run();
  },
};

const Bookings = {
  async getAll(db) {
    const { results: bRows } = await db.prepare('SELECT * FROM bookings ORDER BY checkin').all();
    const { results: sRows } = await db.prepare(
      'SELECT * FROM booking_segments ORDER BY booking_id, checkin'
    ).all();
    const segMap = {};
    sRows.forEach(s => {
      if (!segMap[s.booking_id]) segMap[s.booking_id] = [];
      segMap[s.booking_id].push({ checkin: s.checkin, checkout: s.checkout, isOn: !!s.is_on });
    });
    return bRows.map(b => ({
      id: b.id, roomId: b.room_id, name: b.name,
      company: b.company || '', role: b.role || '',
      checkin: b.checkin, checkout: b.checkout,
      clean: !!b.clean, repair: !!b.repair,
      notes: b.notes || '', color: b.color,
      rosterPattern: b.roster_pattern || '', offweek: b.offweek,
      segments: segMap[b.id] || [],
    }));
  },

  async upsert(db, b) {
    await db.prepare(`
      INSERT INTO bookings (id,room_id,name,company,role,checkin,checkout,clean,repair,notes,color,roster_pattern,offweek)
      VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
      ON CONFLICT(id) DO UPDATE SET
        room_id=excluded.room_id, name=excluded.name, company=excluded.company,
        role=excluded.role, checkin=excluded.checkin, checkout=excluded.checkout,
        clean=excluded.clean, repair=excluded.repair, notes=excluded.notes,
        color=excluded.color, roster_pattern=excluded.roster_pattern, offweek=excluded.offweek
    `).bind(b.id, b.roomId, b.name, b.company||'', b.role||'', b.checkin, b.checkout,
            b.clean?1:0, b.repair?1:0, b.notes||'', b.color||0,
            b.rosterPattern||'', b.offweek||'held').run();

    await db.prepare('DELETE FROM booking_segments WHERE booking_id=?1').bind(b.id).run();
    for (const s of (b.segments || [])) {
      await db.prepare(
        'INSERT INTO booking_segments (booking_id,checkin,checkout,is_on) VALUES (?1,?2,?3,?4)'
      ).bind(b.id, s.checkin, s.checkout, s.isOn ? 1 : 0).run();
    }
  },

  async delete(db, id) {
    await db.prepare('DELETE FROM booking_segments WHERE booking_id=?1').bind(id).run();
    await db.prepare('DELETE FROM bookings WHERE id=?1').bind(id).run();
  },

  async filterByDate(db, dateField, date) {
    const all = await this.getAll(db);
    return all.filter(b =>
      b[dateField] === date ||
      (b.segments && b.segments.some(s => s[dateField] === date && (dateField !== 'checkin' || s.isOn)))
    );
  },
};
// backend/src/middleware/auth.js
// JWT verification middleware + role-based access control


const ROLES = { ADMIN: 'admin', EDITOR: 'editor', VIEWER: 'viewer' };

// Role hierarchy: admin > editor > viewer
const ROLE_LEVEL = { viewer: 1, editor: 2, admin: 3 };

function hasRole(userRole, required) {
  return (ROLE_LEVEL[userRole] || 0) >= (ROLE_LEVEL[required] || 0);
}

// Extract Bearer token from Authorization header
function extractToken(req) {
  const auth = req.headers.get('Authorization') || '';
  if (auth.startsWith('Bearer ')) return auth.slice(7).trim();
  return null;
}

// requireAuth — verifies JWT, attaches ctx.user
// requireRole — additionally checks minimum role level
function requireAuth(env) {
  return async (req, ctx) => {
    const token = extractToken(req);
    if (!token) return unauthorized('Missing access token');

    const claims = await verifyJWT(token, env.JWT_SECRET);
    if (!claims) return unauthorized('Invalid or expired access token');

    // Verify session still exists in DB (allows server-side logout)
    const session = await Sessions.findById(ctx.db, claims.sid);
    if (!session) return unauthorized('Session expired — please log in again');

    // Attach user to context
    const user = await Users.findById(ctx.db, claims.sub);
    if (!user || !user.is_active) return unauthorized('Account not found or deactivated');

    ctx.user = { id: user.id, email: user.email, name: user.name, role: user.role, sessionId: claims.sid };
    return null; // null = pass through
  };
}

function requireRole(env, minRole) {
  const authMiddleware = requireAuth(env);
  return async (req, ctx) => {
    const authResult = await authMiddleware(req, ctx);
    if (authResult) return authResult; // auth failed

    if (!hasRole(ctx.user.role, minRole)) {
      return forbidden(`This action requires ${minRole} role or higher`);
    }
    return null;
  };
}

// Helper: run a middleware and return its response if it failed
async function runMiddleware(mw, req, ctx) {
  return mw(req, ctx);
}
// backend/src/auth/handlers.js
// All authentication route handlers


const ACCESS_TOKEN_TTL  =  15 * 60;          // 15 minutes
const REFRESH_TOKEN_TTL =  7 * 24 * 3600;    // 7 days
const VERIFY_TTL        = 24 * 3600 * 1000;  // 24 hours (ms)
const RESET_TTL         =  1 * 3600 * 1000;  // 1 hour (ms)

function ip(req) { return req.headers.get('CF-Connecting-IP') || ''; }
function ua(req) { return req.headers.get('User-Agent') || ''; }

async function issueTokenPair(env, db, user, req) {
  const sessionId = uuid();
  const now       = nowISO();
  const sessExp   = futureISO(REFRESH_TOKEN_TTL * 1000);

  await Sessions.create(db, {
    id: sessionId, userId: user.id,
    createdAt: now, expiresAt: sessExp,
    ipAddress: ip(req), userAgent: ua(req),
  });

  const accessToken = await signJWT(
    { sub: user.id, email: user.email, role: user.role, sid: sessionId },
    env.JWT_SECRET, ACCESS_TOKEN_TTL
  );

  const rawRefresh  = generateOpaqueToken(40);
  const refreshHash = await sha256(rawRefresh);

  await RefreshTokens.create(db, {
    id: uuid(), tokenHash: refreshHash,
    userId: user.id, sessionId,
    createdAt: now, expiresAt: sessExp,
  });

  return { accessToken, refreshToken: rawRefresh, sessionId };
}

// ── POST /api/auth/register ───────────────────────────────────────────────────
async function register(req, ctx) {
  const { email, password, name } = await req.json().catch(() => ({}));

  if (!email || !password || !name)
    return err('email, password and name are required');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return err('Invalid email address');
  if (password.length < 8)
    return err('Password must be at least 8 characters');

  const existing = await Users.findByEmail(ctx.db, email);
  if (existing) return err('An account with this email already exists', 409);

  // First user ever becomes admin automatically
  const userCount = await Users.countAll(ctx.db);
  const role = userCount === 0 ? ROLES.ADMIN : ROLES.VIEWER;

  const id           = uuid();
  const passwordHash = await hashPassword(password);
  const createdAt    = nowISO();

  await Users.create(ctx.db, { id, email, passwordHash, name, role, createdAt });

  // Send verification email
  const rawToken  = generateOpaqueToken(32);
  const tokenHash = await sha256(rawToken);
  await EmailVerifications.create(ctx.db, {
    id: uuid(), userId: id, tokenHash,
    createdAt, expiresAt: futureISO(VERIFY_TTL),
  });

  const verifyUrl = `${ctx.env.FRONTEND_URL}/verify-email?token=${rawToken}`;
  try {
    await sendEmail(ctx.env, { to: email, ...verificationEmail(name, verifyUrl) });
  } catch (e) { console.error('Email send failed:', e); }

  await AuditLog.insert(ctx.db, {
    userId: id, action: 'auth.register',
    detail: { email, role }, ipAddress: ip(req),
  });

  return ok({ message: 'Account created. Please check your email to verify.', role }, 201);
}

// ── POST /api/auth/login ──────────────────────────────────────────────────────
async function login(req, ctx) {
  const { email, password } = await req.json().catch(() => ({}));
  if (!email || !password) return err('email and password are required');

  const user = await Users.findByEmail(ctx.db, email);
  if (!user) return unauthorized('Invalid email or password');

  const valid = await verifyPassword(password, user.password_hash);
  if (!valid) {
    await AuditLog.insert(ctx.db, { userId: user.id, action: 'auth.login.fail', ipAddress: ip(req) });
    return unauthorized('Invalid email or password');
  }

  if (!user.is_active) return unauthorized('Account is deactivated');

  const { accessToken, refreshToken } = await issueTokenPair(ctx.env, ctx.db, user, req);

  await AuditLog.insert(ctx.db, {
    userId: user.id, action: 'auth.login',
    detail: { email }, ipAddress: ip(req),
  });

  return ok({
    accessToken, refreshToken,
    user: { id: user.id, email: user.email, name: user.name, role: user.role, emailVerified: !!user.email_verified },
  });
}

// ── POST /api/auth/logout ─────────────────────────────────────────────────────
async function logout(req, ctx) {
  // ctx.user already attached by requireAuth middleware
  await Sessions.deleteById(ctx.db, ctx.user.sessionId);
  await RefreshTokens.revokeAllForUser(ctx.db, ctx.user.id);
  await AuditLog.insert(ctx.db, {
    userId: ctx.user.id, action: 'auth.logout', ipAddress: ip(req),
  });
  return ok({ message: 'Logged out' });
}

// ── POST /api/auth/refresh ────────────────────────────────────────────────────
async function refresh(req, ctx) {
  const body = await req.json().catch(() => ({}));
  const raw  = body.refreshToken || req.headers.get('X-Refresh-Token');
  if (!raw) return err('refreshToken required');

  const tokenHash = await sha256(raw);
  const stored    = await RefreshTokens.findByHash(ctx.db, tokenHash);

  if (!stored || new Date(stored.expires_at) < new Date())
    return unauthorized('Refresh token invalid or expired');

  // Rotate: revoke old, issue new pair
  await RefreshTokens.revoke(ctx.db, stored.id);
  await Sessions.deleteById(ctx.db, stored.session_id);

  const user = await Users.findById(ctx.db, stored.user_id);
  if (!user || !user.is_active) return unauthorized('Account not found');

  const { accessToken, refreshToken } = await issueTokenPair(ctx.env, ctx.db, user, req);

  await AuditLog.insert(ctx.db, {
    userId: user.id, action: 'auth.token.refresh', ipAddress: ip(req),
  });

  return ok({ accessToken, refreshToken });
}

// ── POST /api/auth/verify-email ───────────────────────────────────────────────
async function verifyEmail(req, ctx) {
  const { token } = await req.json().catch(() => ({}));
  if (!token) return err('token required');

  const tokenHash = await sha256(token);
  const record    = await EmailVerifications.findByHash(ctx.db, tokenHash);

  if (!record || new Date(record.expires_at) < new Date())
    return err('Verification link is invalid or has expired', 400);

  await EmailVerifications.markUsed(ctx.db, record.id);
  await Users.updateEmailVerified(ctx.db, record.user_id);

  await AuditLog.insert(ctx.db, {
    userId: record.user_id, action: 'auth.email.verified',
  });

  return ok({ message: 'Email verified successfully' });
}

// ── POST /api/auth/forgot-password ───────────────────────────────────────────
async function forgotPassword(req, ctx) {
  const { email } = await req.json().catch(() => ({}));
  if (!email) return err('email required');

  const user = await Users.findByEmail(ctx.db, email);
  // Always return success to prevent email enumeration
  if (!user) return ok({ message: 'If that email exists, a reset link has been sent.' });

  const rawToken  = generateOpaqueToken(32);
  const tokenHash = await sha256(rawToken);
  const now       = nowISO();

  await PasswordResets.create(ctx.db, {
    id: uuid(), userId: user.id, tokenHash,
    createdAt: now, expiresAt: futureISO(RESET_TTL),
  });

  const resetUrl = `${ctx.env.FRONTEND_URL}/reset-password?token=${rawToken}`;
  try {
    await sendEmail(ctx.env, { to: email, ...passwordResetEmail(user.name, resetUrl) });
  } catch (e) { console.error('Email send failed:', e); }

  await AuditLog.insert(ctx.db, {
    userId: user.id, action: 'auth.password.reset_requested', ipAddress: ip(req),
  });

  return ok({ message: 'If that email exists, a reset link has been sent.' });
}

// ── POST /api/auth/reset-password ─────────────────────────────────────────────
async function resetPassword(req, ctx) {
  const { token, password } = await req.json().catch(() => ({}));
  if (!token || !password) return err('token and password required');
  if (password.length < 8) return err('Password must be at least 8 characters');

  const tokenHash = await sha256(token);
  const record    = await PasswordResets.findByHash(ctx.db, tokenHash);

  if (!record || new Date(record.expires_at) < new Date())
    return err('Reset link is invalid or has expired', 400);

  const passwordHash = await hashPassword(password);
  await Users.updatePassword(ctx.db, record.user_id, passwordHash);
  await PasswordResets.markUsed(ctx.db, record.id);

  // Invalidate all existing sessions
  await Sessions.deleteByUserId(ctx.db, record.user_id);
  await RefreshTokens.revokeAllForUser(ctx.db, record.user_id);

  await AuditLog.insert(ctx.db, {
    userId: record.user_id, action: 'auth.password.reset',
  });

  return ok({ message: 'Password reset successfully. Please log in.' });
}

// ── GET /api/auth/me ───────────────────────────────────────────────────────────
async function me(req, ctx) {
  const user = await Users.findById(ctx.db, ctx.user.id);
  return ok({
    user: {
      id: user.id, email: user.email, name: user.name,
      role: user.role, emailVerified: !!user.email_verified,
      createdAt: user.created_at,
    },
  });
}

// ── GET  /api/admin/users ─────────────────────────────────────────────────────
// ── PATCH /api/admin/users/:id/role ───────────────────────────────────────────
async function listUsers(req, ctx) {
  const users = await Users.listAll(ctx.db);
  return ok({ users });
}

async function updateUserRole(req, ctx, userId) {
  if (ctx.user.id === userId) return err("You can't change your own role", 400);
  const { role } = await req.json().catch(() => ({}));
  if (!['admin','editor','viewer'].includes(role)) return err('Invalid role');

  const target = await Users.findById(ctx.db, userId);
  if (!target) return err('User not found', 404);

  await Users.updateRole(ctx.db, userId, role);
  await AuditLog.insert(ctx.db, {
    userId: ctx.user.id, action: 'admin.user.role_change',
    targetType: 'user', targetId: userId,
    detail: { from: target.role, to: role, targetEmail: target.email },
    ipAddress: ip(req),
  });

  return ok({ message: `Role updated to ${role}` });
}

// ── GET /api/admin/audit-log ──────────────────────────────────────────────────
async function getAuditLog(req, ctx) {
  const url    = new URL(req.url);
  const limit  = Math.min(+url.searchParams.get('limit')  || 100, 500);
  const offset = +url.searchParams.get('offset') || 0;
  const userId = url.searchParams.get('userId')  || null;
  const logs   = await AuditLog.list(ctx.db, { limit, offset, userId });
  return ok({ logs });
}
// backend/src/rooms/handlers.js

async function getRooms(req, ctx) {
  return ok({ rooms: await Rooms.getAll(ctx.db) });
}

async function updateRoom(req, ctx, roomId) {
  const { clean, repair } = await req.json().catch(() => ({}));
  if (clean === undefined || repair === undefined) return err('clean and repair required');
  await Rooms.update(ctx.db, { id: +roomId, clean, repair });
  await AuditLog.insert(ctx.db, {
    userId: ctx.user.id, action: 'room.update',
    targetType: 'room', targetId: String(roomId),
    detail: { clean, repair },
  });
  return ok();
}
// backend/src/bookings/handlers.js

async function getBookings(req, ctx) {
  return ok({ bookings: await Bookings.getAll(ctx.db) });
}

async function createBooking(req, ctx) {
  const b = await req.json().catch(() => ({}));
  if (!b.id || !b.roomId || !b.name || !b.checkin || !b.checkout)
    return err('Missing required fields: id, roomId, name, checkin, checkout');
  await Bookings.upsert(ctx.db, b);
  await AuditLog.insert(ctx.db, {
    userId: ctx.user.id, action: 'booking.create',
    targetType: 'booking', targetId: b.id,
    detail: { roomId: b.roomId, name: b.name, checkin: b.checkin, checkout: b.checkout },
  });
  return ok({ id: b.id }, 201);
}

async function updateBooking(req, ctx, bookingId) {
  const b = await req.json().catch(() => ({}));
  b.id = bookingId;
  await Bookings.upsert(ctx.db, b);
  await AuditLog.insert(ctx.db, {
    userId: ctx.user.id, action: 'booking.update',
    targetType: 'booking', targetId: bookingId,
    detail: { roomId: b.roomId, name: b.name },
  });
  return ok();
}

async function deleteBooking(req, ctx, bookingId) {
  await Bookings.delete(ctx.db, bookingId);
  await AuditLog.insert(ctx.db, {
    userId: ctx.user.id, action: 'booking.delete',
    targetType: 'booking', targetId: bookingId,
  });
  return ok();
}

async function getCheckins(req, ctx) {
  const url  = new URL(req.url);
  const date = url.searchParams.get('date') || new Date().toISOString().slice(0, 10);
  const list = await Bookings.filterByDate(ctx.db, 'checkin', date);
  return ok({ date, checkins: list });
}

async function getCheckouts(req, ctx) {
  const url  = new URL(req.url);
  const date = url.searchParams.get('date') || new Date().toISOString().slice(0, 10);
  const list = await Bookings.filterByDate(ctx.db, 'checkout', date);
  return ok({ date, checkouts: list });
}

async function importBookings(req, ctx) {
  const { bookings: bArr = [], rooms: rArr = [] } = await req.json().catch(() => ({}));
  for (const r of rArr) await Rooms.update(ctx.db, r);
  for (const b of bArr) await Bookings.upsert(ctx.db, b);
  await AuditLog.insert(ctx.db, {
    userId: ctx.user.id, action: 'booking.import',
    detail: { bookingsImported: bArr.length, roomsImported: rArr.length },
  });
  return ok({ bookingsImported: bArr.length, roomsImported: rArr.length });
}
// backend/src/index.js
// Main Cloudflare Worker entry point — thin router only
// All business logic lives in src/auth/, src/rooms/, src/bookings/



// Build a request context shared across handlers
function makeCtx(env, db) {
  return { env, db, user: null };
}

// Run middleware; return its error response or null
async function mw(middleware, req, ctx) {
  return middleware(req, ctx);
}

export default {
  async fetch(request, env) {
    const url    = new URL(request.url);
    const path   = url.pathname;
    const method = request.method;

    if (method === 'OPTIONS') return preflight();

    const db  = env.DB;
    const ctx = makeCtx(env, db);

    // ── Auth routes (public) ─────────────────────────────────────────────────
    if (path === '/api/auth/register'      && method === 'POST') return register(request, ctx);
    if (path === '/api/auth/login'         && method === 'POST') return login(request, ctx);
    if (path === '/api/auth/refresh'       && method === 'POST') return refresh(request, ctx);
    if (path === '/api/auth/verify-email'  && method === 'POST') return verifyEmail(request, ctx);
    if (path === '/api/auth/forgot-password' && method === 'POST') return forgotPassword(request, ctx);
    if (path === '/api/auth/reset-password'  && method === 'POST') return resetPassword(request, ctx);

    // ── Auth routes (protected) ──────────────────────────────────────────────
    if (path === '/api/auth/me'     && method === 'GET')  { const e = await mw(requireAuth(env), request, ctx); if (e) return e; return me(request, ctx); }
    if (path === '/api/auth/logout' && method === 'POST') { const e = await mw(requireAuth(env), request, ctx); if (e) return e; return logout(request, ctx); }

    // ── Admin routes (admin only) ─────────────────────────────────────────────
    if (path === '/api/admin/users' && method === 'GET') {
      const e = await mw(requireRole(env, ROLES.ADMIN), request, ctx); if (e) return e;
      return listUsers(request, ctx);
    }
    if (path === '/api/admin/audit-log' && method === 'GET') {
      const e = await mw(requireRole(env, ROLES.ADMIN), request, ctx); if (e) return e;
      return getAuditLog(request, ctx);
    }
    const roleMatch = path.match(/^\/api\/admin\/users\/([^/]+)\/role$/);
    if (roleMatch && method === 'PATCH') {
      const e = await mw(requireRole(env, ROLES.ADMIN), request, ctx); if (e) return e;
      return updateUserRole(request, ctx, roleMatch[1]);
    }

    // ── Rooms (read: viewer+, write: editor+) ────────────────────────────────
    if (path === '/api/rooms' && method === 'GET') {
      const e = await mw(requireAuth(env), request, ctx); if (e) return e;
      return getRooms(request, ctx);
    }
    const roomMatch = path.match(/^\/api\/rooms\/(\d+)$/);
    if (roomMatch && method === 'PUT') {
      const e = await mw(requireRole(env, ROLES.EDITOR), request, ctx); if (e) return e;
      return updateRoom(request, ctx, roomMatch[1]);
    }

    // ── Bookings (read: viewer+, write: editor+) ──────────────────────────────
    if (path === '/api/bookings' && method === 'GET') {
      const e = await mw(requireAuth(env), request, ctx); if (e) return e;
      return getBookings(request, ctx);
    }
    if (path === '/api/bookings' && method === 'POST') {
      const e = await mw(requireRole(env, ROLES.EDITOR), request, ctx); if (e) return e;
      return createBooking(request, ctx);
    }
    const bookMatch = path.match(/^\/api\/bookings\/([^/]+)$/);
    if (bookMatch && method === 'PUT') {
      const e = await mw(requireRole(env, ROLES.EDITOR), request, ctx); if (e) return e;
      return updateBooking(request, ctx, decodeURIComponent(bookMatch[1]));
    }
    if (bookMatch && method === 'DELETE') {
      const e = await mw(requireRole(env, ROLES.EDITOR), request, ctx); if (e) return e;
      return deleteBooking(request, ctx, decodeURIComponent(bookMatch[1]));
    }
    if (path === '/api/checkins'  && method === 'GET') {
      const e = await mw(requireAuth(env), request, ctx); if (e) return e;
      return getCheckins(request, ctx);
    }
    if (path === '/api/checkouts' && method === 'GET') {
      const e = await mw(requireAuth(env), request, ctx); if (e) return e;
      return getCheckouts(request, ctx);
    }
    if (path === '/api/import' && method === 'POST') {
      const e = await mw(requireRole(env, ROLES.EDITOR), request, ctx); if (e) return e;
      return importBookings(request, ctx);
    }

    return notFound();
  },
};

