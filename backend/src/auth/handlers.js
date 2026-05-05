// backend/src/auth/handlers.js
// All authentication route handlers

import {
  hashPassword, verifyPassword, signJWT, generateOpaqueToken,
  sha256, uuid, nowISO, futureISO,
} from '../utils/crypto.js';
import {
  Users, Sessions, RefreshTokens,
  EmailVerifications, PasswordResets, AuditLog,
} from '../db/users.js';
import { sendEmail, verificationEmail, passwordResetEmail } from '../utils/email.js';
import { ok, err, unauthorized, forbidden } from '../utils/response.js';
import { ROLES, hasRole } from '../middleware/auth.js';

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
export async function register(req, ctx) {
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
export async function login(req, ctx) {
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
export async function logout(req, ctx) {
  // ctx.user already attached by requireAuth middleware
  await Sessions.deleteById(ctx.db, ctx.user.sessionId);
  await RefreshTokens.revokeAllForUser(ctx.db, ctx.user.id);
  await AuditLog.insert(ctx.db, {
    userId: ctx.user.id, action: 'auth.logout', ipAddress: ip(req),
  });
  return ok({ message: 'Logged out' });
}

// ── POST /api/auth/refresh ────────────────────────────────────────────────────
export async function refresh(req, ctx) {
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
export async function verifyEmail(req, ctx) {
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
export async function forgotPassword(req, ctx) {
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
export async function resetPassword(req, ctx) {
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
export async function me(req, ctx) {
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
export async function listUsers(req, ctx) {
  const users = await Users.listAll(ctx.db);
  return ok({ users });
}

export async function updateUserRole(req, ctx, userId) {
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
export async function getAuditLog(req, ctx) {
  const url    = new URL(req.url);
  const limit  = Math.min(+url.searchParams.get('limit')  || 100, 500);
  const offset = +url.searchParams.get('offset') || 0;
  const userId = url.searchParams.get('userId')  || null;
  const logs   = await AuditLog.list(ctx.db, { limit, offset, userId });
  return ok({ logs });
}
