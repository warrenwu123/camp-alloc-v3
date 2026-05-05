// backend/src/middleware/auth.js
// JWT verification middleware + role-based access control

import { verifyJWT } from '../utils/crypto.js';
import { Sessions, Users } from '../db/users.js';
import { unauthorized, forbidden } from '../utils/response.js';

export const ROLES = { ADMIN: 'admin', EDITOR: 'editor', VIEWER: 'viewer' };

// Role hierarchy: admin > editor > viewer
const ROLE_LEVEL = { viewer: 1, editor: 2, admin: 3 };

export function hasRole(userRole, required) {
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
export function requireAuth(env) {
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

export function requireRole(env, minRole) {
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
export async function runMiddleware(mw, req, ctx) {
  return mw(req, ctx);
}
