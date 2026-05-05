// backend/src/index.js
// Main Cloudflare Worker entry point — thin router only
// All business logic lives in src/auth/, src/rooms/, src/bookings/

import { preflight, notFound } from './utils/response.js';
import { requireAuth, requireRole, ROLES } from './middleware/auth.js';

import * as AuthHandlers    from './auth/handlers.js';
import * as RoomHandlers    from './rooms/handlers.js';
import * as BookingHandlers from './bookings/handlers.js';

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
    if (path === '/api/auth/register'      && method === 'POST') return AuthHandlers.register(request, ctx);
    if (path === '/api/auth/login'         && method === 'POST') return AuthHandlers.login(request, ctx);
    if (path === '/api/auth/refresh'       && method === 'POST') return AuthHandlers.refresh(request, ctx);
    if (path === '/api/auth/verify-email'  && method === 'POST') return AuthHandlers.verifyEmail(request, ctx);
    if (path === '/api/auth/forgot-password' && method === 'POST') return AuthHandlers.forgotPassword(request, ctx);
    if (path === '/api/auth/reset-password'  && method === 'POST') return AuthHandlers.resetPassword(request, ctx);

    // ── Auth routes (protected) ──────────────────────────────────────────────
    if (path === '/api/auth/me'     && method === 'GET')  { const e = await mw(requireAuth(env), request, ctx); if (e) return e; return AuthHandlers.me(request, ctx); }
    if (path === '/api/auth/logout' && method === 'POST') { const e = await mw(requireAuth(env), request, ctx); if (e) return e; return AuthHandlers.logout(request, ctx); }

    // ── Admin routes (admin only) ─────────────────────────────────────────────
    if (path === '/api/admin/users' && method === 'GET') {
      const e = await mw(requireRole(env, ROLES.ADMIN), request, ctx); if (e) return e;
      return AuthHandlers.listUsers(request, ctx);
    }
    if (path === '/api/admin/audit-log' && method === 'GET') {
      const e = await mw(requireRole(env, ROLES.ADMIN), request, ctx); if (e) return e;
      return AuthHandlers.getAuditLog(request, ctx);
    }
    const roleMatch = path.match(/^\/api\/admin\/users\/([^/]+)\/role$/);
    if (roleMatch && method === 'PATCH') {
      const e = await mw(requireRole(env, ROLES.ADMIN), request, ctx); if (e) return e;
      return AuthHandlers.updateUserRole(request, ctx, roleMatch[1]);
    }

    // ── Rooms (read: viewer+, write: editor+) ────────────────────────────────
    if (path === '/api/rooms' && method === 'GET') {
      const e = await mw(requireAuth(env), request, ctx); if (e) return e;
      return RoomHandlers.getRooms(request, ctx);
    }
    const roomMatch = path.match(/^\/api\/rooms\/(\d+)$/);
    if (roomMatch && method === 'PUT') {
      const e = await mw(requireRole(env, ROLES.EDITOR), request, ctx); if (e) return e;
      return RoomHandlers.updateRoom(request, ctx, roomMatch[1]);
    }

    // ── Bookings (read: viewer+, write: editor+) ──────────────────────────────
    if (path === '/api/bookings' && method === 'GET') {
      const e = await mw(requireAuth(env), request, ctx); if (e) return e;
      return BookingHandlers.getBookings(request, ctx);
    }
    if (path === '/api/bookings' && method === 'POST') {
      const e = await mw(requireRole(env, ROLES.EDITOR), request, ctx); if (e) return e;
      return BookingHandlers.createBooking(request, ctx);
    }
    const bookMatch = path.match(/^\/api\/bookings\/([^/]+)$/);
    if (bookMatch && method === 'PUT') {
      const e = await mw(requireRole(env, ROLES.EDITOR), request, ctx); if (e) return e;
      return BookingHandlers.updateBooking(request, ctx, decodeURIComponent(bookMatch[1]));
    }
    if (bookMatch && method === 'DELETE') {
      const e = await mw(requireRole(env, ROLES.EDITOR), request, ctx); if (e) return e;
      return BookingHandlers.deleteBooking(request, ctx, decodeURIComponent(bookMatch[1]));
    }
    if (path === '/api/checkins'  && method === 'GET') {
      const e = await mw(requireAuth(env), request, ctx); if (e) return e;
      return BookingHandlers.getCheckins(request, ctx);
    }
    if (path === '/api/checkouts' && method === 'GET') {
      const e = await mw(requireAuth(env), request, ctx); if (e) return e;
      return BookingHandlers.getCheckouts(request, ctx);
    }
    if (path === '/api/import' && method === 'POST') {
      const e = await mw(requireRole(env, ROLES.EDITOR), request, ctx); if (e) return e;
      return BookingHandlers.importBookings(request, ctx);
    }

    return notFound();
  },
};
