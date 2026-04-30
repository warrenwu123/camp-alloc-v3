// backend/src/bookings/handlers.js
import { Bookings } from '../db/camp.js';
import { AuditLog } from '../db/users.js';
import { ok, err } from '../utils/response.js';

export async function getBookings(req, ctx) {
  return ok({ bookings: await Bookings.getAll(ctx.db) });
}

export async function createBooking(req, ctx) {
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

export async function updateBooking(req, ctx, bookingId) {
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

export async function deleteBooking(req, ctx, bookingId) {
  await Bookings.delete(ctx.db, bookingId);
  await AuditLog.insert(ctx.db, {
    userId: ctx.user.id, action: 'booking.delete',
    targetType: 'booking', targetId: bookingId,
  });
  return ok();
}

export async function getCheckins(req, ctx) {
  const url  = new URL(req.url);
  const date = url.searchParams.get('date') || new Date().toISOString().slice(0, 10);
  const list = await Bookings.filterByDate(ctx.db, 'checkin', date);
  return ok({ date, checkins: list });
}

export async function getCheckouts(req, ctx) {
  const url  = new URL(req.url);
  const date = url.searchParams.get('date') || new Date().toISOString().slice(0, 10);
  const list = await Bookings.filterByDate(ctx.db, 'checkout', date);
  return ok({ date, checkouts: list });
}

export async function importBookings(req, ctx) {
  const { bookings: bArr = [], rooms: rArr = [] } = await req.json().catch(() => ({}));
  const { Rooms } = await import('../db/camp.js');
  for (const r of rArr) await Rooms.update(ctx.db, r);
  for (const b of bArr) await Bookings.upsert(ctx.db, b);
  await AuditLog.insert(ctx.db, {
    userId: ctx.user.id, action: 'booking.import',
    detail: { bookingsImported: bArr.length, roomsImported: rArr.length },
  });
  return ok({ bookingsImported: bArr.length, roomsImported: rArr.length });
}
