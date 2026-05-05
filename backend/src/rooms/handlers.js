// backend/src/rooms/handlers.js
import { Rooms } from '../db/camp.js';
import { AuditLog } from '../db/users.js';
import { ok, err } from '../utils/response.js';

export async function getRooms(req, ctx) {
  return ok({ rooms: await Rooms.getAll(ctx.db) });
}

export async function updateRoom(req, ctx, roomId) {
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
