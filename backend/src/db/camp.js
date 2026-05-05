// backend/src/db/camp.js
// D1 query helpers for rooms and bookings

export const Rooms = {
  async getAll(db) {
    const { results } = await db.prepare('SELECT * FROM rooms ORDER BY id').all();
    return results.map(r => ({ id: r.id, num: r.num, clean: !!r.clean, repair: !!r.repair }));
  },
  async update(db, { id, clean, repair }) {
    await db.prepare('UPDATE rooms SET clean=?1, repair=?2 WHERE id=?3')
      .bind(clean ? 1 : 0, repair ? 1 : 0, id).run();
  },
};

export const Bookings = {
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
