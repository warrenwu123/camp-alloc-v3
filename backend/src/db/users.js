// backend/src/db/users.js
// D1 query helpers for user + auth tables

export const Users = {
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

export const Sessions = {
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

export const RefreshTokens = {
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

export const EmailVerifications = {
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

export const PasswordResets = {
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

export const AuditLog = {
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
