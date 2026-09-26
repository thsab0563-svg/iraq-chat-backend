/* ============================================================
   Dust Server v11.0 — Secure Admin + E2EE + Anti-MITM
   ============================================================ */
'use strict';

require('dotenv').config();

const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { Server } = require('socket.io');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const multer = require('multer');
const webpush = require('web-push');
const QRCode = require('qrcode');
const cors = require('cors');
const { nanoid } = require('nanoid');

/* ===== 1. Environment ===== */
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) { console.error('❌ JWT_SECRET missing or too short'); process.exit(1); }
const DB_KEY_HEX = process.env.DB_ENCRYPTION_KEY;
if (!DB_KEY_HEX || DB_KEY_HEX.length !== 32) { console.error('❌ DB_ENCRYPTION_KEY must be exactly 32 chars'); process.exit(1); }
const DB_KEY = Buffer.from(DB_KEY_HEX, 'utf8');
const PUBLIC_URL = process.env.PUBLIC_URL || 'http://localhost:8080';
const PORT = parseInt(process.env.PORT || '8080', 10);
const DB_PATH = process.env.DB_PATH || './dust.db';

/* ===== 2. Database ===== */
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  display_name TEXT NOT NULL,
  color TEXT DEFAULT '#e8b567',
  bio_enc TEXT,
  location_enc TEXT,
  avatar TEXT,
  cover TEXT,
  qr_id TEXT UNIQUE,
  token_hash TEXT NOT NULL,
  theme TEXT DEFAULT 'light',
  sound INTEGER DEFAULT 1,
  created_at INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  public_key TEXT,
  is_admin INTEGER DEFAULT 0,
  banned INTEGER DEFAULT 0,
  deleted INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_users_qr ON users(qr_id);
CREATE INDEX IF NOT EXISTS idx_users_token ON users(token_hash);

CREATE TABLE IF NOT EXISTS friendships (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL, friend_id INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'accepted', time INTEGER NOT NULL,
  UNIQUE(user_id, friend_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (friend_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS blocks (
  blocker_id INTEGER NOT NULL, blocked_id INTEGER NOT NULL, time INTEGER NOT NULL,
  PRIMARY KEY (blocker_id, blocked_id)
);

CREATE TABLE IF NOT EXISTS dms (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  from_id INTEGER NOT NULL, to_id INTEGER NOT NULL, text TEXT NOT NULL,
  time INTEGER NOT NULL, delivered INTEGER DEFAULT 0, read INTEGER DEFAULT 0,
  edited INTEGER DEFAULT 0, deleted INTEGER DEFAULT 0,
  FOREIGN KEY (from_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (to_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_dms_from_to ON dms(from_id, to_id, time);
CREATE INDEX IF NOT EXISTS idx_dms_to ON dms(to_id, read);

CREATE TABLE IF NOT EXISTS push_subs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL, endpoint TEXT NOT NULL UNIQUE,
  p256dh TEXT NOT NULL, auth TEXT NOT NULL, time INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
`);

console.log('✅ Database initialized');
try { db.exec('ALTER TABLE users ADD COLUMN public_key TEXT'); } catch(e) {}
try { db.exec('ALTER TABLE dms ADD COLUMN edited INTEGER DEFAULT 0'); } catch(e) {}
try { db.exec('ALTER TABLE dms ADD COLUMN deleted INTEGER DEFAULT 0'); } catch(e) {}
try { db.exec('ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0'); } catch(e) {}
try { db.exec('ALTER TABLE users ADD COLUMN banned INTEGER DEFAULT 0'); } catch(e) {}

/* ===== 3. Admin Secret System ===== */
const ADMIN_SECRET = process.env.ADMIN_SECRET || '';
const ADMIN_USER_ID = process.env.ADMIN_USER_ID || '';

if (ADMIN_SECRET && ADMIN_SECRET.length < 20) {
  console.error('❌ ADMIN_SECRET must be at least 20 characters!');
  process.exit(1);
}
if (ADMIN_SECRET) console.log('🔑 Admin secret configured (first claim wins)');
if (ADMIN_USER_ID) console.log('🔑 Admin ID fallback configured:', ADMIN_USER_ID);

function ensureAdminById() {
  if (!ADMIN_USER_ID) return;
  try {
    const existingAdmins = db.prepare('SELECT COUNT(*) as c FROM users WHERE is_admin = 1').get().c;
    if (existingAdmins > 0) return;
    const r = db.prepare('UPDATE users SET is_admin = 1 WHERE id = ?').run(parseInt(ADMIN_USER_ID, 10));
    if (r.changes > 0) console.log('✅ Admin configured by ID:', ADMIN_USER_ID);
  } catch(e) {}
}
ensureAdminById();
setInterval(ensureAdminById, 60 * 1000);

/* ===== 4. Field encryption ===== */
function encryptField(plain) {
  if (!plain) return null;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', DB_KEY, iv);
  const enc = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString('base64');
}
function decryptField(payload) {
  if (!payload) return null;
  try {
    const raw = Buffer.from(payload, 'base64');
    const iv = raw.slice(0, 12);
    const tag = raw.slice(12, 28);
    const enc = raw.slice(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', DB_KEY, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf8');
  } catch (e) { return null; }
}

/* ===== 5. Helpers ===== */
function now() { return Date.now(); }
function hashToken(token) { return crypto.createHash('sha256').update(token).digest('hex'); }
const ONLINE_USERS = new Map();

function publicUser(row, includePrivate = false) {
  if (!row) return null;
  const u = {
    id: row.id, username: row.username, display_name: row.display_name,
    color: row.color, avatar: row.avatar, cover: row.cover, qr_id: row.qr_id,
    created_at: row.created_at, last_seen: row.last_seen,
    online: ONLINE_USERS.has(row.id),
    public_key: row.public_key || null,
    bio: decryptField(row.bio_enc),
    location: decryptField(row.location_enc),
    deleted: row.deleted === 1,
    is_admin: row.is_admin === 1,
    banned: row.banned === 1
  };
  if (includePrivate) { u.theme = row.theme; u.sound = !!row.sound; }
  return u;
}
function mapMessage(m) {
  return {
    id: m.id, from_id: m.from_id, to_id: m.to_id,
    text: m.deleted === 1 ? '' : m.text,
    time: m.time,
    delivered: !!m.delivered, read: !!m.read,
    edited: !!m.edited, deleted: !!m.deleted
  };
}

/* ===== 6. Express ===== */
const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false, crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(cors({ origin: (o, cb) => cb(null, true), credentials: true }));
app.use(express.json({ limit: '256kb' }));
app.use(express.urlencoded({ extended: true, limit: '256kb' }));

const PUBLIC_DIR = path.join(__dirname, 'public');
if (fs.existsSync(PUBLIC_DIR)) {
  app.use(express.static(PUBLIC_DIR, {
    maxAge: '1h',
    setHeaders: (res, p) => { if (p.endsWith('.html')) res.setHeader('Cache-Control', 'no-cache'); }
  }));
}
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
app.use('/uploads', express.static(UPLOAD_DIR, { maxAge: '7d' }));

/* ===== 7. Rate limiting ===== */
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, message: { error: 'too_many_requests' } });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: 240, message: { error: 'rate_limit_exceeded' } });
const dmLimiter = rateLimit({ windowMs: 60 * 1000, max: 80, keyGenerator: (req) => req.userId ? String(req.userId) : req.ip, message: { error: 'slow_down' } });
const claimLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 5, message: { error: 'too_many_claims' } });

app.use('/api/', apiLimiter);
app.use('/api/register', authLimiter);
app.use('/api/claim-admin', claimLimiter);

/* ===== 8. Auth middleware ===== */
function authRequired(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'auth_required' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const row = db.prepare('SELECT * FROM users WHERE id = ? AND deleted = 0').get(decoded.id);
    if (!row) return res.status(401).json({ error: 'user_not_found' });
    if (row.token_hash !== hashToken(token)) return res.status(401).json({ error: 'session_expired' });
    if (row.banned === 1) return res.status(403).json({ error: 'banned' });
    req.userId = row.id; req.user = row; req.token = token;
    next();
  } catch (e) { return res.status(401).json({ error: 'invalid_token' }); }
}
function validate(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: 'invalid_input', details: errors.array() });
  next();
}
function adminRequired(req, res, next) {
  if (!req.user || req.user.is_admin !== 1) return res.status(403).json({ error: 'admin_only' });
  next();
}

/* ===== 9. Auth routes ===== */
app.post('/api/register',
  body('name').trim().isLength({ min: 2, max: 20 }).matches(/^[a-z][a-z0-9_]*$/i),
  body('color').optional().matches(/^#[0-9a-f]{6}$/i),
  validate,
  (req, res) => {
    const { name, color } = req.body;
    const baseName = name.toLowerCase();
    let username = baseName;
    const exists = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
    if (exists) {
      for (let i = 0; i < 10; i++) {
        const candidate = baseName + Math.floor(Math.random() * 9999).toString().padStart(4, '0');
        if (!db.prepare('SELECT id FROM users WHERE username = ?').get(candidate)) { username = candidate; break; }
      }
    }
    const qrId = nanoid(16).toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 16);
    const info = db.prepare(`INSERT INTO users (username, display_name, color, qr_id, token_hash, created_at, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)`).run(username, baseName, color || '#e8b567', qrId, 'pending', now(), now());
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);
    const jwtToken = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '365d' });
    db.prepare('UPDATE users SET token_hash = ? WHERE id = ?').run(hashToken(jwtToken), user.id);
    const updated = db.prepare('SELECT * FROM users WHERE id = ?').get(user.id);
    res.json({ token: jwtToken, user: publicUser(updated, true) });
  }
);

app.post('/api/logout', authRequired, (req, res) => {
  db.prepare('UPDATE users SET deleted = 1 WHERE id = ?').run(req.userId);
  io.emit('user-deleted', { userId: req.userId });
  res.json({ ok: true });
});

/* ===== 9.5. Claim Admin ===== */
app.post('/api/claim-admin', authRequired, (req, res) => {
  if (!ADMIN_SECRET) return res.status(400).json({ error: 'no_secret_configured' });

  const provided = String((req.body && req.body.secret) || '');
  if (provided.length < 20) return res.status(400).json({ error: 'secret_too_short' });

  const a = Buffer.from(provided, 'utf8');
  const b = Buffer.from(ADMIN_SECRET, 'utf8');
  if (a.length !== b.length) return res.status(403).json({ error: 'invalid_secret' });
  try {
    if (!crypto.timingSafeEqual(a, b)) return res.status(403).json({ error: 'invalid_secret' });
  } catch(e) { return res.status(403).json({ error: 'invalid_secret' }); }

  const existingAdmins = db.prepare('SELECT COUNT(*) as c FROM users WHERE is_admin = 1').get().c;
  const me = db.prepare('SELECT is_admin FROM users WHERE id = ?').get(req.userId);
  const iAmAdmin = me && me.is_admin === 1;

  if (existingAdmins > 0 && !iAmAdmin) {
    console.log(`⚠️  Admin claim rejected: admins exist (user ${req.userId})`);
    return res.status(403).json({ error: 'admin_already_exists' });
  }

  db.prepare('UPDATE users SET is_admin = 1 WHERE id = ?').run(req.userId);
  console.log(`🎉 User ${req.userId} (${req.user.username}) became admin`);

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.userId);
  res.json({ ok: true, user: publicUser(user, true) });
});

/* ===== 10. User routes ===== */
app.get('/api/me', authRequired, (req, res) => res.json({ user: publicUser(req.user, true) }));

app.put('/api/me', authRequired,
  body('display_name').optional().trim().isLength({ min: 2, max: 20 }),
  body('bio').optional().trim().isLength({ max: 200 }),
  body('location').optional().trim().isLength({ max: 100 }),
  body('theme').optional().isIn(['dark', 'light']),
  body('sound').optional().isBoolean(),
  validate,
  (req, res) => {
    const b = req.body;
    const updates = []; const values = [];
    if (b.display_name !== undefined) { updates.push('display_name = ?'); values.push(b.display_name); }
    if (b.bio !== undefined) { updates.push('bio_enc = ?'); values.push(encryptField(b.bio)); }
    if (b.location !== undefined) { updates.push('location_enc = ?'); values.push(encryptField(b.location)); }
    if (b.theme !== undefined) { updates.push('theme = ?'); values.push(b.theme); }
    if (b.sound !== undefined) { updates.push('sound = ?'); values.push(b.sound ? 1 : 0); }
    if (updates.length) { values.push(req.userId); db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).run(...values); }
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.userId);
    res.json({ user: publicUser(user, true) });
  }
);

app.put('/api/me/public-key', authRequired,
  body('public_key').trim().isLength({ min: 40, max: 500 }),
  validate,
  (req, res) => {
    db.prepare('UPDATE users SET public_key = ? WHERE id = ?').run(req.body.public_key, req.userId);
    res.json({ ok: true });
  }
);

app.get('/api/users/:id', authRequired, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'invalid_id' });
  const row = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!row) return res.status(404).json({ error: 'user_not_found' });
  const blocked = !!db.prepare('SELECT 1 FROM blocks WHERE (blocker_id = ? AND blocked_id = ?) OR (blocker_id = ? AND blocked_id = ?)').get(req.userId, id, id, req.userId);
  const isFriend = !!db.prepare('SELECT 1 FROM friendships WHERE user_id = ? AND friend_id = ? AND status = ?').get(req.userId, id, 'accepted');
  res.json({ user: publicUser(row), isFriend, blocked });
});

/* ===== 10.5. Admin routes ===== */
app.get('/api/admin/stats', authRequired, adminRequired, (req, res) => {
  const totalUsers = db.prepare('SELECT COUNT(*) as c FROM users WHERE deleted = 0').get().c;
  const activeUsers = db.prepare('SELECT COUNT(*) as c FROM users WHERE deleted = 0 AND last_seen > ?').get(Date.now() - 24*60*60*1000).c;
  const bannedUsers = db.prepare('SELECT COUNT(*) as c FROM users WHERE banned = 1').get().c;
  const totalMessages = db.prepare('SELECT COUNT(*) as c FROM dms').get().c;
  const messages24h = db.prepare('SELECT COUNT(*) as c FROM dms WHERE time > ?').get(Date.now() - 24*60*60*1000).c;
  const totalFriendships = db.prepare('SELECT COUNT(*) as c FROM friendships').get().c / 2;
  const onlineNow = ONLINE_USERS.size;
  res.json({
    totalUsers, activeUsers, bannedUsers,
    totalMessages, messages24h,
    totalFriendships, onlineNow,
    uptime: process.uptime(), version: '11.0.0'
  });
});

app.get('/api/admin/users', authRequired, adminRequired, (req, res) => {
  const q = String(req.query.q || '').trim().slice(0, 50);
  let rows;
  if (q) {
    rows = db.prepare(`SELECT * FROM users WHERE username LIKE ? OR display_name LIKE ? ORDER BY last_seen DESC LIMIT 100`).all(`%${q}%`, `%${q}%`);
  } else {
    rows = db.prepare('SELECT * FROM users ORDER BY last_seen DESC LIMIT 100').all();
  }
  const users = rows.map(r => {
    const msgCount = db.prepare('SELECT COUNT(*) as c FROM dms WHERE from_id = ? OR to_id = ?').get(r.id, r.id).c;
    const friends = db.prepare('SELECT COUNT(*) as c FROM friendships WHERE user_id = ?').get(r.id).c;
    const u = publicUser(r, true);
    u.msg_count = msgCount;
    u.friends_count = friends;
    return u;
  });
  res.json({ users });
});

app.post('/api/admin/user/:id/ban', authRequired, adminRequired, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'invalid' });
  if (id === req.userId) return res.status(400).json({ error: 'self' });
  const action = req.body && req.body.action;
  const banned = action === 'unban' ? 0 : 1;
  db.prepare('UPDATE users SET banned = ? WHERE id = ?').run(banned, id);
  if (banned === 1) io.to(`u_${id}`).emit('auth-error', { error: 'banned' });
  res.json({ ok: true, banned: banned === 1 });
});

app.delete('/api/admin/user/:id', authRequired, adminRequired, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'invalid' });
  if (id === req.userId) return res.status(400).json({ error: 'self' });
  db.prepare('UPDATE users SET deleted = 1, banned = 1 WHERE id = ?').run(id);
  io.to(`u_${id}`).emit('user-deleted', { userId: id });
  res.json({ ok: true });
});

app.post('/api/admin/user/:id/admin', authRequired, adminRequired, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'invalid' });
  if (id === req.userId) return res.status(400).json({ error: 'self' });
  const current = db.prepare('SELECT is_admin FROM users WHERE id = ?').get(id);
  if (!current) return res.status(404).json({ error: 'not_found' });
  const newVal = current.is_admin === 1 ? 0 : 1;
  db.prepare('UPDATE users SET is_admin = ? WHERE id = ?').run(newVal, id);
  res.json({ ok: true, is_admin: newVal === 1 });
});

app.post('/api/admin/broadcast', authRequired, adminRequired,
  body('text').trim().isLength({ min: 1, max: 500 }),
  validate,
  (req, res) => {
    const text = req.body.text;
    const users = db.prepare('SELECT id FROM users WHERE deleted = 0').all();
    let sent = 0;
    const t = Date.now();
    const senderId = req.userId;
    for (const u of users) {
      if (u.id === senderId) continue;
      try {
        const info = db.prepare('INSERT INTO dms (from_id, to_id, text, time, delivered) VALUES (?, ?, ?, ?, 0)').run(senderId, u.id, '📢 ' + text, t);
        const msg = { id: info.lastInsertRowid, from_id: senderId, to_id: u.id, text: '📢 ' + text, time: t, delivered: ONLINE_USERS.has(u.id), read: false, edited: false, deleted: false };
        io.to(`u_${u.id}`).emit('dm-message', msg);
        sent++;
      } catch(e) {}
    }
    res.json({ ok: true, sent });
  }
);

/* ===== 11. QR ===== */
app.get('/api/qr/image', authRequired, async (req, res) => {
  try {
    const link = `${PUBLIC_URL}/?qr=${req.user.qr_id}`;
    const dataUrl = await QRCode.toDataURL(link, { width: 512, margin: 2, color: { dark: '#0b0d14', light: '#ffffff' } });
    res.json({ qr: dataUrl, link, qr_id: req.user.qr_id });
  } catch (e) { res.status(500).json({ error: 'qr_failed' }); }
});

/* ===== 12. Friends ===== */
app.post('/api/friends/add-by-qr', authRequired,
  body('qr_id').trim().isLength({ min: 8, max: 32 }).matches(/^[a-z0-9]+$/i),
  validate,
  (req, res) => {
    const qrId = req.body.qr_id.toLowerCase();
    const target = db.prepare('SELECT * FROM users WHERE qr_id = ? AND deleted = 0').get(qrId);
    if (!target) return res.status(404).json({ error: 'user_not_found' });
    if (target.id === req.userId) return res.status(400).json({ error: 'self' });
    const blocked = db.prepare('SELECT 1 FROM blocks WHERE (blocker_id = ? AND blocked_id = ?) OR (blocker_id = ? AND blocked_id = ?)').get(req.userId, target.id, target.id, req.userId);
    if (blocked) return res.status(403).json({ error: 'blocked' });
    const existing = db.prepare('SELECT 1 FROM friendships WHERE user_id = ? AND friend_id = ?').get(req.userId, target.id);
    if (existing) return res.json({ status: 'already_friends', user: publicUser(target) });
    const t = now();
    const tx = db.transaction(() => {
      db.prepare('INSERT OR IGNORE INTO friendships (user_id, friend_id, status, time) VALUES (?, ?, ?, ?)').run(req.userId, target.id, 'accepted', t);
      db.prepare('INSERT OR IGNORE INTO friendships (user_id, friend_id, status, time) VALUES (?, ?, ?, ?)').run(target.id, req.userId, 'accepted', t);
    });
    tx();
    io.to(`u_${target.id}`).emit('notification', { type: 'friend_added', text: `${req.user.display_name} أضافك كصديق`, from: publicUser(req.user) });
    res.json({ status: 'added', user: publicUser(target) });
  }
);

/* ===== 13. DM ===== */
app.get('/api/dm-conversations', authRequired, (req, res) => {
  const rows = db.prepare(`SELECT CASE WHEN from_id = ? THEN to_id ELSE from_id END AS other_id, MAX(time) AS last_time FROM dms WHERE from_id = ? OR to_id = ? GROUP BY other_id ORDER BY last_time DESC LIMIT 100`).all(req.userId, req.userId, req.userId);
  const conversations = rows.map(r => {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(r.other_id);
    if (!user) return null;
    const last = db.prepare('SELECT id, text, time, deleted FROM dms WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?) ORDER BY time DESC LIMIT 1').get(req.userId, r.other_id, r.other_id, req.userId);
    const unread = db.prepare('SELECT COUNT(*) as c FROM dms WHERE from_id = ? AND to_id = ? AND read = 0').get(r.other_id, req.userId).c;
    return { user: publicUser(user), last: last ? { text: last.deleted === 1 ? '' : last.text, time: last.time, deleted: last.deleted === 1 } : null, unread };
  }).filter(Boolean);
  res.json({ conversations });
});

app.get('/api/dms/:userId', authRequired, (req, res) => {
  const otherId = parseInt(req.params.userId, 10);
  if (!otherId) return res.status(400).json({ error: 'invalid' });
  const rows = db.prepare(`SELECT * FROM dms WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?) ORDER BY time ASC LIMIT 500`).all(req.userId, otherId, otherId, req.userId);
  db.prepare('UPDATE dms SET read = 1 WHERE from_id = ? AND to_id = ? AND read = 0').run(otherId, req.userId);
  io.to(`u_${otherId}`).emit('dm-read-receipt', { byId: req.userId });
  res.json({ messages: rows.map(mapMessage) });
});

app.delete('/api/dm-conversations/:userId', authRequired, (req, res) => {
  const otherId = parseInt(req.params.userId, 10);
  if (!otherId) return res.status(400).json({ error: 'invalid' });
  db.prepare('DELETE FROM dms WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?)').run(req.userId, otherId, otherId, req.userId);
  io.to(`u_${otherId}`).emit('dm-conversation-deleted', { byId: req.userId });
  res.json({ ok: true });
});

app.put('/api/dms/:messageId', authRequired,
  body('text').trim().isLength({ min: 1, max: 10000 }),
  validate,
  (req, res) => {
    const msgId = parseInt(req.params.messageId, 10);
    if (!msgId) return res.status(400).json({ error: 'invalid' });
    const msg = db.prepare('SELECT * FROM dms WHERE id = ?').get(msgId);
    if (!msg) return res.status(404).json({ error: 'not_found' });
    if (msg.from_id !== req.userId) return res.status(403).json({ error: 'forbidden' });
    if (msg.deleted === 1) return res.status(400).json({ error: 'already_deleted' });
    db.prepare('UPDATE dms SET text = ?, edited = 1 WHERE id = ?').run(req.body.text, msgId);
    io.to(`u_${msg.to_id}`).emit('dm-edited', { id: msgId, text: req.body.text, edited: true, byId: req.userId });
    res.json({ ok: true });
  }
);

app.delete('/api/dms/:messageId', authRequired, (req, res) => {
  const msgId = parseInt(req.params.messageId, 10);
  if (!msgId) return res.status(400).json({ error: 'invalid' });
  const msg = db.prepare('SELECT * FROM dms WHERE id = ?').get(msgId);
  if (!msg) return res.status(404).json({ error: 'not_found' });
  if (msg.from_id !== req.userId) return res.status(403).json({ error: 'forbidden' });
  if (msg.deleted === 1) return res.json({ ok: true });
  db.prepare('UPDATE dms SET deleted = 1, text = ? WHERE id = ?').run('', msgId);
  io.to(`u_${msg.to_id}`).emit('dm-deleted', { id: msgId, byId: req.userId });
  res.json({ ok: true });
});

/* ===== 14. Upload ===== */
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase().slice(0, 10) || '.jpg';
    const safe = ['.jpg', '.jpeg', '.png', '.webp', '.gif'].includes(ext) ? ext : '.jpg';
    cb(null, `${Date.now()}_${crypto.randomBytes(8).toString('hex')}${safe}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 8 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ok = /^image\/(jpeg|png|webp|gif)$/.test(file.mimetype);
    cb(ok ? null : new Error('invalid_type'), ok);
  }
});
app.post('/upload', authRequired, upload.single('image'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'no_file' });
  res.json({ url: `${PUBLIC_URL}/uploads/${req.file.filename}` });
});

/* ===== 15. Push ===== */
let pushEnabled = false;
if (process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY) {
  webpush.setVapidDetails(process.env.VAPID_SUBJECT || 'mailto:admin@dust.app', process.env.VAPID_PUBLIC_KEY, process.env.VAPID_PRIVATE_KEY);
  pushEnabled = true;
}
app.get('/api/vapid-public', (req, res) => res.json({ key: process.env.VAPID_PUBLIC_KEY || null }));
app.post('/api/push/subscribe', authRequired, (req, res) => {
  const sub = req.body;
  if (!sub || !sub.endpoint) return res.status(400).json({ error: 'invalid' });
  db.prepare(`INSERT INTO push_subs (user_id, endpoint, p256dh, auth, time) VALUES (?, ?, ?, ?, ?) ON CONFLICT(endpoint) DO UPDATE SET user_id = excluded.user_id`).run(req.userId, sub.endpoint, sub.keys ? sub.keys.p256dh : '', sub.keys ? sub.keys.auth : '', now());
  res.json({ ok: true });
});
async function sendPush(userId, payload) {
  if (!pushEnabled) return;
  const subs = db.prepare('SELECT * FROM push_subs WHERE user_id = ?').all(userId);
  const dead = [];
  for (const s of subs) {
    try { await webpush.sendNotification({ endpoint: s.endpoint, keys: { p256dh: s.p256dh, auth: s.auth } }, JSON.stringify(payload)); }
    catch (e) { if (e.statusCode === 404 || e.statusCode === 410) dead.push(s.id); }
  }
  for (const id of dead) db.prepare('DELETE FROM push_subs WHERE id = ?').run(id);
}

/* ===== 16. Socket.io ===== */
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*', methods: ['GET', 'POST'] }, pingTimeout: 30000, pingInterval: 25000, maxHttpBufferSize: 1e6 });

function verifyToken(token) {
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const row = db.prepare('SELECT * FROM users WHERE id = ? AND deleted = 0').get(decoded.id);
    if (!row) return { error: 'user_not_found' };
    if (row.token_hash !== hashToken(token)) return { error: 'session_expired' };
    if (row.banned === 1) return { error: 'banned' };
    return { user: row };
  } catch (e) { return { error: 'invalid_token' }; }
}
function activateSocket(socket, row) {
  if (socket.userId) { try { socket.leave(`u_${socket.userId}`); } catch(_){} }
  socket.userId = row.id;
  socket.user = row;
  socket.join(`u_${row.id}`);
  if (!ONLINE_USERS.has(row.id)) ONLINE_USERS.set(row.id, new Set());
  ONLINE_USERS.get(row.id).add(socket.id);
  io.emit('user-online', { userId: row.id });
  db.prepare('UPDATE users SET last_seen = ? WHERE id = ?').run(now(), row.id);
  socket.emit('auth-ok', { user: publicUser(row, true) });
}

io.on('connection', (socket) => {
  const handshakeToken = (socket.handshake.auth && socket.handshake.auth.token) || (socket.handshake.query && socket.handshake.query.token);
  if (handshakeToken) {
    const result = verifyToken(handshakeToken);
    if (result.error) socket.emit('auth-error', { error: result.error });
    else activateSocket(socket, result.user);
  }
  socket.on('auth', (data) => {
    const token = data && data.token;
    if (!token) { socket.emit('auth-error', { error: 'auth_required' }); return; }
    const result = verifyToken(token);
    if (result.error) { socket.emit('auth-error', { error: result.error }); return; }
    activateSocket(socket, result.user);
  });
  socket.on('dm-send', (data) => {
    if (!socket.userId) return;
    try {
      if (!data || typeof data.toId !== 'number' || typeof data.text !== 'string') return;
      if (data.text.length === 0 || data.text.length > 10000) return;
      const userId = socket.userId;
      const toId = data.toId;
      const blocked = db.prepare('SELECT 1 FROM blocks WHERE (blocker_id = ? AND blocked_id = ?) OR (blocker_id = ? AND blocked_id = ?)').get(userId, toId, toId, userId);
      if (blocked) return;
      const target = db.prepare('SELECT id, deleted FROM users WHERE id = ?').get(toId);
      if (!target || target.deleted === 1) return;
      const t = now();
      const isOnline = ONLINE_USERS.has(toId);
      const info = db.prepare('INSERT INTO dms (from_id, to_id, text, time, delivered) VALUES (?, ?, ?, ?, ?)').run(userId, toId, data.text, t, isOnline ? 1 : 0);
      const msg = { id: info.lastInsertRowid, from_id: userId, to_id: toId, text: data.text, time: t, delivered: isOnline, read: false, edited: false, deleted: false };
      io.to(`u_${toId}`).emit('dm-message', msg);
      socket.emit('dm-message', msg);
      if (isOnline) socket.emit('dm-delivered', { id: msg.id });
      else sendPush(toId, { title: 'Dust', body: 'رسالة جديدة', tag: 'dm_' + userId }).catch(() => {});
    } catch (e) { console.error('dm-send error:', e); }
  });
  socket.on('dm-read', (data) => {
    if (!socket.userId || !data || typeof data.fromId !== 'number') return;
    db.prepare('UPDATE dms SET read = 1 WHERE from_id = ? AND to_id = ? AND read = 0').run(data.fromId, socket.userId);
    io.to(`u_${data.fromId}`).emit('dm-read-receipt', { byId: socket.userId });
  });
  socket.on('dm-typing', (data) => {
    if (!socket.userId || !data || typeof data.toId !== 'number') return;
    io.to(`u_${data.toId}`).emit('dm-typing', { fromId: socket.userId, isTyping: !!data.isTyping });
  });
  socket.on('disconnect', () => {
    if (!socket.userId) return;
    const userId = socket.userId;
    const set = ONLINE_USERS.get(userId);
    if (set) {
      set.delete(socket.id);
      if (set.size === 0) {
        ONLINE_USERS.delete(userId);
        db.prepare('UPDATE users SET last_seen = ? WHERE id = ?').run(now(), userId);
        io.emit('user-offline', { userId });
      }
    }
  });
});

/* ===== 17. Cleanup ===== */
setInterval(() => {
  const cutoff = now() - (48 * 60 * 60 * 1000);
  const r = db.prepare('DELETE FROM dms WHERE time < ? AND read = 1').run(cutoff);
  if (r.changes > 0) console.log(`🧹 Cleaned ${r.changes} messages`);
}, 60 * 60 * 1000);

/* ===== 18. Health ===== */
app.get('/health', (req, res) => {
  res.json({
    ok: true, uptime: process.uptime(),
    users: db.prepare('SELECT COUNT(*) as c FROM users WHERE deleted = 0').get().c,
    admins: db.prepare('SELECT COUNT(*) as c FROM users WHERE is_admin = 1').get().c,
    online: ONLINE_USERS.size, e2ee: 'ECDH-P256', version: '11.0.0'
  });
});
app.use((err, req, res, next) => {
  console.error('❌ Error:', err.message);
  if (err.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: 'file_too_large' });
  res.status(500).json({ error: 'server_error' });
});

/* ===== 19. Start ===== */
server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Dust Server v11.0 on port ${PORT}`);
  console.log(`🔗 ${PUBLIC_URL}`);
  console.log(`🔐 E2EE: ECDH P-256 + HKDF`);
  console.log(`🔑 Admin secret: ${ADMIN_SECRET ? 'configured' : 'NOT SET'}`);
});
process.on('SIGTERM', () => { server.close(() => { db.close(); process.exit(0); }); });
