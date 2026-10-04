/* ============================================================
   Dust Server v13.3 — Auth + Recovery + Avatars + Reports
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
if (!JWT_SECRET || JWT_SECRET.length < 32) { console.error('❌ JWT_SECRET missing'); process.exit(1); }

const DB_KEY_HEX = process.env.DB_ENCRYPTION_KEY;
if (!DB_KEY_HEX || DB_KEY_HEX.length !== 32) { console.error('❌ DB_ENCRYPTION_KEY must be 32 chars'); process.exit(1); }
const DB_KEY = Buffer.from(DB_KEY_HEX, 'utf8');

const PUBLIC_URL = process.env.PUBLIC_URL || 'http://localhost:8080';
const PORT = parseInt(process.env.PORT || '8080', 10);
const DB_PATH = process.env.DB_PATH || './dust.db';

/* ===== 2. Database ===== */
const dbDir = path.dirname(DB_PATH);
if (dbDir && dbDir !== '.' && !fs.existsSync(dbDir)) {
  try { fs.mkdirSync(dbDir, { recursive: true }); } catch (e) {}
}
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  display_name TEXT NOT NULL,
  color TEXT DEFAULT '#e8b567',
  bio_enc TEXT, location_enc TEXT, avatar TEXT, avatar_id TEXT, cover TEXT,
  qr_id TEXT UNIQUE, token_hash TEXT NOT NULL, password_hash TEXT,
  security_q INTEGER, security_a_hash TEXT,
  theme TEXT DEFAULT 'light', sound INTEGER DEFAULT 1,
  created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL,
  public_key TEXT, is_admin INTEGER DEFAULT 0, verified INTEGER DEFAULT 0,
  banned INTEGER DEFAULT 0, deleted INTEGER DEFAULT 0
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

CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  reporter_id INTEGER NOT NULL, reported_user_id INTEGER, reported_msg_id INTEGER,
  reason TEXT NOT NULL, note TEXT, msg_snapshot TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at INTEGER NOT NULL, reviewed_at INTEGER, reviewed_by INTEGER, action TEXT,
  FOREIGN KEY (reporter_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
`);

console.log('✅ Database initialized at', path.resolve(DB_PATH));

/* ===== 3. Migrations ===== */
try { db.exec('ALTER TABLE users ADD COLUMN public_key TEXT'); } catch(e) {}
try { db.exec('ALTER TABLE dms ADD COLUMN edited INTEGER DEFAULT 0'); } catch(e) {}
try { db.exec('ALTER TABLE dms ADD COLUMN deleted INTEGER DEFAULT 0'); } catch(e) {}
try { db.exec('ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0'); } catch(e) {}
try { db.exec('ALTER TABLE users ADD COLUMN banned INTEGER DEFAULT 0'); } catch(e) {}
try { db.exec('ALTER TABLE users ADD COLUMN password_hash TEXT'); } catch(e) {}
try { db.exec('ALTER TABLE users ADD COLUMN verified INTEGER DEFAULT 0'); } catch(e) {}
try { db.exec('ALTER TABLE users ADD COLUMN avatar_id TEXT'); } catch(e) {}
try { db.exec('ALTER TABLE users ADD COLUMN security_q INTEGER'); } catch(e) {}
try { db.exec('ALTER TABLE users ADD COLUMN security_a_hash TEXT'); } catch(e) {}

/* ===== 4. Password hashing ===== */
const SCRYPT_N = 16384, SCRYPT_R = 8, SCRYPT_P = 1, SCRYPT_KEYLEN = 64;

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, SCRYPT_KEYLEN, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P }).toString('hex');
  return 'scrypt$' + SCRYPT_N + '$' + SCRYPT_R + '$' + SCRYPT_P + '$' + salt + '$' + hash;
}
function verifyPassword(password, stored) {
  try {
    if (!stored || typeof stored !== 'string') return false;
    const parts = stored.split('$');
    if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
    const N = parseInt(parts[1], 10), r = parseInt(parts[2], 10), p = parseInt(parts[3], 10);
    const salt = parts[4];
    const expected = Buffer.from(parts[5], 'hex');
    const computed = crypto.scryptSync(password, salt, expected.length, { N, r, p });
    if (expected.length !== computed.length) return false;
    return crypto.timingSafeEqual(expected, computed);
  } catch (e) { return false; }
}

/* Security answer normalization */
function normalizeAnswer(a) {
  return String(a || '').trim().toLowerCase().replace(/\s+/g, ' ');
}

/* ===== 5. Admin ===== */
const ADMIN_SECRET = process.env.ADMIN_SECRET || '';
const ADMIN_USER_ID = process.env.ADMIN_USER_ID || '';

if (ADMIN_SECRET && ADMIN_SECRET.length < 20) { console.error('❌ ADMIN_SECRET too short'); process.exit(1); }
if (ADMIN_SECRET) console.log('🔑 Admin secret configured');
if (ADMIN_USER_ID) console.log('🔑 Admin ID:', ADMIN_USER_ID);

function ensureAdminById() {
  if (!ADMIN_USER_ID) return;
  try {
    const existingAdmins = db.prepare('SELECT COUNT(*) as c FROM users WHERE is_admin = 1').get().c;
    if (existingAdmins > 0) return;
    const r = db.prepare('UPDATE users SET is_admin = 1 WHERE id = ?').run(parseInt(ADMIN_USER_ID, 10));
    if (r.changes > 0) console.log('✅ Admin configured by ID');
  } catch(e) {}
}
ensureAdminById();
setInterval(ensureAdminById, 60 * 1000);

/* ===== 6. Field encryption ===== */
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
    const decipher = crypto.createDecipheriv('aes-256-gcm', DB_KEY, raw.slice(0, 12));
    decipher.setAuthTag(raw.slice(12, 28));
    return Buffer.concat([decipher.update(raw.slice(28)), decipher.final()]).toString('utf8');
  } catch (e) { return null; }
}

/* ===== 7. Helpers ===== */
function now() { return Date.now(); }
function hashToken(token) { return crypto.createHash('sha256').update(token).digest('hex'); }
const ONLINE_USERS = new Map();

const NAME_REGEX = /^[\u0600-\u06FFa-zA-Z][\u0600-\u06FFa-zA-Z0-9_]{1,19}$/;
function validateUsername(name) {
  if (!NAME_REGEX.test(name)) return false;
  if (/[<>&"'`\\\/;(){}\[\]\s]/.test(name)) return false;
  return true;
}

const ALLOWED_AVATARS = [
  'm1','m2','m3','m4','m5','m6','m7','m8',
  'f1','f2','f3','f4','f5','f6','f7',
  'c1','c2','c3','c4','c5','c6','c7'
];

const SECURITY_QUESTIONS = [
  'ما اسم أول مدرسة لك؟',
  'ما اسم حيوانك الأليف الأول؟',
  'ما اسم مدينتك المفضلة؟',
  'ما اسم أفضل صديق في طفولتك؟',
  'ما هي مهنة والدك؟',
  'ما اسم أول كتاب قرأته؟',
  'ما هو طبقك المفضل؟',
  'ما اسم فريقك الرياضي المفضل؟'
];

function publicUser(row, includePrivate = false) {
  if (!row) return null;
  const u = {
    id: row.id, username: row.username, display_name: row.display_name,
    color: row.color, avatar: row.avatar, avatar_id: row.avatar_id || null,
    cover: row.cover, qr_id: row.qr_id,
    created_at: row.created_at, last_seen: row.last_seen,
    online: ONLINE_USERS.has(row.id),
    public_key: row.public_key || null,
    bio: decryptField(row.bio_enc),
    location: decryptField(row.location_enc),
    deleted: row.deleted === 1,
    is_admin: row.is_admin === 1,
    verified: row.verified === 1,
    banned: row.banned === 1,
    has_security: !!(row.security_q !== null && row.security_a_hash)
  };
  if (includePrivate) { u.theme = row.theme; u.sound = !!row.sound; }
  return u;
}
function mapMessage(m) {
  return {
    id: m.id, from_id: m.from_id, to_id: m.to_id,
    text: m.deleted === 1 ? '' : m.text,
    time: m.time, delivered: !!m.delivered, read: !!m.read,
    edited: !!m.edited, deleted: !!m.deleted
  };
}
const REPORT_REASONS = ['spam', 'harassment', 'inappropriate', 'scam', 'impersonation', 'other'];

/* ===== 8. Express ===== */
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

/* ===== 9. HTTP + Socket.io ===== */
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] },
  pingTimeout: 30000, pingInterval: 25000, maxHttpBufferSize: 1e6
});

/* ===== 10. Rate limit ===== */
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, message: { error: 'too_many_requests' } });
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 15, message: { error: 'too_many_login_attempts' } });
const recoveryLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: { error: 'too_many_recovery_attempts' } });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: 240, message: { error: 'rate_limit_exceeded' } });
const reportLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 10, message: { error: 'too_many_reports' } });

app.use('/api/', apiLimiter);
app.use('/api/register', authLimiter);
app.use('/api/login', loginLimiter);
app.use('/api/recovery', recoveryLimiter);
app.use('/api/reports', reportLimiter);

/* ===== 11. Middleware ===== */
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

/* ===== 12. Register ===== */
app.post('/api/register',
  body('name').trim().isLength({ min: 2, max: 20 }).matches(NAME_REGEX).custom((v) => !/[<>&"'`\\\/;(){}\[\]\s]/.test(v)),
  body('password').isLength({ min: 6, max: 128 }),
  body('color').optional().matches(/^#[0-9a-f]{6}$/i),
  body('security_q').optional().isInt({ min: 0, max: 7 }),
  body('security_a').optional().trim().isLength({ min: 2, max: 100 }),
  validate,
  (req, res) => {
    const { name, color, password, security_q, security_a } = req.body;
    const baseName = name.trim();
    if (!validateUsername(baseName)) return res.status(400).json({ error: 'invalid_input' });

    const exists = db.prepare('SELECT id FROM users WHERE username = ? AND deleted = 0').get(baseName);
    if (exists) return res.status(409).json({ error: 'username_taken' });

    const passwordHash = hashPassword(password);
    let secQ = null, secAHash = null;
    if (typeof security_q === 'number' && security_a && security_a.trim().length >= 2) {
      secQ = security_q;
      secAHash = hashPassword(normalizeAnswer(security_a));
    }

    const qrId = nanoid(16).toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 16);
    const info = db.prepare(`
      INSERT INTO users (username, display_name, color, qr_id, token_hash, password_hash, security_q, security_a_hash, created_at, last_seen)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(baseName, baseName, color || '#e8b567', qrId, 'pending', passwordHash, secQ, secAHash, now(), now());

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);
    const jwtToken = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '365d' });
    db.prepare('UPDATE users SET token_hash = ? WHERE id = ?').run(hashToken(jwtToken), user.id);

    const updated = db.prepare('SELECT * FROM users WHERE id = ?').get(user.id);
    res.json({ token: jwtToken, user: publicUser(updated, true) });
  }
);

/* ===== 13. Login ===== */
app.post('/api/login',
  body('name').trim().isLength({ min: 2, max: 20 }),
  body('password').isLength({ min: 1, max: 128 }),
  validate,
  (req, res) => {
    const name = req.body.name.trim();
    const password = req.body.password;
    const user = db.prepare('SELECT * FROM users WHERE username = ? AND deleted = 0').get(name);
    if (!user) return res.status(401).json({ error: 'invalid_credentials' });
    if (user.banned === 1) return res.status(403).json({ error: 'banned' });

    if (!user.password_hash) {
      const passwordHash = hashPassword(password);
      const jwtToken = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '365d' });
      db.prepare('UPDATE users SET password_hash = ?, token_hash = ? WHERE id = ?').run(passwordHash, hashToken(jwtToken), user.id);
      const updated = db.prepare('SELECT * FROM users WHERE id = ?').get(user.id);
      return res.json({ token: jwtToken, user: publicUser(updated, true), firstTime: true });
    }
    if (!verifyPassword(password, user.password_hash)) return res.status(401).json({ error: 'invalid_credentials' });

    const jwtToken = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '365d' });
    db.prepare('UPDATE users SET token_hash = ? WHERE id = ?').run(hashToken(jwtToken), user.id);
    const updated = db.prepare('SELECT * FROM users WHERE id = ?').get(user.id);
    res.json({ token: jwtToken, user: publicUser(updated, true) });
  }
);

/* ===== 14. Change Password ===== */
app.post('/api/change-password', authRequired,
  body('current_password').isLength({ min: 1, max: 128 }),
  body('new_password').isLength({ min: 6, max: 128 }),
  validate,
  (req, res) => {
    const user = req.user;
    if (user.password_hash && !verifyPassword(req.body.current_password, user.password_hash)) {
      return res.status(401).json({ error: 'wrong_password' });
    }
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hashPassword(req.body.new_password), user.id);
    res.json({ ok: true });
  }
);

/* ===== 15. Password Recovery ===== */
app.post('/api/recovery/lookup',
  body('name').trim().isLength({ min: 2, max: 20 }),
  validate,
  (req, res) => {
    const name = req.body.name.trim();
    const user = db.prepare('SELECT id, username, display_name, security_q, security_a_hash FROM users WHERE username = ? AND deleted = 0').get(name);
    if (!user) return res.status(404).json({ error: 'user_not_found' });
    if (user.security_q === null || user.security_q === undefined || !user.security_a_hash) {
      return res.status(400).json({ error: 'no_security_question' });
    }
    res.json({
      ok: true,
      username: user.username,
      display_name: user.display_name,
      question_index: user.security_q,
      question: SECURITY_QUESTIONS[user.security_q] || ''
    });
  }
);

app.post('/api/recovery/reset',
  body('name').trim().isLength({ min: 2, max: 20 }),
  body('answer').trim().isLength({ min: 1, max: 100 }),
  body('new_password').isLength({ min: 6, max: 128 }),
  validate,
  (req, res) => {
    const name = req.body.name.trim();
    const answer = req.body.answer;
    const newPassword = req.body.new_password;

    const user = db.prepare('SELECT * FROM users WHERE username = ? AND deleted = 0').get(name);
    if (!user) return res.status(404).json({ error: 'user_not_found' });
    if (!user.security_a_hash) return res.status(400).json({ error: 'no_security_question' });
    if (user.banned === 1) return res.status(403).json({ error: 'banned' });

    const norm = normalizeAnswer(answer);
    if (!verifyPassword(norm, user.security_a_hash)) {
      return res.status(401).json({ error: 'wrong_answer' });
    }

    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hashPassword(newPassword), user.id);
    res.json({ ok: true });
  }
);

/* ===== 16. Logout ===== */
app.post('/api/logout', authRequired, (req, res) => {
  const uid = req.userId;
  db.prepare('UPDATE users SET token_hash = ?, public_key = NULL WHERE id = ?')
    .run(hashToken('loggedout_' + uid + '_' + Date.now()), uid);

  const friends = db.prepare('SELECT friend_id FROM friendships WHERE user_id = ?').all(uid);
  for (const f of friends) io.to(`u_${f.friend_id}`).emit('user-offline', { userId: uid });

  const sockets = ONLINE_USERS.get(uid);
  if (sockets) for (const sid of sockets) io.to(sid).emit('auth-error', { error: 'session_expired' });
  ONLINE_USERS.delete(uid);

  res.json({ ok: true });
});

/* ===== 17. User routes ===== */
app.get('/api/me', authRequired, (req, res) => res.json({ user: publicUser(req.user, true) }));

app.put('/api/me', authRequired,
  body('display_name').optional().trim().isLength({ min: 2, max: 20 }),
  body('bio').optional().trim().isLength({ max: 200 }),
  body('location').optional().trim().isLength({ max: 100 }),
  body('theme').optional().isIn(['dark', 'light']),
  body('sound').optional().isBoolean(),
  validate,
  (req, res) => {
    const b = req.body, updates = [], values = [];
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

app.put('/api/me/avatar', authRequired,
  body('avatar_id').optional({ nullable: true }).trim().isLength({ max: 10 }),
  validate,
  (req, res) => {
    const aid = req.body.avatar_id || null;
    if (aid && ALLOWED_AVATARS.indexOf(aid) === -1) return res.status(400).json({ error: 'invalid_avatar' });
    db.prepare('UPDATE users SET avatar_id = ? WHERE id = ?').run(aid, req.userId);
    res.json({ ok: true, avatar_id: aid });
  }
);

app.post('/api/me/security-question', authRequired,
  body('question_index').isInt({ min: 0, max: 7 }),
  body('answer').trim().isLength({ min: 2, max: 100 }),
  body('password').isLength({ min: 1, max: 128 }),
  validate,
  (req, res) => {
    const user = req.user;
    if (!user.password_hash) return res.status(400).json({ error: 'no_password' });
    if (!verifyPassword(req.body.password, user.password_hash)) return res.status(401).json({ error: 'wrong_password' });
    const secAHash = hashPassword(normalizeAnswer(req.body.answer));
    db.prepare('UPDATE users SET security_q = ?, security_a_hash = ? WHERE id = ?')
      .run(req.body.question_index, secAHash, user.id);
    res.json({ ok: true });
  }
);

app.get('/api/security-questions', (req, res) => {
  res.json({ questions: SECURITY_QUESTIONS });
});

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
  const isFriend = !!db.prepare('SELECT 1 FROM friendships WHERE user_id = ? AND friend_id = ?').get(req.userId, id);
  res.json({ user: publicUser(row), isFriend, blocked });
});

/* ===== 18. Reports ===== */
app.post('/api/reports', authRequired,
  body('reported_user_id').optional().isInt({ min: 1 }),
  body('reported_msg_id').optional().isInt({ min: 1 }),
  body('reason').trim().isIn(REPORT_REASONS),
  body('note').optional().trim().isLength({ max: 500 }),
  validate,
  (req, res) => {
    const reporterId = req.userId;
    const { reported_user_id, reported_msg_id, reason, note } = req.body;
    if (!reported_user_id && !reported_msg_id) return res.status(400).json({ error: 'nothing_to_report' });
    if (reported_user_id && reported_user_id === reporterId) return res.status(400).json({ error: 'self_report' });

    let msgSnapshot = null, targetUserId = reported_user_id || null;
    if (reported_msg_id) {
      const msg = db.prepare('SELECT * FROM dms WHERE id = ?').get(reported_msg_id);
      if (!msg) return res.status(404).json({ error: 'message_not_found' });
      if (msg.from_id === reporterId) return res.status(400).json({ error: 'own_message' });
      msgSnapshot = msg.text;
      targetUserId = targetUserId || msg.from_id;
    }
    const dup = reported_msg_id
      ? db.prepare('SELECT 1 FROM reports WHERE reporter_id = ? AND reported_msg_id = ? AND status = ?').get(reporterId, reported_msg_id, 'pending')
      : db.prepare('SELECT 1 FROM reports WHERE reporter_id = ? AND reported_user_id = ? AND status = ? AND reported_msg_id IS NULL').get(reporterId, targetUserId, 'pending');
    if (dup) return res.status(429).json({ error: 'already_reported' });

    const info = db.prepare(`INSERT INTO reports (reporter_id, reported_user_id, reported_msg_id, reason, note, msg_snapshot, status, created_at) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)`)
      .run(reporterId, targetUserId, reported_msg_id || null, reason, note || null, msgSnapshot, now());

    const admins = db.prepare('SELECT id FROM users WHERE is_admin = 1 AND deleted = 0').all();
    const reporterName = req.user.display_name;
    for (const a of admins) io.to(`u_${a.id}`).emit('notification', { type: 'report', text: '🚨 بلاغ جديد من ' + reporterName, reportId: info.lastInsertRowid });
    res.json({ ok: true, reportId: info.lastInsertRowid });
  }
);

/* ===== 19. Admin ===== */
app.get('/api/admin/stats', authRequired, adminRequired, (req, res) => {
  const totalUsers = db.prepare('SELECT COUNT(*) as c FROM users WHERE deleted = 0').get().c;
  const activeUsers = db.prepare('SELECT COUNT(*) as c FROM users WHERE deleted = 0 AND last_seen > ?').get(Date.now() - 24*60*60*1000).c;
  const bannedUsers = db.prepare('SELECT COUNT(*) as c FROM users WHERE banned = 1').get().c;
  const verifiedUsers = db.prepare('SELECT COUNT(*) as c FROM users WHERE verified = 1 AND deleted = 0').get().c;
  const totalMessages = db.prepare('SELECT COUNT(*) as c FROM dms').get().c;
  const messages24h = db.prepare('SELECT COUNT(*) as c FROM dms WHERE time > ?').get(Date.now() - 24*60*60*1000).c;
  const totalFriendships = db.prepare('SELECT COUNT(*) as c FROM friendships').get().c / 2;
  const pendingReports = db.prepare('SELECT COUNT(*) as c FROM reports WHERE status = ?').get('pending').c;
  const totalReports = db.prepare('SELECT COUNT(*) as c FROM reports').get().c;
  const onlineNow = ONLINE_USERS.size;
  res.json({ totalUsers, activeUsers, bannedUsers, verifiedUsers, totalMessages, messages24h, totalFriendships, pendingReports, totalReports, onlineNow, uptime: process.uptime(), version: '13.3.0' });
});

app.get('/api/admin/users', authRequired, adminRequired, (req, res) => {
  const q = String(req.query.q || '').trim().slice(0, 50);
  let rows;
  if (q) rows = db.prepare('SELECT * FROM users WHERE username LIKE ? OR display_name LIKE ? ORDER BY last_seen DESC LIMIT 100').all(`%${q}%`, `%${q}%`);
  else rows = db.prepare('SELECT * FROM users ORDER BY last_seen DESC LIMIT 100').all();

  const users = rows.map(r => {
    const msgCount = db.prepare('SELECT COUNT(*) as c FROM dms WHERE from_id = ? OR to_id = ?').get(r.id, r.id).c;
    const friends = db.prepare('SELECT COUNT(*) as c FROM friendships WHERE user_id = ?').get(r.id).c;
    const reportsAgainst = db.prepare('SELECT COUNT(*) as c FROM reports WHERE reported_user_id = ? AND status = ?').get(r.id, 'pending').c;
    const u = publicUser(r, true);
    u.msg_count = msgCount; u.friends_count = friends;
    u.has_password = !!r.password_hash;
    u.reports_against = reportsAgainst;
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
  if (banned === 1) {
    const socks = ONLINE_USERS.get(id);
    if (socks) for (const sid of socks) io.to(sid).emit('auth-error', { error: 'banned' });
    ONLINE_USERS.delete(id);
  }
  res.json({ ok: true, banned: banned === 1 });
});

app.post('/api/admin/user/:id/verify', authRequired, adminRequired, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'invalid' });
  const action = req.body && req.body.action;
  const verified = action === 'unverify' ? 0 : 1;
  const user = db.prepare('SELECT id FROM users WHERE id = ?').get(id);
  if (!user) return res.status(404).json({ error: 'not_found' });
  db.prepare('UPDATE users SET verified = ? WHERE id = ?').run(verified, id);
  const friends = db.prepare('SELECT friend_id FROM friendships WHERE user_id = ?').all(id);
  for (const f of friends) io.to(`u_${f.friend_id}`).emit('user-verified', { userId: id, verified: verified === 1 });
  io.to(`u_${id}`).emit('user-verified', { userId: id, verified: verified === 1 });
  res.json({ ok: true, verified: verified === 1 });
});

app.delete('/api/admin/user/:id', authRequired, adminRequired, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'invalid' });
  if (id === req.userId) return res.status(400).json({ error: 'self' });
  const friendRows = db.prepare('SELECT friend_id FROM friendships WHERE user_id = ?').all(id);
  const tx = db.transaction(() => {
    db.prepare('DELETE FROM dms WHERE from_id = ? OR to_id = ?').run(id, id);
    db.prepare('DELETE FROM friendships WHERE user_id = ? OR friend_id = ?').run(id, id);
    db.prepare('DELETE FROM blocks WHERE blocker_id = ? OR blocked_id = ?').run(id, id);
    db.prepare('DELETE FROM push_subs WHERE user_id = ?').run(id);
    db.prepare('DELETE FROM users WHERE id = ?').run(id);
  });
  tx();
  for (const f of friendRows) io.to(`u_${f.friend_id}`).emit('user-deleted', { userId: id });
  const socks = ONLINE_USERS.get(id);
  if (socks) for (const sid of socks) io.to(sid).emit('auth-error', { error: 'session_expired' });
  ONLINE_USERS.delete(id);
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
    const t = now();
    const senderId = req.userId;
    let sent = 0;
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

app.get('/api/admin/reports', authRequired, adminRequired, (req, res) => {
  const status = String(req.query.status || 'pending');
  if (['pending', 'resolved', 'dismissed', 'all'].indexOf(status) === -1) return res.status(400).json({ error: 'invalid_status' });
  let rows;
  if (status === 'all') rows = db.prepare('SELECT * FROM reports ORDER BY created_at DESC LIMIT 200').all();
  else rows = db.prepare('SELECT * FROM reports WHERE status = ? ORDER BY created_at DESC LIMIT 200').all(status);

  const reports = rows.map(r => {
    const reporter = db.prepare('SELECT id, username, display_name, color, avatar_id, verified FROM users WHERE id = ?').get(r.reporter_id);
    const reported = r.reported_user_id ? db.prepare('SELECT id, username, display_name, color, avatar_id, verified, banned FROM users WHERE id = ?').get(r.reported_user_id) : null;
    let msgData = null;
    if (r.reported_msg_id) {
      const m = db.prepare('SELECT id, from_id, to_id, text, time FROM dms WHERE id = ?').get(r.reported_msg_id);
      if (m) msgData = { id: m.id, from_id: m.from_id, to_id: m.to_id, text: m.text, time: m.time };
    }
    return {
      id: r.id,
      reporter: reporter ? { id: reporter.id, username: reporter.username, display_name: reporter.display_name, color: reporter.color, avatar_id: reporter.avatar_id, verified: reporter.verified === 1 } : null,
      reported: reported ? { id: reported.id, username: reported.username, display_name: reported.display_name, color: reported.color, avatar_id: reported.avatar_id, verified: reported.verified === 1, banned: reported.banned === 1 } : null,
      reason: r.reason, note: r.note, msg_snapshot: r.msg_snapshot, msg: msgData,
      status: r.status, created_at: r.created_at, reviewed_at: r.reviewed_at, action: r.action
    };
  });
  res.json({ reports });
});

app.post('/api/admin/reports/:id/resolve', authRequired, adminRequired,
  body('action').optional().isIn(['dismiss', 'ban_user', 'warn']),
  validate,
  (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (!id) return res.status(400).json({ error: 'invalid' });
    const action = (req.body && req.body.action) || 'dismiss';
    const r = db.prepare('SELECT * FROM reports WHERE id = ?').get(id);
    if (!r) return res.status(404).json({ error: 'not_found' });
    if (action === 'ban_user' && r.reported_user_id) {
      db.prepare('UPDATE users SET banned = 1 WHERE id = ?').run(r.reported_user_id);
      const socks = ONLINE_USERS.get(r.reported_user_id);
      if (socks) for (const sid of socks) io.to(sid).emit('auth-error', { error: 'banned' });
      ONLINE_USERS.delete(r.reported_user_id);
    }
    const newStatus = action === 'dismiss' ? 'dismissed' : 'resolved';
    db.prepare('UPDATE reports SET status = ?, reviewed_at = ?, reviewed_by = ?, action = ? WHERE id = ?').run(newStatus, now(), req.userId, action, id);
    res.json({ ok: true, status: newStatus, action });
  }
);

app.delete('/api/admin/reports/:id', authRequired, adminRequired, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'invalid' });
  db.prepare('DELETE FROM reports WHERE id = ?').run(id);
  res.json({ ok: true });
});

/* ===== 20. QR ===== */
app.get('/api/qr/image', authRequired, async (req, res) => {
  try {
    const link = `${PUBLIC_URL}/?qr=${req.user.qr_id}`;
    const dataUrl = await QRCode.toDataURL(link, { width: 512, margin: 2, color: { dark: '#0b0d14', light: '#ffffff' } });
    res.json({ qr: dataUrl, link, qr_id: req.user.qr_id });
  } catch (e) { res.status(500).json({ error: 'qr_failed' }); }
});

/* ===== 21. Friends ===== */
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

/* ===== 22. DM ===== */
app.get('/api/dm-conversations', authRequired, (req, res) => {
  const rows = db.prepare(`
    SELECT CASE WHEN from_id = ? THEN to_id ELSE from_id END AS other_id, MAX(time) AS last_time
    FROM dms WHERE from_id = ? OR to_id = ?
    GROUP BY other_id ORDER BY last_time DESC LIMIT 100
  `).all(req.userId, req.userId, req.userId);

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
  const rows = db.prepare('SELECT * FROM dms WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?) ORDER BY time ASC LIMIT 500').all(req.userId, otherId, otherId, req.userId);
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

/* ===== 23. Upload ===== */
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase().slice(0, 10) || '.jpg';
    const safe = ['.jpg', '.jpeg', '.png', '.webp', '.gif'].includes(ext) ? ext : '.jpg';
    cb(null, `${Date.now()}_${crypto.randomBytes(8).toString('hex')}${safe}`);
  }
});
const upload = multer({ storage, limits: { fileSize: 8 * 1024 * 1024 }, fileFilter: (req, file, cb) => {
  const ok = /^image\/(jpeg|png|webp|gif)$/.test(file.mimetype);
  cb(ok ? null : new Error('invalid_type'), ok);
}});
app.post('/upload', authRequired, upload.single('image'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'no_file' });
  res.json({ url: `${PUBLIC_URL}/uploads/${req.file.filename}` });
});

/* ===== 24. Push ===== */
let pushEnabled = false;
if (process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY) {
  webpush.setVapidDetails(process.env.VAPID_SUBJECT || 'mailto:admin@dust.app', process.env.VAPID_PUBLIC_KEY, process.env.VAPID_PRIVATE_KEY);
  pushEnabled = true;
  console.log('✅ Web Push enabled');
}
app.get('/api/vapid-public', (req, res) => res.json({ key: process.env.VAPID_PUBLIC_KEY || null }));
app.post('/api/push/subscribe', authRequired, (req, res) => {
  const sub = req.body;
  if (!sub || !sub.endpoint) return res.status(400).json({ error: 'invalid' });
  db.prepare(`INSERT INTO push_subs (user_id, endpoint, p256dh, auth, time) VALUES (?, ?, ?, ?, ?) ON CONFLICT(endpoint) DO UPDATE SET user_id = excluded.user_id`)
    .run(req.userId, sub.endpoint, sub.keys ? sub.keys.p256dh : '', sub.keys ? sub.keys.auth : '', now());
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

/* ===== 25. Socket.io ===== */
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
  const friends = db.prepare('SELECT friend_id FROM friendships WHERE user_id = ?').all(row.id);
  for (const f of friends) io.to(`u_${f.friend_id}`).emit('user-online', { userId: row.id });
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
      const userId = socket.userId, toId = data.toId;
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
        const friends = db.prepare('SELECT friend_id FROM friendships WHERE user_id = ?').all(userId);
        for (const f of friends) io.to(`u_${f.friend_id}`).emit('user-offline', { userId });
      }
    }
  });
});

/* ===== 26. Cleanup ===== */
setInterval(() => {
  const cutoff = now() - (48 * 60 * 60 * 1000);
  const r = db.prepare('DELETE FROM dms WHERE time < ? AND read = 1').run(cutoff);
  if (r.changes > 0) console.log(`🧹 Cleaned ${r.changes} messages`);
}, 60 * 60 * 1000);

/* ===== 27. Health ===== */
app.get('/health', (req, res) => {
  res.json({
    ok: true, uptime: process.uptime(),
    users: db.prepare('SELECT COUNT(*) as c FROM users WHERE deleted = 0').get().c,
    admins: db.prepare('SELECT COUNT(*) as c FROM users WHERE is_admin = 1').get().c,
    verified: db.prepare('SELECT COUNT(*) as c FROM users WHERE verified = 1 AND deleted = 0').get().c,
    with_security: db.prepare('SELECT COUNT(*) as c FROM users WHERE deleted = 0 AND security_a_hash IS NOT NULL').get().c,
    pending_reports: db.prepare('SELECT COUNT(*) as c FROM reports WHERE status = ?').get('pending').c,
    online: ONLINE_USERS.size,
    version: '13.3.0'
  });
});

app.get('*', (req, res) => {
  const idx = path.join(PUBLIC_DIR, 'index.html');
  if (fs.existsSync(idx)) return res.sendFile(idx);
  res.status(404).json({ error: 'not_found' });
});

app.use((err, req, res, next) => {
  console.error('❌ Error:', err.message);
  if (err.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: 'file_too_large' });
  res.status(500).json({ error: 'server_error' });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Dust Server v13.3 on port ${PORT}`);
  console.log(`🔗 ${PUBLIC_URL}`);
  console.log(`🔐 Password: scrypt`);
  console.log(`🛡️  Recovery: ${SECURITY_QUESTIONS.length} questions available`);
  console.log(`🎨 Avatars: ${ALLOWED_AVATARS.length}`);
  console.log(`📦 DB: ${path.resolve(DB_PATH)}`);
});

process.on('SIGTERM', () => { server.close(() => { db.close(); process.exit(0); }); });
process.on('SIGINT', () => { server.close(() => { db.close(); process.exit(0); }); });
