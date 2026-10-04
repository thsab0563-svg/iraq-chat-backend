/* ============================================================
   Dust Server v13.3.0 — Turso Edition (Auth + Recovery + Avatars + Reports)
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
const multer = require('multer');
const webpush = require('web-push');
const QRCode = require('qrcode');
const cors = require('cors');
const { nanoid } = require('nanoid');

// 👇 استيراد قاعدة البيانات من ملف db.js
const { db, initDb } = require('./db');

/* ===== 1. Environment ===== */
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) { console.error('❌ JWT_SECRET missing'); process.exit(1); }

const DB_KEY_HEX = process.env.DB_ENCRYPTION_KEY;
if (!DB_KEY_HEX || DB_KEY_HEX.length !== 32) { console.error('❌ DB_ENCRYPTION_KEY must be 32 chars'); process.exit(1); }
const DB_KEY = Buffer.from(DB_KEY_HEX, 'utf8');

const PUBLIC_URL = process.env.PUBLIC_URL || 'http://localhost:8080';
const PORT = parseInt(process.env.PORT || '8080', 10);

/* ===== 2. Password hashing ===== */
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
    const N = parseInt(parts[1], 10);
    const r = parseInt(parts[2], 10);
    const p = parseInt(parts[3], 10);
    const salt = parts[4];
    const expected = Buffer.from(parts[5], 'hex');
    const computed = crypto.scryptSync(password, salt, expected.length, { N, r, p });
    if (expected.length !== computed.length) return false;
    return crypto.timingSafeEqual(expected, computed);
  } catch (e) { return false; }
}

function normalizeAnswer(a) {
  return String(a || '').trim().toLowerCase().replace(/\s+/g, ' ');
}

/* ===== 3. Admin Secret ===== */
const ADMIN_SECRET = process.env.ADMIN_SECRET || '';
const ADMIN_USER_ID = process.env.ADMIN_USER_ID || '';

if (ADMIN_SECRET && ADMIN_SECRET.length < 20) { console.error('❌ ADMIN_SECRET too short'); process.exit(1); }
if (ADMIN_SECRET) console.log('🔑 Admin secret configured');
if (ADMIN_USER_ID) console.log('🔑 Admin ID:', ADMIN_USER_ID);

async function ensureAdminById() {
  if (!ADMIN_USER_ID) return;
  try {
    const res = await db.execute('SELECT COUNT(*) as c FROM users WHERE is_admin = 1');
    if (res.rows[0].c > 0) return;
    const updateRes = await db.execute({ sql: 'UPDATE users SET is_admin = 1 WHERE id = ?', args: [parseInt(ADMIN_USER_ID, 10)] });
    if (updateRes.rowsAffected > 0) console.log('✅ Admin configured by ID');
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

const NAME_REGEX = /^[\u0600-\u06FFa-zA-Z][\u0600-\u06FFa-zA-Z0-9_]{1,19}$/;
function validateUsername(name) {
  if (!NAME_REGEX.test(name)) return false;
  if (/[<>&"'`\\\/;(){}\[\]\s]/.test(name)) return false;
  return true;
}

const ALLOWED_AVATARS = ['m1','m2','m3','m4','m5','m6','m7','m8','f1','f2','f3','f4','f5','f6','f7','c1','c2','c3','c4','c5','c6','c7'];

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
    has_security: !!(row.security_q !== null && row.security_q !== undefined && row.security_a_hash)
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

/* ===== 7. HTTP + Socket.io ===== */
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] },
  pingTimeout: 30000, pingInterval: 25000, maxHttpBufferSize: 1e6
});

/* ===== 8. Rate limit ===== */
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

/* ===== 9. Middleware ===== */
async function authRequired(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'auth_required' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const result = await db.execute({ sql: 'SELECT * FROM users WHERE id = ? AND deleted = 0', args: [decoded.id] });
    const row = result.rows[0];
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

/* ===== 10. Register (سؤال الأمان إجباري) ===== */
app.post('/api/register',
  body('name').trim().isLength({ min: 2, max: 20 }).matches(NAME_REGEX).custom((v) => !/[<>&"'`\\\/;(){}\[\]\s]/.test(v)),
  body('password').isLength({ min: 6, max: 128 }),
  body('color').optional().matches(/^#[0-9a-f]{6}$/i),
  body('security_q').isInt({ min: 0, max: 7 }).withMessage('يجب اختيار سؤال أمان'),
  body('security_a').trim().isLength({ min: 2, max: 100 }).withMessage('يجب إدخال إجابة صحيحة'),
  validate,
  async (req, res) => {
    const { name, color, password, security_q, security_a } = req.body;
    const baseName = name.trim();
    if (!validateUsername(baseName)) return res.status(400).json({ error: 'invalid_input' });

    const existsResult = await db.execute({ sql: 'SELECT id FROM users WHERE username = ? AND deleted = 0', args: [baseName] });
    if (existsResult.rows.length > 0) return res.status(409).json({ error: 'username_taken' });

    const passwordHash = hashPassword(password);
    const secQ = security_q;
    const secAHash = hashPassword(normalizeAnswer(security_a));

    const qrId = nanoid(16).toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 16);
    const insertResult = await db.execute({
      sql: `INSERT INTO users (username, display_name, color, qr_id, token_hash, password_hash, security_q, security_a_hash, created_at, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [baseName, baseName, color || '#e8b567', qrId, 'pending', passwordHash, secQ, secAHash, now(), now()]
    });

    const userId = insertResult.lastInsertRowid;
    const jwtToken = jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: '365d' });
    await db.execute({ sql: 'UPDATE users SET token_hash = ? WHERE id = ?', args: [hashToken(jwtToken), userId] });

    const updatedResult = await db.execute({ sql: 'SELECT * FROM users WHERE id = ?', args: [userId] });
    res.json({ token: jwtToken, user: publicUser(updatedResult.rows[0], true) });
  }
);

/* ===== 11. Login ===== */
app.post('/api/login',
  body('name').trim().isLength({ min: 2, max: 20 }),
  body('password').isLength({ min: 1, max: 128 }),
  validate,
  async (req, res) => {
    const name = req.body.name.trim();
    const password = req.body.password;
    const userResult = await db.execute({ sql: 'SELECT * FROM users WHERE username = ? AND deleted = 0', args: [name] });
    const user = userResult.rows[0];
    
    if (!user) return res.status(401).json({ error: 'invalid_credentials' });
    if (user.banned === 1) return res.status(403).json({ error: 'banned' });

    if (!user.password_hash) {
      const passwordHash = hashPassword(password);
      const jwtToken = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '365d' });
      await db.execute({ sql: 'UPDATE users SET password_hash = ?, token_hash = ? WHERE id = ?', args: [passwordHash, hashToken(jwtToken), user.id] });
      const updatedResult = await db.execute({ sql: 'SELECT * FROM users WHERE id = ?', args: [user.id] });
      return res.json({ token: jwtToken, user: publicUser(updatedResult.rows[0], true), firstTime: true });
    }
    if (!verifyPassword(password, user.password_hash)) return res.status(401).json({ error: 'invalid_credentials' });

    const jwtToken = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '365d' });
    await db.execute({ sql: 'UPDATE users SET token_hash = ? WHERE id = ?', args: [hashToken(jwtToken), user.id] });
    const updatedResult = await db.execute({ sql: 'SELECT * FROM users WHERE id = ?', args: [user.id] });
    res.json({ token: jwtToken, user: publicUser(updatedResult.rows[0], true) });
  }
);

/* ===== 12. Change Password ===== */
app.post('/api/change-password', authRequired,
  body('current_password').isLength({ min: 1, max: 128 }),
  body('new_password').isLength({ min: 6, max: 128 }),
  validate,
  async (req, res) => {
    const user = req.user;
    if (user.password_hash && !verifyPassword(req.body.current_password, user.password_hash)) {
      return res.status(401).json({ error: 'wrong_password' });
    }
    await db.execute({ sql: 'UPDATE users SET password_hash = ? WHERE id = ?', args: [hashPassword(req.body.new_password), user.id] });
    res.json({ ok: true });
  }
);

/* ===== 13. Password Recovery ===== */
app.post('/api/recovery/lookup',
  body('name').trim().isLength({ min: 2, max: 20 }),
  validate,
  async (req, res) => {
    const name = req.body.name.trim();
    const userResult = await db.execute({ sql: 'SELECT id, username, display_name, security_q, security_a_hash FROM users WHERE username = ? AND deleted = 0', args: [name] });
    const user = userResult.rows[0];
    if (!user) return res.status(404).json({ error: 'user_not_found' });
    if (user.security_q === null || user.security_q === undefined || !user.security_a_hash) {
      return res.status(400).json({ error: 'no_security_question' });
    }
    res.json({
      ok: true, username: user.username, display_name: user.display_name,
      question_index: user.security_q, question: SECURITY_QUESTIONS[user.security_q] || ''
    });
  }
);

app.post('/api/recovery/reset',
  body('name').trim().isLength({ min: 2, max: 20 }),
  body('answer').trim().isLength({ min: 1, max: 100 }),
  body('new_password').isLength({ min: 6, max: 128 }),
  validate,
  async (req, res) => {
    const name = req.body.name.trim();
    const answer = req.body.answer;
    const newPassword = req.body.new_password;

    const userResult = await db.execute({ sql: 'SELECT * FROM users WHERE username = ? AND deleted = 0', args: [name] });
    const user = userResult.rows[0];
    if (!user) return res.status(404).json({ error: 'user_not_found' });
    if (!user.security_a_hash) return res.status(400).json({ error: 'no_security_question' });
    if (user.banned === 1) return res.status(403).json({ error: 'banned' });

    const norm = normalizeAnswer(answer);
    if (!verifyPassword(norm, user.security_a_hash)) {
      return res.status(401).json({ error: 'wrong_answer' });
    }

    await db.execute({ sql: 'UPDATE users SET password_hash = ? WHERE id = ?', args: [hashPassword(newPassword), user.id] });
    res.json({ ok: true });
  }
);

/* ===== 14. Logout ===== */
app.post('/api/logout', authRequired, async (req, res) => {
  const uid = req.userId;
  await db.execute({ sql: 'UPDATE users SET token_hash = ?, public_key = NULL WHERE id = ?', args: [hashToken('loggedout_' + uid + '_' + Date.now()), uid] });

  const friendsResult = await db.execute({ sql: 'SELECT friend_id FROM friendships WHERE user_id = ?', args: [uid] });
  for (const f of friendsResult.rows) io.to(`u_${f.friend_id}`).emit('user-offline', { userId: uid });

  const sockets = ONLINE_USERS.get(uid);
  if (sockets) for (const sid of sockets) io.to(sid).emit('auth-error', { error: 'session_expired' });
  ONLINE_USERS.delete(uid);

  res.json({ ok: true });
});

/* ===== 15. User routes ===== */
app.get('/api/me', authRequired, (req, res) => res.json({ user: publicUser(req.user, true) }));

app.put('/api/me', authRequired,
  body('display_name').optional().trim().isLength({ min: 2, max: 20 }),
  body('bio').optional().trim().isLength({ max: 200 }),
  body('location').optional().trim().isLength({ max: 100 }),
  body('theme').optional().isIn(['dark', 'light']),
  body('sound').optional().isBoolean(),
  validate,
  async (req, res) => {
    const b = req.body, updates = [], values = [];
    if (b.display_name !== undefined) { updates.push('display_name = ?'); values.push(b.display_name); }
    if (b.bio !== undefined) { updates.push('bio_enc = ?'); values.push(encryptField(b.bio)); }
    if (b.location !== undefined) { updates.push('location_enc = ?'); values.push(encryptField(b.location)); }
    if (b.theme !== undefined) { updates.push('theme = ?'); values.push(b.theme); }
    if (b.sound !== undefined) { updates.push('sound = ?'); values.push(b.sound ? 1 : 0); }
    
    if (updates.length) { 
      values.push(req.userId); 
      await db.execute({ sql: `UPDATE users SET ${updates.join(', ')} WHERE id = ?`, args: values }); 
    }
    const userResult = await db.execute({ sql: 'SELECT * FROM users WHERE id = ?', args: [req.userId] });
    res.json({ user: publicUser(userResult.rows[0], true) });
  }
);

app.put('/api/me/avatar', authRequired,
  body('avatar_id').optional({ nullable: true }).trim().isLength({ max: 10 }),
  validate,
  async (req, res) => {
    const aid = req.body.avatar_id || null;
    if (aid && ALLOWED_AVATARS.indexOf(aid) === -1) return res.status(400).json({ error: 'invalid_avatar' });
    await db.execute({ sql: 'UPDATE users SET avatar_id = ? WHERE id = ?', args: [aid, req.userId] });
    res.json({ ok: true, avatar_id: aid });
  }
);

app.put('/api/me/public-key', authRequired,
  body('public_key').trim().isLength({ min: 40, max: 500 }),
  validate,
  async (req, res) => {
    await db.execute({ sql: 'UPDATE users SET public_key = ? WHERE id = ?', args: [req.body.public_key, req.userId] });
    res.json({ ok: true });
  }
);

app.get('/api/users/:id', authRequired, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'invalid_id' });
  const rowResult = await db.execute({ sql: 'SELECT * FROM users WHERE id = ?', args: [id] });
  const row = rowResult.rows[0];
  if (!row) return res.status(404).json({ error: 'user_not_found' });
  
  const blockResult = await db.execute({ sql: 'SELECT 1 FROM blocks WHERE (blocker_id = ? AND blocked_id = ?) OR (blocker_id = ? AND blocked_id = ?)', args: [req.userId, id, id, req.userId] });
  const friendResult = await db.execute({ sql: 'SELECT 1 FROM friendships WHERE user_id = ? AND friend_id = ?', args: [req.userId, id] });
  
  res.json({ user: publicUser(row), isFriend: friendResult.rows.length > 0, blocked: blockResult.rows.length > 0 });
});

app.get('/api/security-questions', (req, res) => {
  res.json({ questions: SECURITY_QUESTIONS });
});

/* ===== 16. Reports ===== */
app.post('/api/reports', authRequired,
  body('reported_user_id').optional().isInt({ min: 1 }),
  body('reported_msg_id').optional().isInt({ min: 1 }),
  body('reason').trim().isIn(REPORT_REASONS),
  body('note').optional().trim().isLength({ max: 500 }),
  validate,
  async (req, res) => {
    const reporterId = req.userId;
    const { reported_user_id, reported_msg_id, reason, note } = req.body;
    if (!reported_user_id && !reported_msg_id) return res.status(400).json({ error: 'nothing_to_report' });
    if (reported_user_id && reported_user_id === reporterId) return res.status(400).json({ error: 'self_report' });

    let msgSnapshot = null, targetUserId = reported_user_id || null;
    if (reported_msg_id) {
      const msgResult = await db.execute({ sql: 'SELECT * FROM dms WHERE id = ?', args: [reported_msg_id] });
      const msg = msgResult.rows[0];
      if (!msg) return res.status(404).json({ error: 'message_not_found' });
      if (msg.from_id === reporterId) return res.status(400).json({ error: 'own_message' });
      msgSnapshot = msg.text;
      targetUserId = targetUserId || msg.from_id;
    }
    
    let dup;
    if (reported_msg_id) {
      dup = await db.execute({ sql: 'SELECT 1 FROM reports WHERE reporter_id = ? AND reported_msg_id = ? AND status = ?', args: [reporterId, reported_msg_id, 'pending'] });
    } else {
      dup = await db.execute({ sql: 'SELECT 1 FROM reports WHERE reporter_id = ? AND reported_user_id = ? AND status = ? AND reported_msg_id IS NULL', args: [reporterId, targetUserId, 'pending'] });
    }
    if (dup.rows.length > 0) return res.status(429).json({ error: 'already_reported' });

    const insertResult = await db.execute({
      sql: `INSERT INTO reports (reporter_id, reported_user_id, reported_msg_id, reason, note, msg_snapshot, status, created_at) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)`,
      args: [reporterId, targetUserId, reported_msg_id || null, reason, note || null, msgSnapshot, now()]
    });

    const adminsResult = await db.execute('SELECT id FROM users WHERE is_admin = 1 AND deleted = 0');
    const reporterName = req.user.display_name;
    for (const a of adminsResult.rows) io.to(`u_${a.id}`).emit('notification', { type: 'report', text: '🚨 بلاغ جديد من ' + reporterName, reportId: insertResult.lastInsertRowid });
    
    res.json({ ok: true, reportId: insertResult.lastInsertRowid });
  }
);

/* ===== 17. Admin Routes ===== */
app.get('/api/admin/stats', authRequired, adminRequired, async (req, res) => {
  const totalUsers = (await db.execute('SELECT COUNT(*) as c FROM users WHERE deleted = 0')).rows[0].c;
  const activeUsers = (await db.execute({ sql: 'SELECT COUNT(*) as c FROM users WHERE deleted = 0 AND last_seen > ?', args: [Date.now() - 24*60*60*1000] })).rows[0].c;
  const bannedUsers = (await db.execute('SELECT COUNT(*) as c FROM users WHERE banned = 1')).rows[0].c;
  const verifiedUsers = (await db.execute('SELECT COUNT(*) as c FROM users WHERE verified = 1 AND deleted = 0')).rows[0].c;
  const totalMessages = (await db.execute('SELECT COUNT(*) as c FROM dms')).rows[0].c;
  const messages24h = (await db.execute({ sql: 'SELECT COUNT(*) as c FROM dms WHERE time > ?', args: [Date.now() - 24*60*60*1000] })).rows[0].c;
  const totalFriendships = (await db.execute('SELECT COUNT(*) as c FROM friendships')).rows[0].c / 2;
  const pendingReports = (await db.execute({ sql: 'SELECT COUNT(*) as c FROM reports WHERE status = ?', args: ['pending'] })).rows[0].c;
  const totalReports = (await db.execute('SELECT COUNT(*) as c FROM reports')).rows[0].c;
  
  res.json({ totalUsers, activeUsers, bannedUsers, verifiedUsers, totalMessages, messages24h, totalFriendships, pendingReports, totalReports, onlineNow: ONLINE_USERS.size, uptime: process.uptime(), version: '13.3.0' });
});

app.get('/api/admin/users', authRequired, adminRequired, async (req, res) => {
  const q = String(req.query.q || '').trim().slice(0, 50);
  let rows;
  if (q) {
    rows = (await db.execute({ sql: 'SELECT * FROM users WHERE username LIKE ? OR display_name LIKE ? ORDER BY last_seen DESC LIMIT 100', args: [`%${q}%`, `%${q}%`] })).rows;
  } else {
    rows = (await db.execute('SELECT * FROM users ORDER BY last_seen DESC LIMIT 100')).rows;
  }

  const users = [];
  for (const r of rows) {
    const msgCount = (await db.execute({ sql: 'SELECT COUNT(*) as c FROM dms WHERE from_id = ? OR to_id = ?', args: [r.id, r.id] })).rows[0].c;
    const friends = (await db.execute({ sql: 'SELECT COUNT(*) as c FROM friendships WHERE user_id = ?', args: [r.id] })).rows[0].c;
    const reportsAgainst = (await db.execute({ sql: 'SELECT COUNT(*) as c FROM reports WHERE reported_user_id = ? AND status = ?', args: [r.id, 'pending'] })).rows[0].c;
    const u = publicUser(r, true);
    u.msg_count = msgCount; u.friends_count = friends;
    u.has_password = !!r.password_hash;
    u.has_security = !!(r.security_q !== null && r.security_q !== undefined && r.security_a_hash);
    u.reports_against = reportsAgainst;
    users.push(u);
  }
  res.json({ users });
});

app.post('/api/admin/user/:id/ban', authRequired, adminRequired, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'invalid' });
  if (id === req.userId) return res.status(400).json({ error: 'self' });
  const action = req.body && req.body.action;
  const banned = action === 'unban' ? 0 : 1;
  
  await db.execute({ sql: 'UPDATE users SET banned = ? WHERE id = ?', args: [banned, id] });
  
  if (banned === 1) {
    const socks = ONLINE_USERS.get(id);
    if (socks) for (const sid of socks) io.to(sid).emit('auth-error', { error: 'banned' });
    ONLINE_USERS.delete(id);
  }
  res.json({ ok: true, banned: banned === 1 });
});

app.post('/api/admin/user/:id/verify', authRequired, adminRequired, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'invalid' });
  const action = req.body && req.body.action;
  const verified = action === 'unverify' ? 0 : 1;
  
  const userResult = await db.execute({ sql: 'SELECT id FROM users WHERE id = ?', args: [id] });
  if (userResult.rows.length === 0) return res.status(404).json({ error: 'not_found' });
  
  await db.execute({ sql: 'UPDATE users SET verified = ? WHERE id = ?', args: [verified, id] });
  
  const friends = await db.execute({ sql: 'SELECT friend_id FROM friendships WHERE user_id = ?', args: [id] });
  for (const f of friends.rows) io.to(`u_${f.friend_id}`).emit('user-verified', { userId: id, verified: verified === 1 });
  io.to(`u_${id}`).emit('user-verified', { userId: id, verified: verified === 1 });
  
  res.json({ ok: true, verified: verified === 1 });
});

app.delete('/api/admin/user/:id', authRequired, adminRequired, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'invalid' });
  if (id === req.userId) return res.status(400).json({ error: 'self' });
  
  const friendRows = (await db.execute({ sql: 'SELECT friend_id FROM friendships WHERE user_id = ?', args: [id] })).rows;
  
  await db.batch([
    { sql: 'DELETE FROM dms WHERE from_id = ? OR to_id = ?', args: [id, id] },
    { sql: 'DELETE FROM friendships WHERE user_id = ? OR friend_id = ?', args: [id, id] },
    { sql: 'DELETE FROM blocks WHERE blocker_id = ? OR blocked_id = ?', args: [id, id] },
    { sql: 'DELETE FROM push_subs WHERE user_id = ?', args: [id] },
    { sql: 'DELETE FROM users WHERE id = ?', args: [id] }
  ]);
  
  await db.execute({ sql: 'INSERT INTO admin_logs (action_type, details) VALUES (?, ?)', args: ['ACCOUNT_DELETED_BY_ADMIN', `Admin deleted user ID: ${id}`] });
  
  for (const f of friendRows) io.to(`u_${f.friend_id}`).emit('user-deleted', { userId: id });
  const socks = ONLINE_USERS.get(id);
  if (socks) for (const sid of socks) io.to(sid).emit('auth-error', { error: 'session_expired' });
  ONLINE_USERS.delete(id);
  
  res.json({ ok: true });
});

app.post('/api/admin/user/:id/admin', authRequired, adminRequired, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'invalid' });
  if (id === req.userId) return res.status(400).json({ error: 'self' });
  
  const currentResult = await db.execute({ sql: 'SELECT is_admin FROM users WHERE id = ?', args: [id] });
  const current = currentResult.rows[0];
  if (!current) return res.status(404).json({ error: 'not_found' });
  
  const newVal = current.is_admin === 1 ? 0 : 1;
  await db.execute({ sql: 'UPDATE users SET is_admin = ? WHERE id = ?', args: [newVal, id] });
  res.json({ ok: true, is_admin: newVal === 1 });
});

app.post('/api/admin/broadcast', authRequired, adminRequired,
  body('text').trim().isLength({ min: 1, max: 500 }),
  validate,
  async (req, res) => {
    const text = req.body.text;
    const usersResult = await db.execute('SELECT id FROM users WHERE deleted = 0');
    const t = now();
    const senderId = req.userId;
    let sent = 0;
    
    for (const u of usersResult.rows) {
      if (u.id === senderId) continue;
      try {
        const info = await db.execute({ sql: 'INSERT INTO dms (from_id, to_id, text, time, delivered) VALUES (?, ?, ?, ?, 0)', args: [senderId, u.id, '📢 ' + text, t] });
        const msg = { id: info.lastInsertRowid, from_id: senderId, to_id: u.id, text: '📢 ' + text, time: t, delivered: ONLINE_USERS.has(u.id), read: false, edited: false, deleted: false };
        io.to(`u_${u.id}`).emit('dm-message', msg);
        sent++;
      } catch(e) {}
    }
    res.json({ ok: true, sent });
  }
);

app.get('/api/admin/reports', authRequired, adminRequired, async (req, res) => {
  const status = String(req.query.status || 'pending');
  if (['pending', 'resolved', 'dismissed', 'all'].indexOf(status) === -1) return res.status(400).json({ error: 'invalid_status' });
  
  let rows;
  if (status === 'all') rows = (await db.execute('SELECT * FROM reports ORDER BY created_at DESC LIMIT 200')).rows;
  else rows = (await db.execute({ sql: 'SELECT * FROM reports WHERE status = ? ORDER BY created_at DESC LIMIT 200', args: [status] })).rows;

  const reports = [];
  for (const r of rows) {
    const reporter = (await db.execute({ sql: 'SELECT id, username, display_name, color, avatar_id, verified FROM users WHERE id = ?', args: [r.reporter_id] })).rows[0];
    let reported = null;
    if (r.reported_user_id) {
      reported = (await db.execute({ sql: 'SELECT id, username, display_name, color, avatar_id, verified, banned FROM users WHERE id = ?', args: [r.reported_user_id] })).rows[0];
    }
    let msgData = null;
    if (r.reported_msg_id) {
      const m = (await db.execute({ sql: 'SELECT id, from_id, to_id, text, time FROM dms WHERE id = ?', args: [r.reported_msg_id] })).rows[0];
      if (m) msgData = { id: m.id, from_id: m.from_id, to_id: m.to_id, text: m.text, time: m.time };
    }
    reports.push({
      id: r.id,
      reporter: reporter ? { id: reporter.id, username: reporter.username, display_name: reporter.display_name, color: reporter.color, avatar_id: reporter.avatar_id, verified: reporter.verified === 1 } : null,
      reported: reported ? { id: reported.id, username: reported.username, display_name: reported.display_name, color: reported.color, avatar_id: reported.avatar_id, verified: reported.verified === 1, banned: reported.banned === 1 } : null,
      reason: r.reason, note: r.note, msg_snapshot: r.msg_snapshot, msg: msgData,
      status: r.status, created_at: r.created_at, reviewed_at: r.reviewed_at, action: r.action
    });
  }
  res.json({ reports });
});

app.post('/api/admin/reports/:id/resolve', authRequired, adminRequired,
  body('action').optional().isIn(['dismiss', 'ban_user', 'warn']),
  validate,
  async (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (!id) return res.status(400).json({ error: 'invalid' });
    const action = (req.body && req.body.action) || 'dismiss';
    const r = (await db.execute({ sql: 'SELECT * FROM reports WHERE id = ?', args: [id] })).rows[0];
    if (!r) return res.status(404).json({ error: 'not_found' });
    
    if (action === 'ban_user' && r.reported_user_id) {
      await db.execute({ sql: 'UPDATE users SET banned = 1 WHERE id = ?', args: [r.reported_user_id] });
      const socks = ONLINE_USERS.get(r.reported_user_id);
      if (socks) for (const sid of socks) io.to(sid).emit('auth-error', { error: 'banned' });
      ONLINE_USERS.delete(r.reported_user_id);
    }
    const newStatus = action === 'dismiss' ? 'dismissed' : 'resolved';
    await db.execute({ sql: 'UPDATE reports SET status = ?, reviewed_at = ?, reviewed_by = ?, action = ? WHERE id = ?', args: [newStatus, now(), req.userId, action, id] });
    res.json({ ok: true, status: newStatus, action });
  }
);

app.delete('/api/admin/reports/:id', authRequired, adminRequired, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'invalid' });
  await db.execute({ sql: 'DELETE FROM reports WHERE id = ?', args: [id] });
  res.json({ ok: true });
});

/* ===== 18. QR ===== */
app.get('/api/qr/image', authRequired, async (req, res) => {
  try {
    const link = `${PUBLIC_URL}/?qr=${req.user.qr_id}`;
    const dataUrl = await QRCode.toDataURL(link, { width: 512, margin: 2, color: { dark: '#0b0d14', light: '#ffffff' } });
    res.json({ qr: dataUrl, link, qr_id: req.user.qr_id });
  } catch (e) { res.status(500).json({ error: 'qr_failed' }); }
});

/* ===== 19. Friends ===== */
app.post('/api/friends/add-by-qr', authRequired,
  body('qr_id').trim().isLength({ min: 8, max: 32 }).matches(/^[a-z0-9]+$/i),
  validate,
  async (req, res) => {
    const qrId = req.body.qr_id.toLowerCase();
    const target = (await db.execute({ sql: 'SELECT * FROM users WHERE qr_id = ? AND deleted = 0', args: [qrId] })).rows[0];
    if (!target) return res.status(404).json({ error: 'user_not_found' });
    if (target.id === req.userId) return res.status(400).json({ error: 'self' });
    
    const blocked = (await db.execute({ sql: 'SELECT 1 FROM blocks WHERE (blocker_id = ? AND blocked_id = ?) OR (blocker_id = ? AND blocked_id = ?)', args: [req.userId, target.id, target.id, req.userId] })).rows.length > 0;
    if (blocked) return res.status(403).json({ error: 'blocked' });
    
    const existing = (await db.execute({ sql: 'SELECT 1 FROM friendships WHERE user_id = ? AND friend_id = ?', args: [req.userId, target.id] })).rows.length > 0;
    if (existing) return res.json({ status: 'already_friends', user: publicUser(target) });

    const t = now();
    await db.batch([
      { sql: 'INSERT OR IGNORE INTO friendships (user_id, friend_id, status, time) VALUES (?, ?, ?, ?)', args: [req.userId, target.id, 'accepted', t] },
      { sql: 'INSERT OR IGNORE INTO friendships (user_id, friend_id, status, time) VALUES (?, ?, ?, ?)', args: [target.id, req.userId, 'accepted', t] }
    ]);
    
    io.to(`u_${target.id}`).emit('notification', { type: 'friend_added', text: `${req.user.display_name} أضافك كصديق`, from: publicUser(req.user) });
    res.json({ status: 'added', user: publicUser(target) });
  }
);

/* ===== 20. DM ===== */
app.get('/api/dm-conversations', authRequired, async (req, res) => {
  const rows = (await db.execute({
    sql: `SELECT CASE WHEN from_id = ? THEN to_id ELSE from_id END AS other_id, MAX(time) AS last_time
          FROM dms WHERE from_id = ? OR to_id = ?
          GROUP BY other_id ORDER BY last_time DESC LIMIT 100`,
    args: [req.userId, req.userId, req.userId]
  })).rows;

  const conversations = [];
  for (const r of rows) {
    const user = (await db.execute({ sql: 'SELECT * FROM users WHERE id = ?', args: [r.other_id] })).rows[0];
    if (!user) continue;
    const last = (await db.execute({ sql: 'SELECT id, text, time, deleted FROM dms WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?) ORDER BY time DESC LIMIT 1', args: [req.userId, r.other_id, r.other_id, req.userId] })).rows[0];
    const unread = (await db.execute({ sql: 'SELECT COUNT(*) as c FROM dms WHERE from_id = ? AND to_id = ? AND read = 0', args: [r.other_id, req.userId] })).rows[0].c;
    conversations.push({ user: publicUser(user), last: last ? { text: last.deleted === 1 ? '' : last.text, time: last.time, deleted: last.deleted === 1 } : null, unread });
  }
  res.json({ conversations });
});

app.get('/api/dms/:userId', authRequired, async (req, res) => {
  const otherId = parseInt(req.params.userId, 10);
  if (!otherId) return res.status(400).json({ error: 'invalid' });
  const rows = (await db.execute({ sql: 'SELECT * FROM dms WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?) ORDER BY time ASC LIMIT 500', args: [req.userId, otherId, otherId, req.userId] })).rows;
  
  await db.execute({ sql: 'UPDATE dms SET read = 1 WHERE from_id = ? AND to_id = ? AND read = 0', args: [otherId, req.userId] });
  io.to(`u_${otherId}`).emit('dm-read-receipt', { byId: req.userId });
  res.json({ messages: rows.map(mapMessage) });
});

app.delete('/api/dm-conversations/:userId', authRequired, async (req, res) => {
  const otherId = parseInt(req.params.userId, 10);
  if (!otherId) return res.status(400).json({ error: 'invalid' });
  await db.execute({ sql: 'DELETE FROM dms WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?)', args: [req.userId, otherId, otherId, req.userId] });
  io.to(`u_${otherId}`).emit('dm-conversation-deleted', { byId: req.userId });
  res.json({ ok: true });
});

app.put('/api/dms/:messageId', authRequired,
  body('text').trim().isLength({ min: 1, max: 10000 }),
  validate,
  async (req, res) => {
    const msgId = parseInt(req.params.messageId, 10);
    if (!msgId) return res.status(400).json({ error: 'invalid' });
    const msg = (await db.execute({ sql: 'SELECT * FROM dms WHERE id = ?', args: [msgId] })).rows[0];
    if (!msg) return res.status(404).json({ error: 'not_found' });
    if (msg.from_id !== req.userId) return res.status(403).json({ error: 'forbidden' });
    if (msg.deleted === 1) return res.status(400).json({ error: 'already_deleted' });
    
    await db.execute({ sql: 'UPDATE dms SET text = ?, edited = 1 WHERE id = ?', args: [req.body.text, msgId] });
    io.to(`u_${msg.to_id}`).emit('dm-edited', { id: msgId, text: req.body.text, edited: true, byId: req.userId });
    res.json({ ok: true });
  }
);

app.delete('/api/dms/:messageId', authRequired, async (req, res) => {
  const msgId = parseInt(req.params.messageId, 10);
  if (!msgId) return res.status(400).json({ error: 'invalid' });
  const msg = (await db.execute({ sql: 'SELECT * FROM dms WHERE id = ?', args: [msgId] })).rows[0];
  if (!msg) return res.status(404).json({ error: 'not_found' });
  if (msg.from_id !== req.userId) return res.status(403).json({ error: 'forbidden' });
  if (msg.deleted === 1) return res.json({ ok: true });
  
  await db.execute({ sql: 'UPDATE dms SET deleted = 1, text = ? WHERE id = ?', args: ['', msgId] });
  io.to(`u_${msg.to_id}`).emit('dm-deleted', { id: msgId, byId: req.userId });
  res.json({ ok: true });
});

/* ===== 21. Upload ===== */
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

/* ===== 22. Push ===== */
let pushEnabled = false;
if (process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY) {
  webpush.setVapidDetails(process.env.VAPID_SUBJECT || 'mailto:admin@dust.app', process.env.VAPID_PUBLIC_KEY, process.env.VAPID_PRIVATE_KEY);
  pushEnabled = true;
  console.log('✅ Web Push enabled');
}
app.get('/api/vapid-public', (req, res) => res.json({ key: process.env.VAPID_PUBLIC_KEY || null }));
app.post('/api/push/subscribe', authRequired, async (req, res) => {
  const sub = req.body;
  if (!sub || !sub.endpoint) return res.status(400).json({ error: 'invalid' });
  await db.execute({
    sql: `INSERT INTO push_subs (user_id, endpoint, p256dh, auth, time) VALUES (?, ?, ?, ?, ?) ON CONFLICT(endpoint) DO UPDATE SET user_id = excluded.user_id`,
    args: [req.userId, sub.endpoint, sub.keys ? sub.keys.p256dh : '', sub.keys ? sub.keys.auth : '', now()]
  });
  res.json({ ok: true });
});
async function sendPush(userId, payload) {
  if (!pushEnabled) return;
  const subs = (await db.execute({ sql: 'SELECT * FROM push_subs WHERE user_id = ?', args: [userId] })).rows;
  const dead = [];
  for (const s of subs) {
    try { await webpush.sendNotification({ endpoint: s.endpoint, keys: { p256dh: s.p256dh, auth: s.auth } }, JSON.stringify(payload)); }
    catch (e) { if (e.statusCode === 404 || e.statusCode === 410) dead.push(s.id); }
  }
  for (const id of dead) await db.execute({ sql: 'DELETE FROM push_subs WHERE id = ?', args: [id] });
}

/* ===== 23. Socket.io ===== */
async function verifyToken(token) {
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const row = (await db.execute({ sql: 'SELECT * FROM users WHERE id = ? AND deleted = 0', args: [decoded.id] })).rows[0];
    if (!row) return { error: 'user_not_found' };
    if (row.token_hash !== hashToken(token)) return { error: 'session_expired' };
    if (row.banned === 1) return { error: 'banned' };
    return { user: row };
  } catch (e) { return { error: 'invalid_token' }; }
}

async function activateSocket(socket, row) {
  if (socket.userId) { try { socket.leave(`u_${socket.userId}`); } catch(_){} }
  socket.userId = row.id;
  socket.user = row;
  socket.join(`u_${row.id}`);
  
  if (!ONLINE_USERS.has(row.id)) ONLINE_USERS.set(row.id, new Set());
  ONLINE_USERS.get(row.id).add(socket.id);
  
  const friends = (await db.execute({ sql: 'SELECT friend_id FROM friendships WHERE user_id = ?', args: [row.id] })).rows;
  for (const f of friends) io.to(`u_${f.friend_id}`).emit('user-online', { userId: row.id });
  
  await db.execute({ sql: 'UPDATE users SET last_seen = ? WHERE id = ?', args: [now(), row.id] });
  socket.emit('auth-ok', { user: publicUser(row, true) });
}

io.on('connection', (socket) => {
  const handshakeToken = (socket.handshake.auth && socket.handshake.auth.token) || (socket.handshake.query && socket.handshake.query.token);
  
  if (handshakeToken) {
    verifyToken(handshakeToken).then(result => {
      if (result.error) socket.emit('auth-error', { error: result.error });
      else activateSocket(socket, result.user);
    });
  }
  
  socket.on('auth', async (data) => {
    const token = data && data.token;
    if (!token) { socket.emit('auth-error', { error: 'auth_required' }); return; }
    const result = await verifyToken(token);
    if (result.error) { socket.emit('auth-error', { error: result.error }); return; }
    await activateSocket(socket, result.user);
  });

  socket.on('dm-send', async (data) => {
    if (!socket.userId) return;
    try {
      if (!data || typeof data.toId !== 'number' || typeof data.text !== 'string') return;
      if (data.text.length === 0 || data.text.length > 10000) return;
      const userId = socket.userId, toId = data.toId;
      
      const blocked = (await db.execute({ sql: 'SELECT 1 FROM blocks WHERE (blocker_id = ? AND blocked_id = ?) OR (blocker_id = ? AND blocked_id = ?)', args: [userId, toId, toId, userId] })).rows.length > 0;
      if (blocked) return;
      
      const target = (await db.execute({ sql: 'SELECT id, deleted FROM users WHERE id = ?', args: [toId] })).rows[0];
      if (!target || target.deleted === 1) return;
      
      const t = now();
      const isOnline = ONLINE_USERS.has(toId);
      const info = await db.execute({ sql: 'INSERT INTO dms (from_id, to_id, text, time, delivered) VALUES (?, ?, ?, ?, ?)', args: [userId, toId, data.text, t, isOnline ? 1 : 0] });
      
      const msg = { id: info.lastInsertRowid, from_id: userId, to_id: toId, text: data.text, time: t, delivered: isOnline, read: false, edited: false, deleted: false };
      io.to(`u_${toId}`).emit('dm-message', msg);
      socket.emit('dm-message', msg);
      
      if (isOnline) socket.emit('dm-delivered', { id: msg.id });
      else sendPush(toId, { title: 'Dust', body: 'رسالة جديدة', tag: 'dm_' + userId }).catch(() => {});
    } catch (e) { console.error('dm-send error:', e); }
  });

  socket.on('dm-read', async (data) => {
    if (!socket.userId || !data || typeof data.fromId !== 'number') return;
    await db.execute({ sql: 'UPDATE dms SET read = 1 WHERE from_id = ? AND to_id = ? AND read = 0', args: [data.fromId, socket.userId] });
    io.to(`u_${data.fromId}`).emit('dm-read-receipt', { byId: socket.userId });
  });

  socket.on('dm-typing', (data) => {
    if (!socket.userId || !data || typeof data.toId !== 'number') return;
    io.to(`u_${data.toId}`).emit('dm-typing', { fromId: socket.userId, isTyping: !!data.isTyping });
  });

  socket.on('disconnect', async () => {
    if (!socket.userId) return;
    const userId = socket.userId;
    const set = ONLINE_USERS.get(userId);
    if (set) {
      set.delete(socket.id);
      if (set.size === 0) {
        ONLINE_USERS.delete(userId);
        await db.execute({ sql: 'UPDATE users SET last_seen = ? WHERE id = ?', args: [now(), userId] });
        const friends = (await db.execute({ sql: 'SELECT friend_id FROM friendships WHERE user_id = ?', args: [userId] })).rows;
        for (const f of friends) io.to(`u_${f.friend_id}`).emit('user-offline', { userId });
      }
    }
  });
});

/* ===== 24. Cleanup ===== */
setInterval(async () => {
  const cutoff = now() - (48 * 60 * 60 * 1000);
  const r = await db.execute({ sql: 'DELETE FROM dms WHERE time < ? AND read = 1', args: [cutoff] });
  if (r.rowsAffected > 0) console.log(`🧹 Cleaned ${r.rowsAffected} messages`);
}, 60 * 60 * 1000);

/* ===== 25. Health ===== */
app.get('/health', async (req, res) => {
  try {
    res.json({
      ok: true, uptime: process.uptime(),
      users: (await db.execute('SELECT COUNT(*) as c FROM users WHERE deleted = 0')).rows[0].c,
      admins: (await db.execute('SELECT COUNT(*) as c FROM users WHERE is_admin = 1')).rows[0].c,
      verified: (await db.execute('SELECT COUNT(*) as c FROM users WHERE verified = 1 AND deleted = 0')).rows[0].c,
      with_password: (await db.execute('SELECT COUNT(*) as c FROM users WHERE deleted = 0 AND password_hash IS NOT NULL')).rows[0].c,
      with_security: (await db.execute('SELECT COUNT(*) as c FROM users WHERE deleted = 0 AND security_a_hash IS NOT NULL')).rows[0].c,
      pending_reports: (await db.execute({ sql: 'SELECT COUNT(*) as c FROM reports WHERE status = ?', args: ['pending'] })).rows[0].c,
      online: ONLINE_USERS.size,
      version: '13.3.0'
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

/* ===== 26. Fallback ===== */
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

/* ===== 27. Start ===== */
initDb().then(() => {
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Dust Server v13.3.0 on port ${PORT}`);
    console.log(`🔗 ${PUBLIC_URL}`);
    console.log(`🔐 Password: scrypt (N=${SCRYPT_N})`);
    console.log(`🛡️  Recovery: ${SECURITY_QUESTIONS.length} questions`);
    console.log(`🎨 Avatars: ${ALLOWED_AVATARS.length}`);
    console.log(`📦 DB: Turso Cloud Database`);
  });
}).catch(err => {
  console.error('❌ Failed to initialize database:', err);
  process.exit(1);
});

process.on('SIGTERM', () => { server.close(() => { process.exit(0); }); });
process.on('SIGINT', () => { server.close(() => { process.exit(0); }); });
