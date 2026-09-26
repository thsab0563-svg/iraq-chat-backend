/* ============================================================
   Dust Server v7.0 — خادم دردشة مشفر مع حماية شاملة
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
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const multer = require('multer');
const webpush = require('web-push');
const QRCode = require('qrcode');
const cors = require('cors');
const { nanoid } = require('nanoid');

/* ============================================================
   1. التحقق من متغيرات البيئة
   ============================================================ */
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error('❌ JWT_SECRET مفقود أو قصير جداً! يجب أن يكون 32 حرفاً على الأقل.');
  process.exit(1);
}

const DB_KEY_HEX = process.env.DB_ENCRYPTION_KEY;
if (!DB_KEY_HEX || DB_KEY_HEX.length !== 32) {
  console.error('❌ DB_ENCRYPTION_KEY يجب أن يكون 32 حرفاً بالضبط.');
  process.exit(1);
}
const DB_KEY = Buffer.from(DB_KEY_HEX, 'utf8');

const PUBLIC_URL = process.env.PUBLIC_URL || 'http://localhost:8080';
const PORT = parseInt(process.env.PORT || '8080', 10);
const DB_PATH = process.env.DB_PATH || './dust.db';

/* ============================================================
   2. تهيئة قاعدة البيانات
   ============================================================ */
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
  theme TEXT DEFAULT 'dark',
  sound INTEGER DEFAULT 1,
  created_at INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  deleted INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_users_qr ON users(qr_id);
CREATE INDEX IF NOT EXISTS idx_users_token ON users(token_hash);

CREATE TABLE IF NOT EXISTS posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  text TEXT NOT NULL,
  edited INTEGER DEFAULT 0,
  time INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_posts_user ON posts(user_id);
CREATE INDEX IF NOT EXISTS idx_posts_time ON posts(time DESC);

CREATE TABLE IF NOT EXISTS likes (
  post_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  time INTEGER NOT NULL,
  PRIMARY KEY (post_id, user_id),
  FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  post_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  text TEXT NOT NULL,
  time INTEGER NOT NULL,
  FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_comments_post ON comments(post_id);

CREATE TABLE IF NOT EXISTS friendships (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  friend_id INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'accepted',
  time INTEGER NOT NULL,
  UNIQUE(user_id, friend_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (friend_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS blocks (
  blocker_id INTEGER NOT NULL,
  blocked_id INTEGER NOT NULL,
  time INTEGER NOT NULL,
  PRIMARY KEY (blocker_id, blocked_id),
  FOREIGN KEY (blocker_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (blocked_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS dms (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  from_id INTEGER NOT NULL,
  to_id INTEGER NOT NULL,
  text TEXT NOT NULL,
  time INTEGER NOT NULL,
  delivered INTEGER DEFAULT 0,
  read INTEGER DEFAULT 0,
  FOREIGN KEY (from_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (to_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_dms_from_to ON dms(from_id, to_id, time);
CREATE INDEX IF NOT EXISTS idx_dms_to ON dms(to_id, read);

CREATE TABLE IF NOT EXISTS push_subs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  endpoint TEXT NOT NULL UNIQUE,
  p256dh TEXT NOT NULL,
  auth TEXT NOT NULL,
  time INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_push_user ON push_subs(user_id);

CREATE TABLE IF NOT EXISTS hashtags (
  post_id INTEGER NOT NULL,
  tag TEXT NOT NULL,
  FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_hashtags_tag ON hashtags(tag);
`);

console.log('✅ Database initialized');

/* ============================================================
   3. أدوات التشفير (AES-256-GCM للبيانات الحساسة)
   ============================================================ */
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
  } catch (e) {
    return null;
  }
}

/* ============================================================
   4. أدوات مساعدة
   ============================================================ */
function now() { return Date.now(); }

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function generateToken() {
  return crypto.randomBytes(48).toString('base64url');
}

function publicUser(row, includePrivate = false) {
  if (!row) return null;
  const u = {
    id: row.id,
    username: row.username,
    display_name: row.display_name,
    color: row.color,
    avatar: row.avatar,
    cover: row.cover,
    qr_id: row.qr_id,
    created_at: row.created_at,
    last_seen: row.last_seen,
    online: ONLINE_USERS.has(row.id)
  };
  if (includePrivate) {
    u.bio = decryptField(row.bio_enc);
    u.location = decryptField(row.location_enc);
    u.theme = row.theme;
    u.sound = !!row.sound;
  } else {
    u.bio = decryptField(row.bio_enc);
    u.location = decryptField(row.location_enc);
  }
  return u;
}

function extractHashtags(text) {
  const tags = [];
  const re = /#([\u0600-\u06FF\w_]{1,40})/g;
  let m;
  while ((m = re.exec(text)) !== null) tags.push(m[1].toLowerCase());
  return [...new Set(tags)];
}

/* ============================================================
   5. Express setup
   ============================================================ */
const app = express();
app.set('trust proxy', 1); // مهم لـ Railway

app.use(helmet({
  contentSecurityPolicy: false, // نستخدم CSP في HTML
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: 'cross-origin' }
}));

app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    cb(null, true); // اسمح للجميع (التطبيق عام)
  },
  credentials: true
}));

app.use(express.json({ limit: '256kb' }));
app.use(express.urlencoded({ extended: true, limit: '256kb' }));

// تقديم الملفات الثابتة
const PUBLIC_DIR = path.join(__dirname, 'public');
if (fs.existsSync(PUBLIC_DIR)) {
  app.use(express.static(PUBLIC_DIR, {
    maxAge: '1h',
    setHeaders: (res, p) => {
      if (p.endsWith('.html')) res.setHeader('Cache-Control', 'no-cache');
    }
  }));
}

// مجلد الرفع
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
app.use('/uploads', express.static(UPLOAD_DIR, { maxAge: '7d' }));

/* ============================================================
   6. Rate Limiting
   ============================================================ */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'too_many_requests' },
  standardHeaders: true,
  legacyHeaders: false
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 180,
  message: { error: 'rate_limit_exceeded' },
  standardHeaders: true,
  legacyHeaders: false
});

const dmLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  keyGenerator: (req) => req.userId ? String(req.userId) : req.ip,
  message: { error: 'slow_down' }
});

app.use('/api/', apiLimiter);
app.use('/api/register', authLimiter);

/* ============================================================
   7. JWT Middleware
   ============================================================ */
function authRequired(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'auth_required' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const row = db.prepare('SELECT * FROM users WHERE id = ? AND deleted = 0').get(decoded.id);
    if (!row) return res.status(401).json({ error: 'user_not_found' });

    // تحقق من token_hash (للسماح بإبطال الجلسة)
    if (row.token_hash !== hashToken(token)) {
      return res.status(401).json({ error: 'session_expired' });
    }

    req.userId = row.id;
    req.user = row;
    req.token = token;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'invalid_token' });
  }
}

function optionalAuth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const row = db.prepare('SELECT * FROM users WHERE id = ? AND deleted = 0').get(decoded.id);
      if (row && row.token_hash === hashToken(token)) {
        req.userId = row.id;
        req.user = row;
      }
    } catch (_) {}
  }
  next();
}

/* ============================================================
   8. Input Validation Middleware
   ============================================================ */
function validate(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ error: 'invalid_input', details: errors.array() });
  }
  next();
}

/* ============================================================
   9. Auth Routes
   ============================================================ */
app.post('/api/register',
  body('name').trim().isLength({ min: 2, max: 20 }).escape(),
  body('color').optional().matches(/^#[0-9a-f]{6}$/i),
  validate,
  (req, res) => {
    const { name, color } = req.body;

    // توليد username فريد
    let username;
    let isDuplicate = false;
    for (let i = 0; i < 5; i++) {
      username = name.toLowerCase().replace(/\s+/g, '_').replace(/[^a-z0-9_\u0600-\u06FF]/g, '') || 'user';
      if (username.length < 3) username = 'user';
      username = username.slice(0, 14);
      const suffix = Math.floor(Math.random() * 9999).toString().padStart(4, '0');
      const candidate = username + suffix;
      const exists = db.prepare('SELECT id FROM users WHERE username = ?').get(candidate);
      if (!exists) { username = candidate; break; }
      if (i === 4) isDuplicate = true;
    }

    const qrId = nanoid(16).toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 16);
    const token = generateToken();
    const tokenHash = hashToken(token);

    const info = db.prepare(`
      INSERT INTO users (username, display_name, color, qr_id, token_hash, created_at, last_seen)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(username, name, color || '#e8b567', qrId, tokenHash, now(), now());

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);
    const jwtToken = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '365d' });

    res.json({
      token: jwtToken,
      user: publicUser(user, true),
      isDuplicate
    });
  }
);

app.post('/api/logout', authRequired, (req, res) => {
  // حذف الحساب نهائياً (كما في التطبيق الأصلي)
  const userId = req.userId;
  db.prepare('UPDATE users SET deleted = 1 WHERE id = ?').run(userId);
  // إعلام المتصلين
  io.emit('user-deleted', { userId });
  res.json({ ok: true });
});

/* ============================================================
   10. User Routes
   ============================================================ */
app.get('/api/me', authRequired, (req, res) => {
  res.json({ user: publicUser(req.user, true) });
});

app.put('/api/me', authRequired,
  body('display_name').optional().trim().isLength({ min: 2, max: 20 }).escape(),
  body('bio').optional().trim().isLength({ max: 200 }),
  body('location').optional().trim().isLength({ max: 100 }),
  body('theme').optional().isIn(['dark', 'light']),
  body('sound').optional().isBoolean(),
  body('avatar').optional().isString().isLength({ max: 500 }),
  body('cover').optional().isString().isLength({ max: 500 }),
  validate,
  (req, res) => {
    const b = req.body;
    const updates = [];
    const values = [];

    if (b.display_name !== undefined) { updates.push('display_name = ?'); values.push(b.display_name); }
    if (b.bio !== undefined) { updates.push('bio_enc = ?'); values.push(encryptField(b.bio)); }
    if (b.location !== undefined) { updates.push('location_enc = ?'); values.push(encryptField(b.location)); }
    if (b.theme !== undefined) { updates.push('theme = ?'); values.push(b.theme); }
    if (b.sound !== undefined) { updates.push('sound = ?'); values.push(b.sound ? 1 : 0); }
    if (b.avatar !== undefined) { updates.push('avatar = ?'); values.push(b.avatar); }
    if (b.cover !== undefined) { updates.push('cover = ?'); values.push(b.cover); }

    if (updates.length) {
      values.push(req.userId);
      db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).run(...values);
    }

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.userId);
    res.json({ user: publicUser(user, true) });
  }
);

app.get('/api/users/:id', authRequired, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'invalid_id' });

  const row = db.prepare('SELECT * FROM users WHERE id = ? AND deleted = 0').get(id);
  if (!row) return res.status(404).json({ error: 'user_not_found' });

  // فحص الحظر
  const blocked = !!db.prepare(
    'SELECT 1 FROM blocks WHERE (blocker_id = ? AND blocked_id = ?) OR (blocker_id = ? AND blocked_id = ?)'
  ).get(req.userId, id, id, req.userId);

  // فحص الصداقة
  const isFriend = !!db.prepare(
    'SELECT 1 FROM friendships WHERE user_id = ? AND friend_id = ? AND status = ?'
  ).get(req.userId, id, 'accepted');

  // إحصائيات
  const stats = {
    friends: db.prepare('SELECT COUNT(*) as c FROM friendships WHERE (user_id = ? OR friend_id = ?) AND status = ?').get(id, id, 'accepted').c,
    posts: db.prepare('SELECT COUNT(*) as c FROM posts WHERE user_id = ?').get(id).c
  };

  res.json({ user: publicUser(row), isFriend, blocked, stats });
});

app.get('/api/users/search', authRequired, (req, res) => {
  const q = String(req.query.q || '').trim().slice(0, 50);
  if (!q) return res.json({ users: [] });

  const rows = db.prepare(`
    SELECT * FROM users
    WHERE deleted = 0 AND (display_name LIKE ? OR username LIKE ?)
    LIMIT 30
  `).all(`%${q}%`, `%${q}%`);

  res.json({ users: rows.map(r => publicUser(r)) });
});

app.get('/api/suggestions', authRequired, (req, res) => {
  const rows = db.prepare(`
    SELECT * FROM users
    WHERE deleted = 0 AND id != ?
    AND id NOT IN (SELECT friend_id FROM friendships WHERE user_id = ?)
    AND id NOT IN (SELECT blocker_id FROM blocks WHERE blocked_id = ?)
    AND id NOT IN (SELECT blocked_id FROM blocks WHERE blocker_id = ?)
    ORDER BY last_seen DESC LIMIT 10
  `).all(req.userId, req.userId, req.userId, req.userId);

  res.json({ users: rows.map(r => publicUser(r)) });
});

app.get('/api/me/stats', authRequired, (req, res) => {
  const friends = db.prepare(
    'SELECT COUNT(*) as c FROM friendships WHERE (user_id = ? OR friend_id = ?) AND status = ?'
  ).get(req.userId, req.userId, 'accepted').c;

  const posts = db.prepare('SELECT COUNT(*) as c FROM posts WHERE user_id = ?').get(req.userId).c;

  res.json({ friends, posts });
});

/* ============================================================
   11. QR Routes
   ============================================================ */
app.get('/api/qr/image', authRequired, async (req, res) => {
  try {
    const link = `${PUBLIC_URL}/?qr=${req.user.qr_id}`;
    const dataUrl = await QRCode.toDataURL(link, {
      width: 512,
      margin: 2,
      color: { dark: '#0b0d14', light: '#ffffff' }
    });
    res.json({ qr: dataUrl, link, qr_id: req.user.qr_id });
  } catch (e) {
    res.status(500).json({ error: 'qr_failed' });
  }
});

/* ============================================================
   12. Friends Routes
   ============================================================ */
app.post('/api/friends/add-by-qr', authRequired,
  body('qr_id').trim().isLength({ min: 8, max: 32 }).matches(/^[a-f0-9]+$/i),
  validate,
  (req, res) => {
    const qrId = req.body.qr_id.toLowerCase();
    const target = db.prepare('SELECT * FROM users WHERE qr_id = ? AND deleted = 0').get(qrId);
    if (!target) return res.status(404).json({ error: 'user_not_found' });
    if (target.id === req.userId) return res.status(400).json({ error: 'self' });

    // فحص الحظر
    const blocked = db.prepare(
      'SELECT 1 FROM blocks WHERE (blocker_id = ? AND blocked_id = ?) OR (blocker_id = ? AND blocked_id = ?)'
    ).get(req.userId, target.id, target.id, req.userId);
    if (blocked) return res.status(403).json({ error: 'blocked' });

    // فحص الصداقة الحالية
    const existing = db.prepare(
      'SELECT 1 FROM friendships WHERE user_id = ? AND friend_id = ?'
    ).get(req.userId, target.id);

    if (existing) {
      return res.json({ status: 'already_friends', user: publicUser(target) });
    }

    // إضافة ثنائية الاتجاه
    const t = now();
    const tx = db.transaction(() => {
      db.prepare('INSERT OR IGNORE INTO friendships (user_id, friend_id, status, time) VALUES (?, ?, ?, ?)')
        .run(req.userId, target.id, 'accepted', t);
      db.prepare('INSERT OR IGNORE INTO friendships (user_id, friend_id, status, time) VALUES (?, ?, ?, ?)')
        .run(target.id, req.userId, 'accepted', t);
    });
    tx();

    // إشعار الطرف الآخر
    io.to(`u_${target.id}`).emit('notification', {
      type: 'friend_added',
      text: `${req.user.display_name} أضافك كصديق`,
      from: publicUser(req.user)
    });

    res.json({ status: 'added', user: publicUser(target) });
  }
);

app.post('/api/friends/request/:id', authRequired, (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  if (!targetId || targetId === req.userId) return res.status(400).json({ error: 'invalid' });

  const target = db.prepare('SELECT id FROM users WHERE id = ? AND deleted = 0').get(targetId);
  if (!target) return res.status(404).json({ error: 'user_not_found' });

  const t = now();
  const tx = db.transaction(() => {
    db.prepare('INSERT OR IGNORE INTO friendships (user_id, friend_id, status, time) VALUES (?, ?, ?, ?)')
      .run(req.userId, targetId, 'accepted', t);
    db.prepare('INSERT OR IGNORE INTO friendships (user_id, friend_id, status, time) VALUES (?, ?, ?, ?)')
      .run(targetId, req.userId, 'accepted', t);
  });
  tx();

  res.json({ ok: true });
});

app.get('/api/friends', authRequired, (req, res) => {
  const rows = db.prepare(`
    SELECT u.* FROM users u
    INNER JOIN friendships f ON (f.friend_id = u.id AND f.user_id = ?)
    WHERE u.deleted = 0 AND f.status = 'accepted'
    ORDER BY u.last_seen DESC
  `).all(req.userId);

  res.json({ friends: rows.map(r => publicUser(r)) });
});

app.delete('/api/friends/:id', authRequired, (req, res) => {
  const friendId = parseInt(req.params.id, 10);
  if (!friendId) return res.status(400).json({ error: 'invalid' });

  const tx = db.transaction(() => {
    db.prepare('DELETE FROM friendships WHERE user_id = ? AND friend_id = ?').run(req.userId, friendId);
    db.prepare('DELETE FROM friendships WHERE user_id = ? AND friend_id = ?').run(friendId, req.userId);
  });
  tx();

  res.json({ ok: true });
});

/* ============================================================
   13. Block Routes
   ============================================================ */
app.post('/api/block/:id', authRequired, (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  if (!targetId || targetId === req.userId) return res.status(400).json({ error: 'invalid' });

  db.prepare('INSERT OR IGNORE INTO blocks (blocker_id, blocked_id, time) VALUES (?, ?, ?)')
    .run(req.userId, targetId, now());

  // إزالة الصداقة
  db.prepare('DELETE FROM friendships WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)')
    .run(req.userId, targetId, targetId, req.userId);

  res.json({ ok: true });
});

app.post('/api/unblock/:id', authRequired, (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  db.prepare('DELETE FROM blocks WHERE blocker_id = ? AND blocked_id = ?').run(req.userId, targetId);
  res.json({ ok: true });
});

/* ============================================================
   14. Posts Routes
   ============================================================ */
app.get('/api/posts', optionalAuth, (req, res) => {
  const { hashtag, user_id, limit } = req.query;
  let rows;

  if (hashtag) {
    const tag = String(hashtag).toLowerCase().slice(0, 40);
    rows = db.prepare(`
      SELECT p.* FROM posts p
      INNER JOIN hashtags h ON h.post_id = p.id
      WHERE h.tag = ?
      ORDER BY p.time DESC LIMIT 100
    `).all(tag);
  } else if (user_id) {
    const uid = parseInt(user_id, 10);
    rows = db.prepare('SELECT * FROM posts WHERE user_id = ? ORDER BY time DESC LIMIT ?')
      .all(uid, Math.min(parseInt(limit) || 50, 200));
  } else {
    rows = db.prepare('SELECT * FROM posts ORDER BY time DESC LIMIT 100').all();
  }

  const posts = rows.map(p => {
    const author = db.prepare('SELECT * FROM users WHERE id = ?').get(p.user_id);
    const likes = db.prepare('SELECT COUNT(*) as c FROM likes WHERE post_id = ?').get(p.id).c;
    const comments = db.prepare('SELECT COUNT(*) as c FROM comments WHERE post_id = ?').get(p.id).c;
    const liked = req.userId ? !!db.prepare('SELECT 1 FROM likes WHERE post_id = ? AND user_id = ?').get(p.id, req.userId) : false;

    return {
      id: p.id,
      text: p.text,
      edited: !!p.edited,
      time: p.time,
      user: publicUser(author),
      likes,
      comments,
      liked
    };
  });

  res.json({ posts });
});

app.post('/api/posts', authRequired, dmLimiter,
  body('text').trim().isLength({ min: 1, max: 1000 }),
  validate,
  (req, res) => {
    const text = req.body.text;
    const t = now();
    const info = db.prepare('INSERT INTO posts (user_id, text, time) VALUES (?, ?, ?)')
      .run(req.userId, text, t);

    // استخراج hashtags
    const tags = extractHashtags(text);
    const insertTag = db.prepare('INSERT INTO hashtags (post_id, tag) VALUES (?, ?)');
    for (const tag of tags) insertTag.run(info.lastInsertRowid, tag);

    res.json({ id: info.lastInsertRowid, ok: true });
  }
);

app.put('/api/posts/:id', authRequired,
  body('text').trim().isLength({ min: 1, max: 1000 }),
  validate,
  (req, res) => {
    const id = parseInt(req.params.id, 10);
    const post = db.prepare('SELECT * FROM posts WHERE id = ?').get(id);
    if (!post) return res.status(404).json({ error: 'not_found' });
    if (post.user_id !== req.userId) return res.status(403).json({ error: 'forbidden' });

    db.prepare('UPDATE posts SET text = ?, edited = 1 WHERE id = ?').run(req.body.text, id);
    db.prepare('DELETE FROM hashtags WHERE post_id = ?').run(id);
    const tags = extractHashtags(req.body.text);
    const insertTag = db.prepare('INSERT INTO hashtags (post_id, tag) VALUES (?, ?)');
    for (const tag of tags) insertTag.run(id, tag);

    res.json({ ok: true });
  }
);

app.delete('/api/posts/:id', authRequired, (req, res) => {
  const id = parseInt(req.params.id, 10);
  const post = db.prepare('SELECT * FROM posts WHERE id = ?').get(id);
  if (!post) return res.status(404).json({ error: 'not_found' });
  if (post.user_id !== req.userId) return res.status(403).json({ error: 'forbidden' });

  db.prepare('DELETE FROM posts WHERE id = ?').run(id);
  res.json({ ok: true });
});

app.post('/api/posts/:id/like', authRequired, (req, res) => {
  const id = parseInt(req.params.id, 10);
  const post = db.prepare('SELECT id FROM posts WHERE id = ?').get(id);
  if (!post) return res.status(404).json({ error: 'not_found' });

  const existing = db.prepare('SELECT 1 FROM likes WHERE post_id = ? AND user_id = ?').get(id, req.userId);
  if (existing) {
    db.prepare('DELETE FROM likes WHERE post_id = ? AND user_id = ?').run(id, req.userId);
  } else {
    db.prepare('INSERT INTO likes (post_id, user_id, time) VALUES (?, ?, ?)').run(id, req.userId, now());
  }

  const count = db.prepare('SELECT COUNT(*) as c FROM likes WHERE post_id = ?').get(id).c;
  res.json({ liked: !existing, likes: count });
});

app.get('/api/posts/:id/comments', authRequired, (req, res) => {
  const id = parseInt(req.params.id, 10);
  const rows = db.prepare('SELECT * FROM comments WHERE post_id = ? ORDER BY time ASC LIMIT 200').all(id);

  const comments = rows.map(c => {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(c.user_id);
    return { id: c.id, text: c.text, time: c.time, user: publicUser(user) };
  });

  res.json({ comments });
});

app.post('/api/posts/:id/comment', authRequired, dmLimiter,
  body('text').trim().isLength({ min: 1, max: 500 }),
  validate,
  (req, res) => {
    const id = parseInt(req.params.id, 10);
    const post = db.prepare('SELECT id FROM posts WHERE id = ?').get(id);
    if (!post) return res.status(404).json({ error: 'not_found' });

    db.prepare('INSERT INTO comments (post_id, user_id, text, time) VALUES (?, ?, ?, ?)')
      .run(id, req.userId, req.body.text, now());

    const rows = db.prepare('SELECT * FROM comments WHERE post_id = ? ORDER BY time ASC LIMIT 200').all(id);
    const comments = rows.map(c => {
      const user = db.prepare('SELECT * FROM users WHERE id = ?').get(c.user_id);
      return { id: c.id, text: c.text, time: c.time, user: publicUser(user) };
    });

    res.json({ comments });
  }
);

/* ============================================================
   15. DM Routes (E2EE - الخادم لا يرى المحتوى)
   ============================================================ */
app.get('/api/dm-conversations', authRequired, (req, res) => {
  const rows = db.prepare(`
    SELECT
      CASE WHEN from_id = ? THEN to_id ELSE from_id END AS other_id,
      MAX(time) AS last_time
    FROM dms
    WHERE from_id = ? OR to_id = ?
    GROUP BY other_id
    ORDER BY last_time DESC
    LIMIT 100
  `).all(req.userId, req.userId, req.userId);

  const conversations = rows.map(r => {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(r.other_id);
    if (!user) return null;

    const last = db.prepare(
      'SELECT text, time FROM dms WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?) ORDER BY time DESC LIMIT 1'
    ).get(req.userId, r.other_id, r.other_id, req.userId);

    const unread = db.prepare(
      'SELECT COUNT(*) as c FROM dms WHERE from_id = ? AND to_id = ? AND read = 0'
    ).get(r.other_id, req.userId).c;

    return {
      user: publicUser(user),
      last: last ? { text: last.text, time: last.time } : null,
      unread
    };
  }).filter(Boolean);

  res.json({ conversations });
});

app.get('/api/dms/:userId', authRequired, (req, res) => {
  const otherId = parseInt(req.params.userId, 10);
  if (!otherId) return res.status(400).json({ error: 'invalid' });

  const rows = db.prepare(`
    SELECT * FROM dms
    WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?)
    ORDER BY time ASC
    LIMIT 500
  `).all(req.userId, otherId, otherId, req.userId);

  // تعليم كمقروء
  db.prepare('UPDATE dms SET read = 1 WHERE from_id = ? AND to_id = ? AND read = 0')
    .run(otherId, req.userId);

  // إعلام المرسل بأن رسائله قُرئت
  io.to(`u_${otherId}`).emit('dm-read-receipt', { byId: req.userId });

  const messages = rows.map(m => ({
    id: m.id,
    from_id: m.from_id,
    to_id: m.to_id,
    text: m.text,
    time: m.time,
    delivered: !!m.delivered,
    read: !!m.read
  }));

  res.json({ messages });
});

/* ============================================================
   16. Upload Route
   ============================================================ */
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
  const url = `${PUBLIC_URL}/uploads/${req.file.filename}`;
  res.json({ url });
});

/* ============================================================
   17. Push Notifications
   ============================================================ */
let pushEnabled = false;
if (process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY) {
  webpush.setVapidDetails(
    process.env.VAPID_SUBJECT || 'mailto:admin@dust.app',
    process.env.VAPID_PUBLIC_KEY,
    process.env.VAPID_PRIVATE_KEY
  );
  pushEnabled = true;
  console.log('✅ Web Push enabled');
}

app.get('/api/vapid-public', (req, res) => {
  res.json({ key: process.env.VAPID_PUBLIC_KEY || null });
});

app.post('/api/push/subscribe', authRequired, (req, res) => {
  const sub = req.body;
  if (!sub || !sub.endpoint) return res.status(400).json({ error: 'invalid' });

  db.prepare(`
    INSERT INTO push_subs (user_id, endpoint, p256dh, auth, time)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(endpoint) DO UPDATE SET user_id = excluded.user_id
  `).run(
    req.userId,
    sub.endpoint,
    sub.keys ? sub.keys.p256dh : '',
    sub.keys ? sub.keys.auth : '',
    now()
  );

  res.json({ ok: true });
});

async function sendPush(userId, payload) {
  if (!pushEnabled) return;
  const subs = db.prepare('SELECT * FROM push_subs WHERE user_id = ?').all(userId);
  const dead = [];

  for (const s of subs) {
    try {
      await webpush.sendNotification({
        endpoint: s.endpoint,
        keys: { p256dh: s.p256dh, auth: s.auth }
      }, JSON.stringify(payload));
    } catch (e) {
      if (e.statusCode === 404 || e.statusCode === 410) dead.push(s.id);
    }
  }

  for (const id of dead) db.prepare('DELETE FROM push_subs WHERE id = ?').run(id);
}

/* ============================================================
   18. HTTP Server + Socket.io
   ============================================================ */
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] },
  pingTimeout: 30000,
  pingInterval: 25000,
  maxHttpBufferSize: 1e6
});

const ONLINE_USERS = new Map(); // userId -> Set<socketId>

io.use((socket, next) => {
  const token = socket.handshake.auth && socket.handshake.auth.token;
  if (!token) return next(new Error('auth_required'));

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const row = db.prepare('SELECT * FROM users WHERE id = ? AND deleted = 0').get(decoded.id);
    if (!row) return next(new Error('user_not_found'));
    if (row.token_hash !== hashToken(token)) return next(new Error('session_expired'));

    socket.userId = row.id;
    socket.user = row;
    next();
  } catch (e) {
    next(new Error('invalid_token'));
  }
});

io.on('connection', (socket) => {
  const userId = socket.userId;

  // انضم لغرفة خاصة
  socket.join(`u_${userId}`);

  // تتبع الحالة
  if (!ONLINE_USERS.has(userId)) ONLINE_USERS.set(userId, new Set());
  ONLINE_USERS.get(userId).add(socket.id);

  // إعلام الآخرين
  io.emit('user-online', { userId });

  // تحديث last_seen
  db.prepare('UPDATE users SET last_seen = ? WHERE id = ?').run(now(), userId);

  console.log(`🟢 User ${userId} connected (${socket.id})`);

  /* -------------------- DM Send -------------------- */
  socket.on('dm-send', async (data, cb) => {
    try {
      if (!data || typeof data.toId !== 'number' || typeof data.text !== 'string') return;
      if (data.text.length === 0 || data.text.length > 10000) return; // حد أقصى للنص المشفر

      const toId = data.toId;

      // فحص الحظر
      const blocked = db.prepare(
        'SELECT 1 FROM blocks WHERE (blocker_id = ? AND blocked_id = ?) OR (blocker_id = ? AND blocked_id = ?)'
      ).get(userId, toId, toId, userId);
      if (blocked) return;

      const target = db.prepare('SELECT id FROM users WHERE id = ? AND deleted = 0').get(toId);
      if (!target) return;

      const t = now();
      const isOnline = ONLINE_USERS.has(toId);

      const info = db.prepare(
        'INSERT INTO dms (from_id, to_id, text, time, delivered) VALUES (?, ?, ?, ?, ?)'
      ).run(userId, toId, data.text, t, isOnline ? 1 : 0);

      const msg = {
        id: info.lastInsertRowid,
        from_id: userId,
        to_id: toId,
        text: data.text,
        time: t,
        delivered: isOnline,
        read: false
      };

      // أرسل للطرفين
      io.to(`u_${toId}`).emit('dm-message', msg);
      socket.emit('dm-message', msg);

      if (isOnline) {
        socket.emit('dm-delivered', { id: msg.id });
      } else {
        // إشعار Push
        sendPush(toId, {
          title: 'Dust',
          body: 'رسالة جديدة',
          tag: 'dm_' + userId,
          data: { type: 'dm', fromId: userId }
        }).catch(() => {});
      }
    } catch (e) {
      console.error('dm-send error:', e);
    }
  });

  /* -------------------- DM Read -------------------- */
  socket.on('dm-read', (data) => {
    if (!data || typeof data.fromId !== 'number') return;
    db.prepare('UPDATE dms SET read = 1 WHERE from_id = ? AND to_id = ? AND read = 0')
      .run(data.fromId, userId);
    io.to(`u_${data.fromId}`).emit('dm-read-receipt', { byId: userId });
  });

  /* -------------------- Typing -------------------- */
  socket.on('dm-typing', (data) => {
    if (!data || typeof data.toId !== 'number') return;
    io.to(`u_${data.toId}`).emit('dm-typing', {
      fromId: userId,
      isTyping: !!data.isTyping
    });
  });

  /* -------------------- Disconnect -------------------- */
  socket.on('disconnect', () => {
    const set = ONLINE_USERS.get(userId);
    if (set) {
      set.delete(socket.id);
      if (set.size === 0) {
        ONLINE_USERS.delete(userId);
        db.prepare('UPDATE users SET last_seen = ? WHERE id = ?').run(now(), userId);
        io.emit('user-offline', { userId });
      }
    }
    console.log(`🔴 User ${userId} disconnected (${socket.id})`);
  });
});

/* ============================================================
   19. Cleanup Task — حذف الرسائل القديمة
   ============================================================ */
setInterval(() => {
  // حذف الرسائل الأقدم من 48 ساعة
  const cutoff = now() - (48 * 60 * 60 * 1000);
  const r = db.prepare('DELETE FROM dms WHERE time < ? AND read = 1').run(cutoff);
  if (r.changes > 0) console.log(`🧹 Cleaned ${r.changes} old messages`);
}, 60 * 60 * 1000); // كل ساعة

/* ============================================================
   20. Health Check + Errors
   ============================================================ */
app.get('/health', (req, res) => {
  res.json({
    ok: true,
    uptime: process.uptime(),
    users: db.prepare('SELECT COUNT(*) as c FROM users WHERE deleted = 0').get().c,
    online: ONLINE_USERS.size,
    e2ee: 'client-side',
    version: '7.0.0'
  });
});

app.use((err, req, res, next) => {
  console.error('❌ Error:', err.message);
  if (err.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: 'file_too_large' });
  res.status(500).json({ error: 'server_error' });
});

/* ============================================================
   21. Start
   ============================================================ */
server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Dust Server running on port ${PORT}`);
  console.log(`🔗 Public URL: ${PUBLIC_URL}`);
  console.log(`🔐 E2EE: client-side (server never sees plaintext)`);
  console.log(`🛡️  Security: helmet, rate-limit, JWT, AES-256-GCM, input validation`);
});

process.on('SIGTERM', () => {
  console.log('SIGTERM — closing...');
  server.close(() => {
    db.close();
    process.exit(0);
  });
});
