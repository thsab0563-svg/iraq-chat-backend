require('dotenv').config();
const path = require('path');
const fs = require('fs');
const http = require('http');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const { Server } = require('socket.io');
const { createClient } = require('@libsql/client');
const webpush = require('web-push');
const QRCode = require('qrcode');

const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const COLORS = ['#e8b567','#f4a261','#ff6b8a','#4ecdc4','#7c9cff','#c084fc','#f472b6','#34d399','#22d3ee','#e11d48'];
const MESSAGE_TTL_MS = 48 * 3600 * 1000;
const SESSION_TTL_MS = 7 * 24 * 3600 * 1000;
const ACCOUNT_LOCK_AFTER = 5;
const ACCOUNT_LOCK_MS = 15 * 60 * 1000;

const ALLOWED_ORIGINS = [
  'https://iraq-chat-backend-production.up.railway.app',
  'http://localhost:3000',
  'http://localhost:8080',
  'http://127.0.0.1:3000',
  'capacitor://localhost',
  'ionic://localhost'
];

// ===== VAPID =====
const VAPID_PUBLIC = process.env.VAPID_PUBLIC_KEY || '';
const VAPID_PRIVATE = process.env.VAPID_PRIVATE_KEY || '';
const VAPID_EMAIL = process.env.VAPID_EMAIL || 'mailto:admin@example.com';
const PUSH_ENABLED = !!(VAPID_PUBLIC && VAPID_PRIVATE);

if (PUSH_ENABLED) {
  try {
    webpush.setVapidDetails(VAPID_EMAIL, VAPID_PUBLIC, VAPID_PRIVATE);
    console.log('✅ Push enabled');
  } catch (e) {
    console.error('❌ VAPID error:', e.message);
  }
} else {
  console.log('⚠️ Push disabled');
}

// ===== Turso =====
const TURSO_URL = process.env.TURSO_URL || '';
const TURSO_TOKEN = process.env.TURSO_TOKEN || '';
if (!TURSO_URL || !TURSO_TOKEN) {
  console.error('❌ TURSO_URL / TURSO_TOKEN missing');
  process.exit(1);
}

const db = createClient({ url: TURSO_URL, authToken: TURSO_TOKEN });

// ===== SECRET =====
let SECRET_KEY;
const SECRET_FILE = path.join(process.env.DATA_DIR || __dirname, '.secret');
if (fs.existsSync(SECRET_FILE)) {
  try { SECRET_KEY = Buffer.from(fs.readFileSync(SECRET_FILE, 'utf8'), 'hex'); }
  catch(_) { SECRET_KEY = crypto.randomBytes(32); }
} else {
  SECRET_KEY = crypto.randomBytes(32);
  try { fs.writeFileSync(SECRET_FILE, SECRET_KEY.toString('hex')); } catch(_){}
}

function encryptText(text) {
  if (!text) return text;
  try {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', SECRET_KEY, iv);
    const enc = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return 'enc:' + Buffer.concat([iv, tag, enc]).toString('base64');
  } catch (_) { return text; }
}
function decryptText(text) {
  if (!text || text.indexOf('enc:') !== 0) return text;
  try {
    const data = Buffer.from(text.slice(4), 'base64');
    const iv = data.slice(0, 12), tag = data.slice(12, 28), enc = data.slice(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', SECRET_KEY, iv);
    decipher.setAuthTag(tag);
    return decipher.update(enc, undefined, 'utf8') + decipher.final('utf8');
  } catch (_) { return '[خطأ]'; }
}
function genToken() { return crypto.randomBytes(32).toString('hex'); }
function genQrId() { return crypto.randomBytes(8).toString('hex'); }

// ===== DB INIT =====
async function initDB() {
  const stmts = [
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      display_name TEXT NOT NULL,
      color TEXT,
      bio TEXT DEFAULT '',
      location TEXT DEFAULT '',
      country TEXT DEFAULT '',
      avatar TEXT DEFAULT '',
      cover TEXT DEFAULT '',
      created_at INTEGER,
      last_seen INTEGER,
      qr_id TEXT UNIQUE,
      push_enabled INTEGER DEFAULT 1,
      theme TEXT DEFAULT 'dark',
      sound INTEGER DEFAULT 1
    )`,
    `CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      device TEXT,
      created_at INTEGER,
      last_active INTEGER
    )`,
    `CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      text TEXT, time INTEGER,
      deleted INTEGER DEFAULT 0, edited INTEGER DEFAULT 0
    )`,
    `CREATE TABLE IF NOT EXISTS post_likes (post_id INTEGER, user_id INTEGER, PRIMARY KEY (post_id, user_id))`,
    `CREATE TABLE IF NOT EXISTS post_comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      post_id INTEGER, user_id INTEGER, text TEXT, time INTEGER
    )`,
    `CREATE TABLE IF NOT EXISTS hashtags (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tag TEXT, source_type TEXT, source_id INTEGER, time INTEGER
    )`,
    `CREATE TABLE IF NOT EXISTS friendships (
      user1 INTEGER, user2 INTEGER, status TEXT,
      PRIMARY KEY (user1, user2)
    )`,
    `CREATE TABLE IF NOT EXISTS dms (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      from_id INTEGER, to_id INTEGER, text TEXT, time INTEGER,
      read INTEGER DEFAULT 0, delivered INTEGER DEFAULT 0
    )`,
    `CREATE TABLE IF NOT EXISTS blocks (
      user1 INTEGER, user2 INTEGER, time INTEGER,
      PRIMARY KEY (user1, user2)
    )`,
    `CREATE TABLE IF NOT EXISTS push_subs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER, endpoint TEXT UNIQUE, keys TEXT, time INTEGER
    )`,
    `CREATE TABLE IF NOT EXISTS notifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL, type TEXT, text TEXT,
      from_user_id INTEGER, post_id INTEGER, url TEXT,
      time INTEGER, read INTEGER DEFAULT 0
    )`,
    `CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER, action TEXT, ip TEXT, details TEXT, time INTEGER
    )`
  ];
  for (const sql of stmts) {
    try { await db.execute(sql); } catch (e) { console.error('SQL error:', e.message); }
  }
  try { await db.execute('ALTER TABLE posts ADD COLUMN edited INTEGER DEFAULT 0'); } catch(_){}
  console.log('✅ DB initialized');
}

// ===== Helpers =====
async function q(sql, args) {
  const res = await db.execute({ sql: sql, args: args || [] });
  return res.rows;
}
async function q1(sql, args) {
  const rows = await q(sql, args);
  return rows[0] || null;
}
async function run(sql, args) {
  return await db.execute({ sql: sql, args: args || [] });
}

const userSockets = new Map();
function isUserOnline(userId) {
  const set = userSockets.get(userId);
  return !!(set && set.size > 0);
}
function addSocketForUser(userId, socketId) {
  if (!userSockets.has(userId)) userSockets.set(userId, new Set());
  userSockets.get(userId).add(socketId);
}
function removeSocketForUser(userId, socketId) {
  const set = userSockets.get(userId);
  if (!set) return false;
  set.delete(socketId);
  if (set.size === 0) { userSockets.delete(userId); return true; }
  return false;
}

function publicUser(u) {
  if (!u) return null;
  const online = isUserOnline(u.id);
  return {
    id: u.id,
    username: u.username,
    display_name: u.display_name,
    color: u.color,
    bio: u.bio,
    location: u.location,
    country: u.country,
    avatar: u.avatar,
    cover: u.cover || '',
    created_at: u.created_at,
    last_seen: u.last_seen,
    qr_id: u.qr_id,
    theme: u.theme,
    sound: !!u.sound,
    online: online
  };
}

async function isBlocked(a, b) {
  const r = await q1('SELECT 1 FROM blocks WHERE (user1 = ? AND user2 = ?) OR (user1 = ? AND user2 = ?)', [a, b, b, a]);
  return !!r;
}

async function genUniqueUsername(base) {
  let clean = String(base || 'user').trim().replace(/\s+/g, '_').slice(0, 20);
  if (!clean) clean = 'user';
  let candidate = clean;
  let i = 0;
  while (await q1('SELECT 1 FROM users WHERE username = ?', [candidate])) {
    i++;
    candidate = clean + '_' + crypto.randomBytes(2).toString('hex');
    if (i > 50) { candidate = 'user_' + crypto.randomBytes(4).toString('hex'); break; }
  }
  return candidate;
}

async function genUniqueDisplay(base) {
  let clean = String(base || 'مستخدم').trim().slice(0, 20);
  if (!clean) clean = 'مستخدم';
  let candidate = clean;
  let i = 0;
  while (await q1('SELECT 1 FROM users WHERE display_name = ?', [candidate])) {
    i++;
    candidate = clean + ' #' + Math.floor(Math.random() * 9000 + 1000);
    if (i > 50) { candidate = clean + ' #' + crypto.randomBytes(2).toString('hex'); break; }
  }
  return candidate;
}

async function genUniqueQr() {
  let candidate;
  let i = 0;
  do {
    candidate = genQrId();
    i++;
    if (i > 20) break;
  } while (await q1('SELECT 1 FROM users WHERE qr_id = ?', [candidate]));
  return candidate;
}

function extractHashtags(text) {
  const tags = [];
  const re = /#([\u0600-\u06FF\w_]{1,40})/g;
  let m;
  while ((m = re.exec(text)) !== null) tags.push(m[1].toLowerCase());
  return Array.from(new Set(tags));
}

async function auditLog(userId, action, req, details) {
  try {
    let ip = 'unknown';
    if (req) {
      ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress || 'unknown';
      if (typeof ip === 'string' && ip.indexOf(',') !== -1) ip = ip.split(',')[0].trim();
    }
    await run('INSERT INTO audit_log (user_id, action, ip, details, time) VALUES (?,?,?,?,?)',
      [userId || null, action, String(ip).slice(0, 50), String(details || '').slice(0, 200), Date.now()]);
  } catch (_) {}
}

async function addNotification(userId, type, text, fromUserId, postId, url) {
  try {
    await run('INSERT INTO notifications (user_id, type, text, from_user_id, post_id, url, time, read) VALUES (?,?,?,?,?,?,?,0)',
      [userId, type, text, fromUserId || null, postId || null, url || null, Date.now()]);
  } catch(e) { console.error('addNotif error:', e.message); }
}

async function sendPushToUser(userId, payload) {
  if (!PUSH_ENABLED) return;
  try {
    const subs = await q('SELECT * FROM push_subs WHERE user_id = ?', [userId]);
    for (const sub of subs) {
      const subscription = { endpoint: sub.endpoint, keys: JSON.parse(sub.keys) };
      try {
        await webpush.sendNotification(subscription, JSON.stringify(payload));
      } catch (e) {
        if (e.statusCode === 410 || e.statusCode === 404) {
          await run('DELETE FROM push_subs WHERE id = ?', [sub.id]);
        }
      }
    }
  } catch (e) { console.error('Push error:', e.message); }
}

// ===== Express =====
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: ALLOWED_ORIGINS, methods: ['GET','POST'], credentials: true },
  maxHttpBufferSize: 5 * 1024 * 1024,
  pingTimeout: 60000,
  pingInterval: 25000
});

app.set('trust proxy', 1);

app.use(cors({
  origin: function(origin, callback){
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.indexOf(origin) !== -1) return callback(null, true);
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','x-health-token']
}));

app.use(express.json({ limit: '5mb' }));

// ===== Security Headers =====
app.use(function(req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(self), geolocation=()');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

// ===== Rate Limit =====
const disableRL = process.env.RATE_LIMIT_DISABLED === 'true';
const mkLimit = (o) => rateLimit({ standardHeaders: true, legacyHeaders: false, skip: () => disableRL, windowMs: o.windowMs, max: o.max, message: o.message || { error: 'too_many_requests' } });
app.use('/api/', mkLimit({ windowMs: 60000, max: 120 }));
app.use('/api/register', mkLimit({ windowMs: 3600000, max: 10 }));

// ===== Auth middleware — Session Token =====
async function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.replace('Bearer ', '') || req.query.token;
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  const s = await q1('SELECT * FROM sessions WHERE token = ?', [token]);
  if (!s) return res.status(401).json({ error: 'invalid_token' });

  const age = Date.now() - (s.last_active || s.created_at || 0);
  if (age > SESSION_TTL_MS) {
    await run('DELETE FROM sessions WHERE token = ?', [token]);
    return res.status(401).json({ error: 'session_expired' });
  }

  const user = await q1('SELECT * FROM users WHERE id = ?', [s.user_id]);
  if (!user) {
    await run('DELETE FROM sessions WHERE token = ?', [token]);
    return res.status(401).json({ error: 'user_not_found' });
  }

  // تحديث last_active
  await run('UPDATE sessions SET last_active = ? WHERE token = ?', [Date.now(), token]);
  await run('UPDATE users SET last_seen = ? WHERE id = ?', [Date.now(), user.id]);

  req.user = user;
  req.sessionToken = token;
  next();
}

// ===== Health =====
const startTime = Date.now();
const HEALTH_TOKEN = process.env.HEALTH_TOKEN || '';

app.get('/health', function(req, res) {
  if (HEALTH_TOKEN) {
    const provided = req.headers['x-health-token'] || req.query.token;
    if (provided !== HEALTH_TOKEN) return res.json({ ok: true });
  }
  res.json({
    ok: true,
    uptime_s: Math.floor((Date.now() - startTime) / 1000),
    env: NODE_ENV,
    online: userSockets.size,
    push: PUSH_ENABLED
  });
});

app.get('/api/vapid-public', function(req, res) {
  res.json({ key: VAPID_PUBLIC });
});

// ===== Upload =====
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 3 * 1024 * 1024 },
  fileFilter: function(req, file, cb) {
    const ok = /^image\/(jpeg|jpg|png|webp|gif)$/i.test(file.mimetype);
    cb(null, ok);
  }
});

app.post('/upload', auth, upload.single('image'), async function(req, res) {
  if (!req.file) return res.status(400).json({ error: 'invalid' });
  try {
    const mime = req.file.mimetype || 'image/jpeg';
    const b64 = req.file.buffer.toString('base64');
    const dataUrl = 'data:' + mime + ';base64,' + b64;
    res.json({ url: dataUrl });
  } catch (e) {
    console.error('Upload error:', e);
    res.status(500).json({ error: 'upload_failed' });
  }
});

// ===== REGISTER — الاسم فقط =====
app.post('/api/register', async function(req, res) {
  try {
    const b = req.body || {};
    const rawName = String(b.name || '').trim().slice(0, 20);
    if (!rawName || rawName.length < 2) {
      return res.status(400).json({ error: 'name_required' });
    }

    const username = await genUniqueUsername(rawName);
    const displayName = await genUniqueDisplay(rawName);
    const qrId = await genUniqueQr();
    const color = /^#[0-9a-fA-F]{6}$/.test(b.color || '') ? b.color : COLORS[Math.floor(Math.random() * COLORS.length)];
    const now = Date.now();

    const r = await run(
      'INSERT INTO users (username, display_name, color, created_at, last_seen, qr_id) VALUES (?,?,?,?,?,?)',
      [username, displayName, color, now, now, qrId]
    );
    const user = await q1('SELECT * FROM users WHERE id = ?', [r.lastInsertRowid]);

    // Session token
    const token = genToken();
    const device = String(req.headers['user-agent'] || '').slice(0, 200);
    await run('INSERT INTO sessions (token, user_id, device, created_at, last_active) VALUES (?,?,?,?,?)',
      [token, user.id, device, now, now]);

    await auditLog(user.id, 'register', req, rawName);

    res.json({
      token: token,
      user: publicUser(user),
      isDuplicate: displayName !== rawName
    });
  } catch (e) {
    console.error('Register error:', e);
    res.status(500).json({ error: 'server_error' });
  }
});

// ===== ME =====
app.get('/api/me', auth, async function(req, res) {
  const u = await q1('SELECT * FROM users WHERE id = ?', [req.user.id]);
  res.json({ user: publicUser(u) });
});

app.get('/api/me/stats', auth, async function(req, res) {
  const uid = req.user.id;
  const f = await q1("SELECT COUNT(*) AS c FROM friendships WHERE (user1 = ? OR user2 = ?) AND status = 'accepted'", [uid, uid]);
  const p = await q1('SELECT COUNT(*) AS c FROM posts WHERE user_id = ? AND deleted = 0', [uid]);
  res.json({ friends: f.c, posts: p.c, views: 0 });
});

app.put('/api/me', auth, async function(req, res) {
  try {
    const b = req.body || {};
    const u = req.user;
    const fields = [], args = [];
    if (b.display_name !== undefined) {
      const nm = String(b.display_name).trim().slice(0, 20);
      if (!nm) return res.status(400).json({ error: 'name_required' });
      fields.push('display_name = ?'); args.push(nm);
    }
    if (b.bio !== undefined) { fields.push('bio = ?'); args.push(String(b.bio).slice(0, 200)); }
    if (b.location !== undefined) { fields.push('location = ?'); args.push(String(b.location).slice(0, 60)); }
    if (b.country !== undefined) { fields.push('country = ?'); args.push(String(b.country).slice(0, 40)); }
    if (b.avatar !== undefined) { fields.push('avatar = ?'); args.push(String(b.avatar)); }
    if (b.cover !== undefined) { fields.push('cover = ?'); args.push(String(b.cover)); }
    if (b.color !== undefined && /^#[0-9a-fA-F]{6}$/.test(b.color)) { fields.push('color = ?'); args.push(b.color); }
    if (b.theme !== undefined && ['dark','light'].indexOf(b.theme) !== -1) { fields.push('theme = ?'); args.push(b.theme); }
    if (b.sound !== undefined) { fields.push('sound = ?'); args.push(b.sound ? 1 : 0); }
    if (!fields.length) return res.json({ user: publicUser(u) });
    args.push(u.id);
    await run('UPDATE users SET ' + fields.join(', ') + ' WHERE id = ?', args);
    const updated = await q1('SELECT * FROM users WHERE id = ?', [u.id]);
    res.json({ user: publicUser(updated) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

// ===== LOGOUT — حذف كامل =====
app.post('/api/logout', auth, async function(req, res) {
  try {
    const uid = req.user.id;
    const token = req.sessionToken;

    await auditLog(uid, 'logout_delete', req, '');

    // حذف كل شيء متعلق بالمستخدم
    await run('DELETE FROM sessions WHERE user_id = ?', [uid]);
    await run('DELETE FROM dms WHERE from_id = ? OR to_id = ?', [uid, uid]);
    await run('DELETE FROM blocks WHERE user1 = ? OR user2 = ?', [uid, uid]);
    await run('DELETE FROM post_likes WHERE user_id = ?', [uid]);
    await run('DELETE FROM post_comments WHERE user_id = ?', [uid]);
    await run('DELETE FROM posts WHERE user_id = ?', [uid]);
    await run('DELETE FROM friendships WHERE user1 = ? OR user2 = ?', [uid, uid]);
    await run('DELETE FROM push_subs WHERE user_id = ?', [uid]);
    await run('DELETE FROM notifications WHERE user_id = ? OR from_user_id = ?', [uid, uid]);
    await run('DELETE FROM users WHERE id = ?', [uid]);

    // إعلام الأصدقاء أن المستخدم حذف حسابه (يختفي من قوائمهم)
    io.emit('user-deleted', { userId: uid });

    res.json({ ok: true });
  } catch (e) {
    console.error('Logout error:', e);
    res.status(500).json({ error: 'server_error' });
  }
});

// ===== QR CODE =====
app.get('/api/qr/image', auth, async function(req, res) {
  try {
    const u = req.user;
    const qrData = JSON.stringify({
      v: 1,
      id: u.id,
      qr: u.qr_id,
      name: u.display_name
    });
    const qrUrl = 'https://iraq-chat-backend-production.up.railway.app/?qr=' + u.qr_id;

    const dataUrl = await QRCode.toDataURL(qrUrl, {
      errorCorrectionLevel: 'H',
      width: 512,
      margin: 2,
      color: {
        dark: '#0a0b10',
        light: '#ffffff'
      }
    });
    res.json({ qr: dataUrl, link: qrUrl, qr_id: u.qr_id });
  } catch (e) {
    console.error('QR error:', e);
    res.status(500).json({ error: 'qr_failed' });
  }
});

// ===== إضافة صديق عبر QR =====
app.post('/api/friends/add-by-qr', auth, async function(req, res) {
  try {
    const qrId = String((req.body || {}).qr_id || '').trim();
    if (!qrId) return res.status(400).json({ error: 'qr_required' });

    const target = await q1('SELECT * FROM users WHERE qr_id = ?', [qrId]);
    if (!target) return res.status(404).json({ error: 'user_not_found' });
    if (target.id === req.user.id) return res.status(400).json({ error: 'self' });

    if (await isBlocked(req.user.id, target.id)) {
      return res.status(403).json({ error: 'blocked' });
    }

    const exists = await q1(
      'SELECT * FROM friendships WHERE (user1 = ? AND user2 = ?) OR (user1 = ? AND user2 = ?)',
      [req.user.id, target.id, target.id, req.user.id]
    );
    if (exists) {
      if (exists.status === 'accepted') return res.json({ ok: true, status: 'already_friends', user: publicUser(target) });
      return res.json({ ok: true, status: 'pending', user: publicUser(target) });
    }

    await run('INSERT INTO friendships (user1, user2, status) VALUES (?,?,?)',
      [req.user.id, target.id, 'accepted']);

    const me = await q1('SELECT * FROM users WHERE id = ?', [req.user.id]);
    const notifText = me.display_name + ' أضافك كصديق عبر QR';
    io.to('user:' + target.id).emit('notification', { type: 'friend_accept', from: publicUser(me), text: notifText });
    await addNotification(target.id, 'friend_accept', notifText, req.user.id, null, '/?tab=friends');
    sendPushToUser(target.id, { title: 'صديق جديد', body: notifText, url: '/?tab=friends', type: 'friend_accept' });

    res.json({ ok: true, status: 'added', user: publicUser(target) });
  } catch (e) {
    console.error('Add by QR error:', e);
    res.status(500).json({ error: 'server_error' });
  }
});

// ===== POSTS (نفس السابق) =====
app.post('/api/posts', auth, async function(req, res) {
  const t = String((req.body || {}).text || '').trim().slice(0, 1000);
  if (!t) return res.status(400).json({ error: 'empty' });
  const now = Date.now();
  const r = await run('INSERT INTO posts (user_id, text, time, deleted, edited) VALUES (?,?,?,0,0)', [req.user.id, encryptText(t), now]);
  const pid = r.lastInsertRowid;
  for (const tag of extractHashtags(t)) {
    await run('INSERT INTO hashtags (tag, source_type, source_id, time) VALUES (?,?,?,?)', [tag, 'post', pid, now]);
  }
  const p = await q1('SELECT * FROM posts WHERE id = ?', [pid]);
  const u = await q1('SELECT * FROM users WHERE id = ?', [p.user_id]);
  res.json({ post: { id: p.id, text: decryptText(p.text), time: p.time, user: publicUser(u), likes: 0, comments: 0, liked: false, edited: false } });
});

app.get('/api/posts', auth, async function(req, res) {
  const lim = Math.min(parseInt(req.query.limit) || 50, 100);
  const { username, user_id, hashtag } = req.query;
  let rows;
  if (hashtag) {
    const tag = String(hashtag).replace(/^#/, '').toLowerCase();
    const ids = (await q('SELECT DISTINCT source_id FROM hashtags WHERE tag = ? AND source_type = ?', [tag, 'post'])).map(r => r.source_id);
    if (!ids.length) rows = [];
    else {
      const ph = ids.map(() => '?').join(',');
      rows = await q(`SELECT * FROM posts WHERE deleted = 0 AND id IN (${ph}) ORDER BY time DESC LIMIT ?`, [...ids, lim]);
    }
  } else if (user_id) {
    rows = await q('SELECT * FROM posts WHERE deleted = 0 AND user_id = ? ORDER BY time DESC LIMIT ?', [parseInt(user_id), lim]);
  } else if (username) {
    const u = await q1('SELECT id FROM users WHERE username = ?', [username]);
    if (!u) return res.json({ posts: [] });
    rows = await q('SELECT * FROM posts WHERE deleted = 0 AND user_id = ? ORDER BY time DESC LIMIT ?', [u.id, lim]);
  } else {
    rows = await q('SELECT * FROM posts WHERE deleted = 0 ORDER BY time DESC LIMIT ?', [lim]);
  }
  const posts = [];
  for (const p of rows) {
    const u = await q1('SELECT * FROM users WHERE id = ?', [p.user_id]);
    const likes = (await q1('SELECT COUNT(*) AS c FROM post_likes WHERE post_id = ?', [p.id])).c;
    const comments = (await q1('SELECT COUNT(*) AS c FROM post_comments WHERE post_id = ?', [p.id])).c;
    const liked = !!(await q1('SELECT 1 FROM post_likes WHERE post_id = ? AND user_id = ?', [p.id, req.user.id]));
    posts.push({ id: p.id, text: decryptText(p.text), time: p.time, user: publicUser(u), likes, comments, liked, edited: !!p.edited });
  }
  res.json({ posts });
});

app.put('/api/posts/:id', auth, async function(req, res) {
  const id = parseInt(req.params.id);
  const p = await q1('SELECT * FROM posts WHERE id = ?', [id]);
  if (!p || p.user_id !== req.user.id) return res.status(403).json({ error: 'forbidden' });
  const t = String((req.body || {}).text || '').trim().slice(0, 1000);
  if (!t) return res.status(400).json({ error: 'empty' });
  await run('UPDATE posts SET text = ?, edited = 1 WHERE id = ?', [encryptText(t), id]);
  res.json({ ok: true });
});

app.post('/api/posts/:id/like', auth, async function(req, res) {
  const id = parseInt(req.params.id);
  const existing = await q1('SELECT 1 FROM post_likes WHERE post_id = ? AND user_id = ?', [id, req.user.id]);
  let liked;
  if (existing) { await run('DELETE FROM post_likes WHERE post_id = ? AND user_id = ?', [id, req.user.id]); liked = false; }
  else {
    await run('INSERT INTO post_likes (post_id, user_id) VALUES (?,?)', [id, req.user.id]); liked = true;
    const post = await q1('SELECT user_id FROM posts WHERE id = ?', [id]);
    if (post && post.user_id !== req.user.id) {
      const me = await q1('SELECT * FROM users WHERE id = ?', [req.user.id]);
      const notifText = me.display_name + ' أعجب بمنشورك';
      io.to('user:' + post.user_id).emit('notification', { type: 'like', from: publicUser(me), postId: id, text: notifText });
      await addNotification(post.user_id, 'like', notifText, req.user.id, id, '/?tab=home');
      sendPushToUser(post.user_id, { title: 'إعجاب', body: notifText, url: '/?tab=home', type: 'like' });
    }
  }
  const likes = (await q1('SELECT COUNT(*) AS c FROM post_likes WHERE post_id = ?', [id])).c;
  res.json({ likes, liked });
});

app.get('/api/posts/:id/comments', auth, async function(req, res) {
  const id = parseInt(req.params.id);
  const rows = await q('SELECT * FROM post_comments WHERE post_id = ? ORDER BY time ASC', [id]);
  const out = [];
  for (const c of rows) {
    const u = await q1('SELECT * FROM users WHERE id = ?', [c.user_id]);
    out.push({ id: c.id, text: decryptText(c.text), time: c.time, user: u ? publicUser(u) : null });
  }
  res.json({ comments: out });
});

app.post('/api/posts/:id/comment', auth, async function(req, res) {
  const id = parseInt(req.params.id);
  const text = String((req.body || {}).text || '').trim().slice(0, 500);
  if (!text) return res.status(400).json({ error: 'empty' });
  await run('INSERT INTO post_comments (post_id, user_id, text, time) VALUES (?,?,?,?)', [id, req.user.id, encryptText(text), Date.now()]);
  const post = await q1('SELECT user_id FROM posts WHERE id = ?', [id]);
  if (post && post.user_id !== req.user.id) {
    const me = await q1('SELECT * FROM users WHERE id = ?', [req.user.id]);
    const notifText = me.display_name + ' علّق على منشورك';
    io.to('user:' + post.user_id).emit('notification', { type: 'comment', from: publicUser(me), postId: id, text: notifText });
    await addNotification(post.user_id, 'comment', notifText, req.user.id, id, '/?tab=home');
  }
  const rows = await q('SELECT * FROM post_comments WHERE post_id = ? ORDER BY time ASC', [id]);
  const out = [];
  for (const c of rows) {
    const u = await q1('SELECT * FROM users WHERE id = ?', [c.user_id]);
    out.push({ id: c.id, text: decryptText(c.text), time: c.time, user: u ? publicUser(u) : null });
  }
  res.json({ comments: out });
});

app.delete('/api/posts/:id', auth, async function(req, res) {
  const p = await q1('SELECT * FROM posts WHERE id = ?', [parseInt(req.params.id)]);
  if (!p || p.user_id !== req.user.id) return res.status(403).json({ error: 'forbidden' });
  await run('UPDATE posts SET deleted = 1, text = ? WHERE id = ?', ['', p.id]);
  res.json({ ok: true });
});

// ===== TRENDS =====
app.get('/api/trends', auth, async function(req, res) {
  const since = Date.now() - 7 * 24 * 3600 * 1000;
  const rows = await q('SELECT tag, COUNT(*) AS c FROM hashtags WHERE time > ? AND source_type = ? GROUP BY tag ORDER BY c DESC LIMIT 20', [since, 'post']);
  res.json({ trends: rows.map(r => ({ tag: r.tag, c: r.c })) });
});

// ===== SUGGESTIONS =====
app.get('/api/suggestions', auth, async function(req, res) {
  const uid = req.user.id;
  const friendRows = await q(`SELECT CASE WHEN user1 = ? THEN user2 ELSE user1 END AS id FROM friendships WHERE (user1 = ? OR user2 = ?) AND status = 'accepted'`, [uid, uid, uid]);
  const friendIds = new Set(friendRows.map(r => r.id));
  const users = await q('SELECT * FROM users WHERE id != ? LIMIT 50', [uid]);
  const list = [];
  for (const u of users) {
    if (friendIds.has(u.id)) continue;
    if (await isBlocked(uid, u.id)) continue;
    list.push(u);
    if (list.length >= 10) break;
  }
  res.json({ users: list.map(publicUser) });
});

// ===== FRIENDS =====
app.get('/api/friends', auth, async function(req, res) {
  const rows = await q(`SELECT u.* FROM users u JOIN friendships f ON ((f.user1 = u.id AND f.user2 = ?) OR (f.user2 = u.id AND f.user1 = ?)) WHERE f.status = 'accepted'`, [req.user.id, req.user.id]);
  res.json({ friends: rows.map(publicUser) });
});

app.delete('/api/friends/:id', auth, async function(req, res) {
  const t = parseInt(req.params.id);
  await run('DELETE FROM friendships WHERE (user1 = ? AND user2 = ?) OR (user1 = ? AND user2 = ?)', [req.user.id, t, t, req.user.id]);
  res.json({ ok: true });
});

// ===== BLOCKS =====
app.post('/api/block/:id', auth, async function(req, res) {
  const t = parseInt(req.params.id);
  if (t === req.user.id) return res.status(400).json({ error: 'self' });
  await run('INSERT OR IGNORE INTO blocks (user1, user2, time) VALUES (?,?,?)', [req.user.id, t, Date.now()]);
  res.json({ ok: true });
});
app.post('/api/unblock/:id', auth, async function(req, res) {
  const t = parseInt(req.params.id);
  await run('DELETE FROM blocks WHERE (user1 = ? AND user2 = ?) OR (user1 = ? AND user2 = ?)', [req.user.id, t, t, req.user.id]);
  res.json({ ok: true });
});
app.get('/api/blocks', auth, async function(req, res) {
  const rows = await q('SELECT u.* FROM users u JOIN blocks b ON b.user2 = u.id WHERE b.user1 = ?', [req.user.id]);
  res.json({ blocks: rows.map(publicUser) });
});

// ===== USERS =====
app.get('/api/users/search', auth, async function(req, res) {
  const s = String(req.query.q || '').trim().slice(0, 40);
  if (!s) return res.json({ users: [] });
  const lq = '%' + s.toLowerCase() + '%';
  const rows = await q('SELECT * FROM users WHERE id != ? AND (LOWER(username) LIKE ? OR LOWER(display_name) LIKE ?) LIMIT 30', [req.user.id, lq, lq]);
  const filtered = [];
  for (const u of rows) if (!(await isBlocked(req.user.id, u.id))) filtered.push(u);
  res.json({ users: filtered.map(publicUser) });
});

app.get('/api/users/:id', auth, async function(req, res) {
  const u = await q1('SELECT * FROM users WHERE id = ?', [parseInt(req.params.id)]);
  if (!u) return res.status(404).json({ error: 'not_found' });
  const f = await q1('SELECT * FROM friendships WHERE (user1 = ? AND user2 = ?) OR (user1 = ? AND user2 = ?)', [req.user.id, u.id, u.id, req.user.id]);
  const isFriend = f && f.status === 'accepted';
  const blocked = await isBlocked(req.user.id, u.id);
  const friends = (await q1("SELECT COUNT(*) AS c FROM friendships WHERE (user1 = ? OR user2 = ?) AND status = 'accepted'", [u.id, u.id])).c;
  const posts = (await q1('SELECT COUNT(*) AS c FROM posts WHERE user_id = ? AND deleted = 0', [u.id])).c;
  res.json({ user: publicUser(u), isFriend, blocked, stats: { friends, posts, views: 0 } });
});

// ===== DM =====
app.get('/api/dms/:userId', auth, async function(req, res) {
  const other = parseInt(req.params.userId);
  if (other === req.user.id) return res.status(400).json({ error: 'self' });
  if (await isBlocked(req.user.id, other)) return res.status(403).json({ error: 'blocked' });
  const msgs = await q(`SELECT * FROM dms WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?) ORDER BY time ASC LIMIT 100`,
    [req.user.id, other, other, req.user.id]);
  await run('UPDATE dms SET read = 1 WHERE from_id = ? AND to_id = ? AND read = 0', [other, req.user.id]);
  io.to('user:' + other).emit('dm-read-receipt', { byId: req.user.id });
  res.json({
    messages: msgs.map(m => ({
      id: m.id, from_id: m.from_id, to_id: m.to_id,
      text: decryptText(m.text), time: m.time, read: !!m.read, delivered: !!m.delivered
    }))
  });
});

app.get('/api/dm-conversations', auth, async function(req, res) {
  const uid = req.user.id;
  const partners = await q(`SELECT DISTINCT CASE WHEN from_id = ? THEN to_id ELSE from_id END AS id FROM dms WHERE from_id = ? OR to_id = ?`, [uid, uid, uid]);
  const conversations = [];
  for (const p of partners) {
    const other = await q1('SELECT * FROM users WHERE id = ?', [p.id]);
    if (!other) continue;
    const last = await q1(`SELECT * FROM dms WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?) ORDER BY time DESC LIMIT 1`, [uid, p.id, p.id, uid]);
    const unread = (await q1('SELECT COUNT(*) AS c FROM dms WHERE from_id = ? AND to_id = ? AND read = 0', [p.id, uid])).c;
    conversations.push({
      user: publicUser(other),
      last: last ? { text: decryptText(last.text), time: last.time, from_id: last.from_id } : null,
      unread
    });
  }
  conversations.sort((a, b) => (b.last?.time || 0) - (a.last?.time || 0));
  res.json({ conversations });
});

// ===== NOTIFICATIONS =====
app.get('/api/notifications', auth, async function(req, res) {
  const rows = await q('SELECT * FROM notifications WHERE user_id = ? ORDER BY time DESC LIMIT 100', [req.user.id]);
  const out = [];
  for (const n of rows) {
    let fromUser = null;
    if (n.from_user_id) {
      const fu = await q1('SELECT id, username, display_name, color, avatar FROM users WHERE id = ?', [n.from_user_id]);
      if (fu) fromUser = publicUser(fu);
    }
    out.push({ id: n.id, type: n.type, text: n.text, url: n.url, time: n.time, read: !!n.read, post_id: n.post_id, from: fromUser });
  }
  res.json({ notifications: out });
});

app.post('/api/notifications/read', auth, async function(req, res) {
  await run('UPDATE notifications SET read = 1 WHERE user_id = ?', [req.user.id]);
  res.json({ ok: true });
});

app.delete('/api/notifications/all', auth, async function(req, res) {
  await run('DELETE FROM notifications WHERE user_id = ?', [req.user.id]);
  res.json({ ok: true });
});

app.delete('/api/notifications/:id', auth, async function(req, res) {
  await run('DELETE FROM notifications WHERE id = ? AND user_id = ?', [parseInt(req.params.id), req.user.id]);
  res.json({ ok: true });
});

// ===== PUSH =====
app.post('/api/push/subscribe', auth, async function(req, res) {
  try {
    const sub = req.body;
    if (!sub || !sub.endpoint || !sub.keys) return res.status(400).json({ error: 'invalid_subscription' });
    await run('INSERT OR REPLACE INTO push_subs (user_id, endpoint, keys, time) VALUES (?,?,?,?)',
      [req.user.id, sub.endpoint, JSON.stringify(sub.keys), Date.now()]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

// ===== Socket.IO =====
const socketRate = new Map();
function checkRate(id, key, max, ms) {
  const now = Date.now(), k = id + ':' + key;
  const e = socketRate.get(k) || { c: 0, r: now + ms };
  if (now > e.r) { e.c = 0; e.r = now + ms; }
  e.c++; socketRate.set(k, e);
  return e.c <= max;
}
setInterval(() => { const n = Date.now(); socketRate.forEach((v, k) => { if (n > v.r) socketRate.delete(k); }); }, 60000);

io.on('connection', (socket) => {

  socket.on('auth', async (data) => {
    try {
      const token = data && data.token;
      if (!token) return socket.emit('auth-error', { error: 'no_token' });
      const s = await q1('SELECT * FROM sessions WHERE token = ?', [token]);
      if (!s) return socket.emit('auth-error', { error: 'invalid_token' });

      const age = Date.now() - (s.last_active || s.created_at || 0);
      if (age > SESSION_TTL_MS) {
        await run('DELETE FROM sessions WHERE token = ?', [token]);
        return socket.emit('auth-error', { error: 'session_expired' });
      }

      const user = await q1('SELECT * FROM users WHERE id = ?', [s.user_id]);
      if (!user) {
        await run('DELETE FROM sessions WHERE token = ?', [token]);
        return socket.emit('auth-error', { error: 'user_not_found' });
      }

      addSocketForUser(user.id, socket.id);
      socket.userId = user.id;
      socket.join('user:' + user.id);
      socket.emit('auth-ok', { user: publicUser(user) });

      await run('UPDATE sessions SET last_active = ? WHERE token = ?', [Date.now(), token]);
      await run('UPDATE dms SET delivered = 1 WHERE to_id = ? AND delivered = 0', [user.id]);

      const senders = await q('SELECT DISTINCT from_id FROM dms WHERE to_id = ? AND delivered = 1', [user.id]);
      senders.forEach(s2 => {
        io.to('user:' + s2.from_id).emit('dm-delivered', { toId: user.id });
      });

      io.emit('user-online', { userId: user.id });
    } catch (e) { console.error('Auth socket error:', e); }
  });

  socket.on('check-online', async (data) => {
    const targetId = data && data.userId;
    const online = isUserOnline(targetId);
    let last_seen = null;
    if (!online) {
      const u = await q1('SELECT last_seen FROM users WHERE id = ?', [targetId]);
      last_seen = u ? u.last_seen : null;
    }
    socket.emit('online-status', { userId: targetId, online, last_seen });
  });

  socket.on('dm-send', async (data) => {
    const u = socket.userId;
    if (!u) return;
    if (!checkRate(socket.id, 'dm', 30, 60000)) return;
    const toId = data && data.toId;
    if (toId === u) return;
    if (await isBlocked(u, toId)) return;
    const t = String((data && data.text) || '').trim().slice(0, 1000);
    if (!t) return;
    const now = Date.now();
    const delivered = isUserOnline(toId) ? 1 : 0;
    const r = await run('INSERT INTO dms (from_id, to_id, text, time, read, delivered) VALUES (?,?,?,?,0,?)',
      [u, toId, encryptText(t), now, delivered]);
    const sender = await q1('SELECT * FROM users WHERE id = ?', [u]);
    const out = {
      id: r.lastInsertRowid, from_id: u, to_id: toId,
      text: t, time: now, read: false, delivered: !!delivered,
      from_name: sender ? sender.display_name : ''
    };
    io.to('user:' + u).emit('dm-message', out);
    io.to('user:' + toId).emit('dm-message', out);
    io.to('user:' + toId).emit('notification', { type: 'dm', from: publicUser(sender), text: t.slice(0, 80) });
    sendPushToUser(toId, {
      title: sender.display_name, body: t.slice(0, 80),
      url: '/?chat=' + u, type: 'dm', tag: 'dm-' + u
    });
  });

  socket.on('dm-read', async (data) => {
    const u = socket.userId;
    if (!u) return;
    const fromId = data && data.fromId;
    await run('UPDATE dms SET read = 1, delivered = 1 WHERE from_id = ? AND to_id = ? AND read = 0', [fromId, u]);
    io.to('user:' + fromId).emit('dm-read-receipt', { byId: u });
  });

  socket.on('dm-typing', (data) => {
    const u = socket.userId;
    if (!u) return;
    const toId = data && data.toId;
    if (toId === u) return;
    io.to('user:' + toId).emit('dm-typing', { fromId: u, isTyping: !!(data && data.isTyping) });
  });

  socket.on('disconnect', async () => {
    const uid = socket.userId;
    if (!uid) return;
    const becameOffline = removeSocketForUser(uid, socket.id);
    if (becameOffline) {
      const now = Date.now();
      await run('UPDATE users SET last_seen = ? WHERE id = ?', [now, uid]);
      io.emit('user-offline', { userId: uid, last_seen: now });
    }
  });
});

// ===== Background =====
setInterval(async () => {
  try {
    const cutoff = Date.now() - MESSAGE_TTL_MS;
    await run('DELETE FROM dms WHERE time < ?', [cutoff]);
  } catch (_){}
}, 600000);

setInterval(async () => {
  try {
    // حذف الجلسات المنتهية + مستخدمين بلا جلسات
    const cutoff = Date.now() - SESSION_TTL_MS;
    const expired = await q('SELECT DISTINCT user_id FROM sessions WHERE last_active < ?', [cutoff]);
    for (const e of expired) {
      await run('DELETE FROM sessions WHERE user_id = ?', [e.user_id]);
      // هل للمستخدم session نشطة؟
      const still = await q1('SELECT 1 FROM sessions WHERE user_id = ? LIMIT 1', [e.user_id]);
      if (!still) {
        // حذف المستخدم وكل بياناته
        const uid = e.user_id;
        await run('DELETE FROM dms WHERE from_id = ? OR to_id = ?', [uid, uid]);
        await run('DELETE FROM blocks WHERE user1 = ? OR user2 = ?', [uid, uid]);
        await run('DELETE FROM post_likes WHERE user_id = ?', [uid]);
        await run('DELETE FROM post_comments WHERE user_id = ?', [uid]);
        await run('DELETE FROM posts WHERE user_id = ?', [uid]);
        await run('DELETE FROM friendships WHERE user1 = ? OR user2 = ?', [uid, uid]);
        await run('DELETE FROM push_subs WHERE user_id = ?', [uid]);
        await run('DELETE FROM notifications WHERE user_id = ? OR from_user_id = ?', [uid, uid]);
        await run('DELETE FROM users WHERE id = ?', [uid]);
        io.emit('user-deleted', { userId: uid });
        console.log('🗑️ حُذف حساب منتهي: ' + uid);
      }
    }
    await run('DELETE FROM audit_log WHERE time < ?', [Date.now() - 30 * 24 * 3600 * 1000]);
  } catch (_){}
}, 3600000);

// ===== Start =====
async function start() {
  try { await initDB(); } catch (e) { console.error('initDB error:', e.message); }
  server.listen(PORT, '0.0.0.0', () => {
    console.log('✅ Server running on port ' + PORT);
    console.log('🌍 Env: ' + NODE_ENV);
    console.log('📊 DB: Turso');
    console.log('🔔 Push: ' + (PUSH_ENABLED ? 'ON' : 'OFF'));
    console.log('🎫 Session TTL: 7 days');
    console.log('💬 Message TTL: 48 hours');
  });
}

let shuttingDown = false;
async function shutdown(sig) {
  if (shuttingDown) return;
  shuttingDown = true;
  const t = setTimeout(() => process.exit(1), 10000);
  t.unref();
  try {
    await new Promise(r => io.close(r));
    await new Promise(r => server.close(r));
    process.exit(0);
  } catch (_) { process.exit(1); }
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('uncaughtException', e => console.error('💥', e));
process.on('unhandledRejection', e => console.error('💥', e));

start();
