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
const cloudinary = require('cloudinary').v2;
const webpush = require('web-push');

const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const COLORS = ['#e8b567','#f4a261','#ff6b8a','#4ecdc4','#7c9cff','#c084fc','#f472b6','#34d399','#22d3ee','#e11d48'];
const USERNAME_CHANGE_DAYS = 7;
const MESSAGE_TTL_MS = 48 * 3600 * 1000;

// ===== VAPID =====
const VAPID_PUBLIC = process.env.VAPID_PUBLIC_KEY || '';
const VAPID_PRIVATE = process.env.VAPID_PRIVATE_KEY || '';
const VAPID_EMAIL = process.env.VAPID_EMAIL || 'mailto:admin@example.com';
const PUSH_ENABLED = !!(VAPID_PUBLIC && VAPID_PRIVATE);

if (PUSH_ENABLED) {
  webpush.setVapidDetails(VAPID_EMAIL, VAPID_PUBLIC, VAPID_PRIVATE);
  console.log('✅ Push notifications enabled');
} else {
  console.log('⚠️ Push notifications disabled (no VAPID keys)');
}

// ===== Turso DB =====
const TURSO_URL = process.env.TURSO_URL || '';
const TURSO_TOKEN = process.env.TURSO_TOKEN || '';

if (!TURSO_URL || !TURSO_TOKEN) {
  console.error('❌ TURSO_URL / TURSO_TOKEN missing');
  process.exit(1);
}

const db = createClient({ url: TURSO_URL, authToken: TURSO_TOKEN });

// ===== Cloudinary =====
if (process.env.CLOUDINARY_CLOUD) {
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD,
    api_key: process.env.CLOUDINARY_KEY,
    api_secret: process.env.CLOUDINARY_SECRET
  });
}

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
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return salt + ':' + hash;
}
function verifyPassword(password, stored) {
  try {
    const parts = stored.split(':');
    const test = crypto.scryptSync(password, parts[0], 64).toString('hex');
    return crypto.timingSafeEqual(Buffer.from(parts[1], 'hex'), Buffer.from(test, 'hex'));
  } catch (_) { return false; }
}
function genToken() { return crypto.randomBytes(32).toString('hex'); }

// ===== DB INIT =====
async function initDB() {
  const stmts = [
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
      display_name TEXT NOT NULL, password TEXT NOT NULL, color TEXT,
      bio TEXT DEFAULT '', location TEXT DEFAULT '', country TEXT DEFAULT '',
      phone TEXT DEFAULT '', verified INTEGER DEFAULT 0, avatar TEXT DEFAULT '',
      cover TEXT DEFAULT '', created_at INTEGER, last_seen INTEGER,
      username_changed_at INTEGER DEFAULT 0, lang TEXT DEFAULT 'ar',
      theme TEXT DEFAULT 'dark', sound INTEGER DEFAULT 1, notifications INTEGER DEFAULT 1
    )`,
    `CREATE TABLE IF NOT EXISTS tokens (token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, created_at INTEGER)`,
    `CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
      text TEXT, time INTEGER, deleted INTEGER DEFAULT 0
    )`,
    `CREATE TABLE IF NOT EXISTS post_likes (post_id INTEGER, user_id INTEGER, PRIMARY KEY (post_id, user_id))`,
    `CREATE TABLE IF NOT EXISTS post_comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT, post_id INTEGER, user_id INTEGER, text TEXT, time INTEGER
    )`,
    `CREATE TABLE IF NOT EXISTS hashtags (
      id INTEGER PRIMARY KEY AUTOINCREMENT, tag TEXT, source_type TEXT, source_id INTEGER, time INTEGER
    )`,
    `CREATE TABLE IF NOT EXISTS friendships (user1 INTEGER, user2 INTEGER, status TEXT, PRIMARY KEY (user1, user2))`,
    `CREATE TABLE IF NOT EXISTS dms (
      id INTEGER PRIMARY KEY AUTOINCREMENT, from_id INTEGER, to_id INTEGER,
      text TEXT, time INTEGER, read INTEGER DEFAULT 0, delivered INTEGER DEFAULT 0
    )`,
    `CREATE TABLE IF NOT EXISTS blocks (user1 INTEGER, user2 INTEGER, time INTEGER, PRIMARY KEY (user1, user2))`,
    `CREATE TABLE IF NOT EXISTS profile_views (id INTEGER PRIMARY KEY AUTOINCREMENT, viewer_id INTEGER, viewed_id INTEGER, time INTEGER)`,
    `CREATE TABLE IF NOT EXISTS push_subs (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, endpoint TEXT UNIQUE, keys TEXT, time INTEGER)`,
    `CREATE INDEX IF NOT EXISTS idx_dms_conv ON dms(from_id, to_id, time)`,
    `CREATE INDEX IF NOT EXISTS idx_dms_to ON dms(to_id, read)`,
    `CREATE INDEX IF NOT EXISTS idx_posts_time ON posts(time)`,
    `CREATE INDEX IF NOT EXISTS idx_push_usr ON push_subs(user_id)`
  ];
  for (const sql of stmts) {
    try { await db.execute(sql); } catch (e) { console.error('SQL error:', e.message); }
  }
  console.log('✅ DB initialized');
}

// ===== Helpers =====
async function q(sql, args = []) {
  const res = await db.execute({ sql, args });
  return res.rows;
}
async function q1(sql, args = []) { return (await q(sql, args))[0] || null; }
async function run(sql, args = []) { return await db.execute({ sql, args }); }

function publicUser(u) {
  if (!u) return null;
  const online = isUserOnline(u.id);
  return {
    id: u.id, username: u.username, display_name: u.display_name,
    color: u.color, bio: u.bio, location: u.location, country: u.country,
    verified: !!u.verified, avatar: u.avatar, cover: u.cover || '',
    created_at: u.created_at, last_seen: u.last_seen,
    lang: u.lang, theme: u.theme, sound: !!u.sound, notifications: !!u.notifications,
    username_changed_at: u.username_changed_at || 0,
    phone: u.phone ? (u.phone.slice(0, 3) + '***' + u.phone.slice(-2)) : '',
    online: online
  };
}

async function isBlocked(a, b) {
  const r = await q1('SELECT 1 FROM blocks WHERE (user1 = ? AND user2 = ?) OR (user1 = ? AND user2 = ?)', [a, b, b, a]);
  return !!r;
}
async function genUsername(name) {
  let base = String(name || 'user').toLowerCase().replace(/[^a-z0-9]/gi, '').slice(0, 10) || 'user';
  let candidate = base, i = 1;
  while (await q1('SELECT 1 FROM users WHERE username = ?', [candidate])) {
    candidate = base + i; i++;
    if (i > 9999) { candidate = 'user' + crypto.randomBytes(3).toString('hex'); break; }
  }
  return candidate;
}
function extractHashtags(text) {
  const tags = [];
  const re = /#([\u0600-\u06FF\w_]{1,40})/g;
  let m;
  while ((m = re.exec(text)) !== null) tags.push(m[1].toLowerCase());
  return Array.from(new Set(tags));
}

// ===== Push Notifications =====
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
  cors: { origin: '*', methods: ['GET','POST'] },
  maxHttpBufferSize: 5 * 1024 * 1024,
  pingTimeout: 60000,
  pingInterval: 25000
});

app.set('trust proxy', 1);
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ===== Rate Limit =====
const disableRL = process.env.RATE_LIMIT_DISABLED === 'true';
const mkLimit = (o) => rateLimit({ standardHeaders: true, legacyHeaders: false, skip: () => disableRL, ...o });
app.use('/api/', mkLimit({ windowMs: 60000, max: 120 }));
app.use('/api/login', mkLimit({ windowMs: 15*60000, max: 10 }));
app.use('/api/register', mkLimit({ windowMs: 3600000, max: 5 }));

// ===== Online tracking =====
const onlineSockets = new Map(); // socket.id -> userId
function isUserOnline(userId) {
  for (const uid of onlineSockets.values()) if (uid === userId) return true;
  return false;
}
function getOnlineCount(userId) {
  let c = 0;
  for (const uid of onlineSockets.values()) if (uid === userId) c++;
  return c;
}

// ===== Auth middleware =====
async function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.replace('Bearer ', '') || req.query.token;
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  const t = await q1('SELECT * FROM tokens WHERE token = ?', [token]);
  if (!t) return res.status(401).json({ error: 'invalid_token' });
  const user = await q1('SELECT * FROM users WHERE id = ?', [t.user_id]);
  if (!user) return res.status(401).json({ error: 'user_not_found' });
  req.user = user;
  next();
}

// ===== Health =====
const startTime = Date.now();
app.get('/health', (req, res) => {
  res.json({ ok: true, uptime_s: Math.floor((Date.now() - startTime)/1000), env: NODE_ENV, online: onlineSockets.size, push: PUSH_ENABLED });
});

// ===== VAPID public key endpoint =====
app.get('/api/vapid-public', (req, res) => {
  res.json({ key: VAPID_PUBLIC });
});

// ===== AUTH =====
app.post('/api/register', async (req, res) => {
  try {
    const b = req.body || {};
    const name = String(b.display_name || '').trim().slice(0, 30);
    const pass = String(b.password || '');
    if (!name) return res.status(400).json({ error: 'name_required' });
    if (pass.length < 4) return res.status(400).json({ error: 'password_too_short' });
    if (await q1('SELECT 1 FROM users WHERE display_name = ?', [name])) return res.status(409).json({ error: 'name_taken' });

    const username = await genUsername(name);
    const color = /^#[0-9a-fA-F]{6}$/.test(b.color || '') ? b.color : COLORS[Math.floor(Math.random() * COLORS.length)];
    const now = Date.now();
    const r = await run(`INSERT INTO users (username, display_name, password, color, bio, location, country, phone, verified, created_at, last_seen, username_changed_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
      [username, name, hashPassword(pass), color, String(b.bio||'').slice(0,200), String(b.location||'').slice(0,60),
       String(b.country||'').slice(0,40), String(b.phone||'').slice(0,20), 0, now, now, now]);
    const user = await q1('SELECT * FROM users WHERE id = ?', [r.lastInsertRowid]);
    const token = genToken();
    await run('INSERT INTO tokens (token, user_id, created_at) VALUES (?,?,?)', [token, user.id, now]);
    res.json({ token, user: publicUser(user) });
  } catch (e) { console.error(e); res.status(500).json({ error: 'server_error' }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const b = req.body || {};
    const key = String(b.username || '').trim();
    const pass = String(b.password || '');
    let user = await q1('SELECT * FROM users WHERE username = ?', [key.toLowerCase()]);
    if (!user) user = await q1('SELECT * FROM users WHERE display_name = ?', [key]);
    if (!user) return res.status(401).json({ error: 'invalid_credentials' });
    if (!verifyPassword(pass, user.password)) return res.status(401).json({ error: 'invalid_credentials' });
    const token = genToken();
    const now = Date.now();
    await run('INSERT INTO tokens (token, user_id, created_at) VALUES (?,?,?)', [token, user.id, now]);
    await run('UPDATE users SET last_seen = ? WHERE id = ?', [now, user.id]);
    res.json({ token, user: publicUser(user) });
  } catch (e) { console.error(e); res.status(500).json({ error: 'server_error' }); }
});

app.get('/api/me', auth, async (req, res) => {
  const u = await q1('SELECT * FROM users WHERE id = ?', [req.user.id]);
  res.json({ user: publicUser(u) });
});

app.get('/api/me/stats', auth, async (req, res) => {
  const uid = req.user.id;
  const friends = (await q1(`SELECT COUNT(*) AS c FROM friendships WHERE (user1 = ? OR user2 = ?) AND status = 'accepted'`, [uid, uid])).c;
  const posts = (await q1('SELECT COUNT(*) AS c FROM posts WHERE user_id = ? AND deleted = 0', [uid])).c;
  const views = (await q1('SELECT COUNT(*) AS c FROM profile_views WHERE viewed_id = ?', [uid])).c;
  res.json({ friends, posts, views });
});

app.put('/api/me', auth, async (req, res) => {
  try {
    const b = req.body || {};
    const u = req.user;
    const fields = [], args = [];
    if (b.display_name !== undefined) {
      const nm = String(b.display_name).trim().slice(0, 30);
      if (!nm) return res.status(400).json({ error: 'name_required' });
      const dup = await q1('SELECT id FROM users WHERE display_name = ? AND id != ?', [nm, u.id]);
      if (dup) return res.status(409).json({ error: 'name_taken' });
      fields.push('display_name = ?'); args.push(nm);
    }
    if (b.username !== undefined) {
      const un = String(b.username).trim().toLowerCase().slice(0, 20).replace(/[^a-z0-9_]/g, '');
      if (un.length < 3) return res.status(400).json({ error: 'username_too_short' });
      if (un !== u.username) {
        const daysSince = (Date.now() - (u.username_changed_at || 0)) / 86400000;
        if (daysSince < USERNAME_CHANGE_DAYS) return res.status(429).json({ error: 'username_cooldown', days_left: Math.ceil(USERNAME_CHANGE_DAYS - daysSince) });
        const dup = await q1('SELECT id FROM users WHERE username = ? AND id != ?', [un, u.id]);
        if (dup) return res.status(409).json({ error: 'username_taken' });
        fields.push('username = ?'); args.push(un);
        fields.push('username_changed_at = ?'); args.push(Date.now());
      }
    }
    if (b.bio !== undefined) { fields.push('bio = ?'); args.push(String(b.bio).slice(0, 200)); }
    if (b.location !== undefined) { fields.push('location = ?'); args.push(String(b.location).slice(0, 60)); }
    if (b.country !== undefined) { fields.push('country = ?'); args.push(String(b.country).slice(0, 40)); }
    if (b.phone !== undefined) {
      const p = String(b.phone).slice(0, 20);
      fields.push('phone = ?'); args.push(p);
      if (p.replace(/\D/g, '').length >= 8) { fields.push('verified = ?'); args.push(1); }
    }
    if (b.avatar !== undefined) { fields.push('avatar = ?'); args.push(String(b.avatar).slice(0, 300)); }
    if (b.cover !== undefined) { fields.push('cover = ?'); args.push(String(b.cover).slice(0, 300)); }
    if (b.color !== undefined && /^#[0-9a-fA-F]{6}$/.test(b.color)) { fields.push('color = ?'); args.push(b.color); }
    if (b.lang !== undefined && ['ar','en'].includes(b.lang)) { fields.push('lang = ?'); args.push(b.lang); }
    if (b.theme !== undefined && ['dark','light'].includes(b.theme)) { fields.push('theme = ?'); args.push(b.theme); }
    if (b.sound !== undefined) { fields.push('sound = ?'); args.push(b.sound ? 1 : 0); }
    if (b.notifications !== undefined) { fields.push('notifications = ?'); args.push(b.notifications ? 1 : 0); }
    if (!fields.length) return res.json({ user: publicUser(u) });
    args.push(u.id);
    await run(`UPDATE users SET ${fields.join(', ')} WHERE id = ?`, args);
    const updated = await q1('SELECT * FROM users WHERE id = ?', [u.id]);
    res.json({ user: publicUser(updated) });
  } catch (e) { console.error(e); res.status(500).json({ error: 'server_error' }); }
});

app.post('/api/change-password', auth, async (req, res) => {
  const b = req.body || {};
  const oldPass = String(b.old_password || '');
  const newPass = String(b.new_password || '');
  if (!oldPass) return res.status(400).json({ error: 'old_required' });
  if (newPass.length < 4) return res.status(400).json({ error: 'password_too_short' });
  if (!verifyPassword(oldPass, req.user.password)) return res.status(401).json({ error: 'wrong_old_password' });
  await run('UPDATE users SET password = ? WHERE id = ?', [hashPassword(newPass), req.user.id]);
  res.json({ ok: true });
});

app.delete('/api/me', auth, async (req, res) => {
  const uid = req.user.id;
  await run('DELETE FROM tokens WHERE user_id = ?', [uid]);
  await run('DELETE FROM dms WHERE from_id = ? OR to_id = ?', [uid, uid]);
  await run('DELETE FROM blocks WHERE user1 = ? OR user2 = ?', [uid, uid]);
  await run('DELETE FROM profile_views WHERE viewer_id = ? OR viewed_id = ?', [uid, uid]);
  await run('DELETE FROM post_likes WHERE user_id = ?', [uid]);
  await run('DELETE FROM post_comments WHERE user_id = ?', [uid]);
  await run('DELETE FROM posts WHERE user_id = ?', [uid]);
  await run('DELETE FROM friendships WHERE user1 = ? OR user2 = ?', [uid, uid]);
  await run('DELETE FROM push_subs WHERE user_id = ?', [uid]);
  await run('DELETE FROM users WHERE id = ?', [uid]);
  res.json({ ok: true });
});

// ===== PUSH SUBSCRIBE =====
app.post('/api/push/subscribe', auth, async (req, res) => {
  try {
    const sub = req.body;
    if (!sub || !sub.endpoint || !sub.keys) return res.status(400).json({ error: 'invalid_subscription' });
    await run('INSERT OR REPLACE INTO push_subs (user_id, endpoint, keys, time) VALUES (?,?,?,?)',
      [req.user.id, sub.endpoint, JSON.stringify(sub.keys), Date.now()]);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'server_error' }); }
});
app.post('/api/push/unsubscribe', auth, async (req, res) => {
  await run('DELETE FROM push_subs WHERE user_id = ? AND endpoint = ?', [req.user.id, req.body.endpoint || '']);
  res.json({ ok: true });
});

// ===== BLOCKS =====
app.post('/api/block/:id', auth, async (req, res) => {
  const t = parseInt(req.params.id);
  if (t === req.user.id) return res.status(400).json({ error: 'self' });
  await run('INSERT OR IGNORE INTO blocks (user1, user2, time) VALUES (?,?,?)', [req.user.id, t, Date.now()]);
  res.json({ ok: true });
});
app.post('/api/unblock/:id', auth, async (req, res) => {
  const t = parseInt(req.params.id);
  await run('DELETE FROM blocks WHERE (user1 = ? AND user2 = ?) OR (user1 = ? AND user2 = ?)', [req.user.id, t, t, req.user.id]);
  res.json({ ok: true });
});
app.get('/api/blocks', auth, async (req, res) => {
  const rows = await q(`SELECT u.* FROM users u JOIN blocks b ON b.user2 = u.id WHERE b.user1 = ?`, [req.user.id]);
  res.json({ blocks: rows.map(publicUser) });
});

// ===== USERS =====
app.get('/api/users/search', auth, async (req, res) => {
  const s = String(req.query.q || '').trim().slice(0, 40);
  if (!s) return res.json({ users: [] });
  const lq = '%' + s.toLowerCase() + '%';
  const rows = await q(`SELECT * FROM users WHERE id != ? AND (LOWER(username) LIKE ? OR LOWER(display_name) LIKE ?) LIMIT 30`,
    [req.user.id, lq, lq]);
  const filtered = [];
  for (const u of rows) if (!await isBlocked(req.user.id, u.id)) filtered.push(u);
  res.json({ users: filtered.map(publicUser) });
});

app.get('/api/users/:id', auth, async (req, res) => {
  const u = await q1('SELECT * FROM users WHERE id = ?', [parseInt(req.params.id)]);
  if (!u) return res.status(404).json({ error: 'not_found' });
  const f = await q1('SELECT * FROM friendships WHERE (user1 = ? AND user2 = ?) OR (user1 = ? AND user2 = ?)',
    [req.user.id, u.id, u.id, req.user.id]);
  const isFriend = f && f.status === 'accepted';
  const blocked = await isBlocked(req.user.id, u.id);
  if (u.id !== req.user.id) await run('INSERT INTO profile_views (viewer_id, viewed_id, time) VALUES (?,?,?)', [req.user.id, u.id, Date.now()]);
  const friends = (await q1(`SELECT COUNT(*) AS c FROM friendships WHERE (user1 = ? OR user2 = ?) AND status = 'accepted'`, [u.id, u.id])).c;
  const posts = (await q1('SELECT COUNT(*) AS c FROM posts WHERE user_id = ? AND deleted = 0', [u.id])).c;
  const views = (await q1('SELECT COUNT(*) AS c FROM profile_views WHERE viewed_id = ?', [u.id])).c;
  res.json({ user: publicUser(u), isFriend, blocked, stats: { friends, posts, views } });
});

// ===== POSTS (بدون صور) =====
app.post('/api/posts', auth, async (req, res) => {
  const t = String((req.body || {}).text || '').trim().slice(0, 1000);
  if (!t) return res.status(400).json({ error: 'empty' });
  const now = Date.now();
  const r = await run('INSERT INTO posts (user_id, text, time, deleted) VALUES (?,?,?,0)', [req.user.id, encryptText(t), now]);
  const pid = r.lastInsertRowid;
  for (const tag of extractHashtags(t)) await run('INSERT INTO hashtags (tag, source_type, source_id, time) VALUES (?,?,?,?)', [tag, 'post', pid, now]);
  const p = await q1('SELECT * FROM posts WHERE id = ?', [pid]);
  const u = await q1('SELECT * FROM users WHERE id = ?', [p.user_id]);
  res.json({ post: { id: p.id, text: decryptText(p.text), time: p.time, user: publicUser(u), likes: 0, comments: 0, liked: false } });
});

app.get('/api/posts', auth, async (req, res) => {
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
    posts.push({ id: p.id, text: decryptText(p.text), time: p.time, user: publicUser(u), likes, comments, liked });
  }
  res.json({ posts });
});

app.post('/api/posts/:id/like', auth, async (req, res) => {
  const id = parseInt(req.params.id);
  const existing = await q1('SELECT 1 FROM post_likes WHERE post_id = ? AND user_id = ?', [id, req.user.id]);
  let liked;
  if (existing) { await run('DELETE FROM post_likes WHERE post_id = ? AND user_id = ?', [id, req.user.id]); liked = false; }
  else {
    await run('INSERT INTO post_likes (post_id, user_id) VALUES (?,?)', [id, req.user.id]); liked = true;
    // ✅ Notification to post owner
    const post = await q1('SELECT user_id FROM posts WHERE id = ?', [id]);
    if (post && post.user_id !== req.user.id) {
      const me = await q1('SELECT * FROM users WHERE id = ?', [req.user.id]);
      const notif = { type: 'like', from: publicUser(me), postId: id, text: me.display_name + ' أعجب بمنشورك' };
      onlineSockets.forEach((uid, sid) => { if (uid === post.user_id) io.to(sid).emit('notification', notif); });
      sendPushToUser(post.user_id, { title: '❤️ إعجاب جديد', body: me.display_name + ' أعجب بمنشورك', url: '/?tab=home', type: 'like' });
    }
  }
  const likes = (await q1('SELECT COUNT(*) AS c FROM post_likes WHERE post_id = ?', [id])).c;
  res.json({ likes, liked });
});

app.get('/api/posts/:id/comments', auth, async (req, res) => {
  const id = parseInt(req.params.id);
  const rows = await q('SELECT * FROM post_comments WHERE post_id = ? ORDER BY time ASC', [id]);
  const out = [];
  for (const c of rows) {
    const u = await q1('SELECT * FROM users WHERE id = ?', [c.user_id]);
    out.push({ id: c.id, text: decryptText(c.text), time: c.time, user: u ? { username: u.username, display_name: u.display_name, color: u.color, verified: !!u.verified, avatar: u.avatar } : null });
  }
  res.json({ comments: out });
});

app.post('/api/posts/:id/comment', auth, async (req, res) => {
  const id = parseInt(req.params.id);
  const text = String((req.body || {}).text || '').trim().slice(0, 500);
  if (!text) return res.status(400).json({ error: 'empty' });
  await run('INSERT INTO post_comments (post_id, user_id, text, time) VALUES (?,?,?,?)', [id, req.user.id, encryptText(text), Date.now()]);
  // ✅ Notify post owner
  const post = await q1('SELECT user_id FROM posts WHERE id = ?', [id]);
  if (post && post.user_id !== req.user.id) {
    const me = await q1('SELECT * FROM users WHERE id = ?', [req.user.id]);
    const notif = { type: 'comment', from: publicUser(me), postId: id, text: me.display_name + ' علّق على منشورك' };
    onlineSockets.forEach((uid, sid) => { if (uid === post.user_id) io.to(sid).emit('notification', notif); });
    sendPushToUser(post.user_id, { title: '💬 تعليق جديد', body: me.display_name + ': ' + text.slice(0, 60), url: '/?tab=home', type: 'comment' });
  }
  const rows = await q('SELECT * FROM post_comments WHERE post_id = ? ORDER BY time ASC', [id]);
  const out = [];
  for (const c of rows) {
    const u = await q1('SELECT * FROM users WHERE id = ?', [c.user_id]);
    out.push({ id: c.id, text: decryptText(c.text), time: c.time, user: u ? { username: u.username, display_name: u.display_name, color: u.color, verified: !!u.verified, avatar: u.avatar } : null });
  }
  res.json({ comments: out });
});

app.delete('/api/posts/:id', auth, async (req, res) => {
  const p = await q1('SELECT * FROM posts WHERE id = ?', [parseInt(req.params.id)]);
  if (!p || p.user_id !== req.user.id) return res.status(403).json({ error: 'forbidden' });
  await run('UPDATE posts SET deleted = 1, text = ? WHERE id = ?', ['', p.id]);
  res.json({ ok: true });
});

// ===== TRENDS =====
app.get('/api/trends', auth, async (req, res) => {
  const since = Date.now() - 7 * 24 * 3600 * 1000;
  const rows = await q('SELECT tag, COUNT(*) AS c FROM hashtags WHERE time > ? AND source_type = ? GROUP BY tag ORDER BY c DESC LIMIT 20', [since, 'post']);
  res.json({ trends: rows.map(r => ({ tag: r.tag, c: r.c })) });
});

// ===== SUGGESTIONS =====
app.get('/api/suggestions', auth, async (req, res) => {
  const uid = req.user.id;
  const friendRows = await q(`SELECT CASE WHEN user1 = ? THEN user2 ELSE user1 END AS id FROM friendships WHERE (user1 = ? OR user2 = ?) AND status = 'accepted'`, [uid, uid, uid]);
  const friendIds = new Set(friendRows.map(r => r.id));
  const pendingRows = await q(`SELECT CASE WHEN user1 = ? THEN user2 ELSE user1 END AS id FROM friendships WHERE (user1 = ? OR user2 = ?) AND status = 'pending'`, [uid, uid, uid]);
  const pendingIds = new Set(pendingRows.map(r => r.id));
  const users = await q('SELECT * FROM users WHERE id != ? LIMIT 50', [uid]);
  const list = [];
  for (const u of users) {
    if (friendIds.has(u.id) || pendingIds.has(u.id)) continue;
    if (await isBlocked(uid, u.id)) continue;
    list.push(u);
    if (list.length >= 10) break;
  }
  res.json({ users: list.map(publicUser) });
});

// ===== FRIENDS =====
app.get('/api/friends', auth, async (req, res) => {
  const rows = await q(`SELECT u.* FROM users u JOIN friendships f ON ((f.user1 = u.id AND f.user2 = ?) OR (f.user2 = u.id AND f.user1 = ?)) WHERE f.status = 'accepted'`, [req.user.id, req.user.id]);
  res.json({ friends: rows.map(publicUser) });
});

app.get('/api/friends/requests', auth, async (req, res) => {
  const rows = await q(`SELECT * FROM friendships WHERE user2 = ? AND status = 'pending'`, [req.user.id]);
  const list = [];
  for (const f of rows) { const u = await q1('SELECT * FROM users WHERE id = ?', [f.user1]); if (u) list.push(u); }
  res.json({ requests: list.map(publicUser) });
});

app.post('/api/friends/request/:id', auth, async (req, res) => {
  const t = parseInt(req.params.id);
  if (t === req.user.id) return res.status(400).json({ error: 'self' });
  if (await isBlocked(req.user.id, t)) return res.status(403).json({ error: 'blocked' });
  if (!await q1('SELECT 1 FROM users WHERE id = ?', [t])) return res.status(404).json({ error: 'not_found' });
  const exists = await q1('SELECT * FROM friendships WHERE (user1 = ? AND user2 = ?) OR (user1 = ? AND user2 = ?)', [req.user.id, t, t, req.user.id]);
  if (exists) return res.status(409).json({ error: 'exists', status: exists.status });
  await run('INSERT INTO friendships (user1, user2, status) VALUES (?,?,?)', [req.user.id, t, 'pending']);
  const me = await q1('SELECT * FROM users WHERE id = ?', [req.user.id]);
  const notif = { type: 'friend_request', from: publicUser(me), text: me.display_name + ' أرسل لك طلب صداقة' };
  onlineSockets.forEach((uid, sid) => { if (uid === t) io.to(sid).emit('notification', notif); });
  sendPushToUser(t, { title: '👥 طلب صداقة', body: me.display_name + ' أرسل لك طلب صداقة', url: '/?tab=notifs', type: 'friend_request' });
  res.json({ ok: true });
});

app.post('/api/friends/accept/:id', auth, async (req, res) => {
  const from = parseInt(req.params.id);
  const r = await run(`UPDATE friendships SET status = 'accepted' WHERE user1 = ? AND user2 = ? AND status = 'pending'`, [from, req.user.id]);
  if (!r.rowsAffected) return res.status(404).json({ error: 'not_found' });
  // ✅ Notify original sender
  const me = await q1('SELECT * FROM users WHERE id = ?', [req.user.id]);
  const notif = { type: 'friend_accept', from: publicUser(me), text: me.display_name + ' قبل طلب صداقتك' };
  onlineSockets.forEach((uid, sid) => { if (uid === from) io.to(sid).emit('notification', notif); });
  sendPushToUser(from, { title: '✅ تم قبول صداقتك', body: me.display_name + ' قبل طلب صداقتك', url: '/?tab=friends', type: 'friend_accept' });
  res.json({ ok: true });
});

app.post('/api/friends/reject/:id', auth, async (req, res) => {
  await run(`DELETE FROM friendships WHERE user1 = ? AND user2 = ? AND status = 'pending'`, [parseInt(req.params.id), req.user.id]);
  res.json({ ok: true });
});

app.delete('/api/friends/:id', auth, async (req, res) => {
  const t = parseInt(req.params.id);
  await run('DELETE FROM friendships WHERE (user1 = ? AND user2 = ?) OR (user1 = ? AND user2 = ?)', [req.user.id, t, t, req.user.id]);
  res.json({ ok: true });
});

// ===== DMs (بدون صور) =====
app.get('/api/dms/:userId', auth, async (req, res) => {
  const other = parseInt(req.params.userId);
  if (other === req.user.id) return res.status(400).json({ error: 'self' });
  if (await isBlocked(req.user.id, other)) return res.status(403).json({ error: 'blocked' });
  const msgs = await q(`SELECT * FROM dms WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?) ORDER BY time ASC LIMIT 100`,
    [req.user.id, other, other, req.user.id]);
  await run('UPDATE dms SET read = 1 WHERE from_id = ? AND to_id = ? AND read = 0', [other, req.user.id]);
  // Notify sender that msgs are read
  onlineSockets.forEach((uid, sid) => { if (uid === other) io.to(sid).emit('dm-read-receipt', { byId: req.user.id }); });
  res.json({
    messages: msgs.map(m => ({
      id: m.id, from_id: m.from_id, to_id: m.to_id,
      text: decryptText(m.text), time: m.time, read: !!m.read, delivered: !!m.delivered
    }))
  });
});

app.get('/api/dm-conversations', auth, async (req, res) => {
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
      const t = await q1('SELECT * FROM tokens WHERE token = ?', [token]);
      if (!t) return socket.emit('auth-error', { error: 'invalid_token' });
      const user = await q1('SELECT * FROM users WHERE id = ?', [t.user_id]);
      if (!user) return socket.emit('auth-error', { error: 'user_not_found' });

      onlineSockets.set(socket.id, user.id);
      socket.emit('auth-ok', { user: publicUser(user) });

      // Mark all pending DMs to this user as delivered
      await run('UPDATE dms SET delivered = 1 WHERE to_id = ? AND delivered = 0', [user.id]);

      // Notify senders
      const senders = await q('SELECT DISTINCT from_id FROM dms WHERE to_id = ? AND delivered = 1', [user.id]);
      senders.forEach(s => {
        onlineSockets.forEach((uid, sid) => {
          if (uid === s.from_id) io.to(sid).emit('dm-delivered', { toId: user.id });
        });
      });

      // Broadcast online status
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
    const u = onlineSockets.get(socket.id);
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
    socket.emit('dm-message', out);
    onlineSockets.forEach((uid, sid) => {
      if (uid === toId) {
        io.to(sid).emit('dm-message', out);
        io.to(sid).emit('notification', { type: 'dm', from: publicUser(sender), text: t.slice(0, 80) });
      }
    });
    // Push notification
    sendPushToUser(toId, {
      title: sender.display_name,
      body: t.slice(0, 80),
      url: '/?chat=' + u,
      type: 'dm',
      tag: 'dm-' + u
    });
  });

  socket.on('dm-read', async (data) => {
    const u = onlineSockets.get(socket.id);
    if (!u) return;
    const fromId = data && data.fromId;
    await run('UPDATE dms SET read = 1, delivered = 1 WHERE from_id = ? AND to_id = ? AND read = 0', [fromId, u]);
    onlineSockets.forEach((uid, sid) => { if (uid === fromId) io.to(sid).emit('dm-read-receipt', { byId: u }); });
  });

  socket.on('dm-typing', (data) => {
    const u = onlineSockets.get(socket.id);
    if (!u) return;
    const toId = data && data.toId;
    if (toId === u) return;
    onlineSockets.forEach((uid, sid) => {
      if (uid === toId) io.to(sid).emit('dm-typing', { fromId: u, isTyping: !!(data && data.isTyping) });
    });
  });

  socket.on('disconnect', async () => {
    const uid = onlineSockets.get(socket.id);
    onlineSockets.delete(socket.id);
    if (uid && !isUserOnline(uid)) {
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
}, 10 * 60 * 1000);

setInterval(async () => {
  try { await run('DELETE FROM tokens WHERE created_at < ?', [Date.now() - 30 * 24 * 3600 * 1000]); } catch (_){}
}, 3600000);

// ===== Start =====
async function start() {
  await initDB();
  server.listen(PORT, '0.0.0.0', () => {
    console.log('✅ Server running on port ' + PORT);
    console.log('🌍 Env: ' + NODE_ENV);
    console.log('📊 DB: Turso (libsql)');
    console.log('🔔 Push: ' + (PUSH_ENABLED ? 'ON' : 'OFF'));
  });
}

let shuttingDown = false;
async function shutdown(sig) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log('\n🛑 Shutdown ' + sig);
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
