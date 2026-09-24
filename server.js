require('dotenv').config();
const path = require('path');
const fs = require('fs');
const http = require('http');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const Database = require('better-sqlite3');
const rateLimit = require('express-rate-limit');
const { Server } = require('socket.io');

const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const COLORS = ['#f87171','#fb923c','#facc15','#4ade80','#22d3ee','#818cf8','#c084fc','#f472b6','#e11d48','#0ea5e9'];
const USERNAME_CHANGE_DAYS = 7;
const MESSAGE_TTL_MS = 48 * 3600 * 1000;

// ===== Data Dir =====
const DATA_DIR = process.env.DATA_DIR && fs.existsSync(process.env.DATA_DIR)
  ? process.env.DATA_DIR
  : (fs.existsSync('/data') ? '/data' : __dirname);
if (!fs.existsSync(DATA_DIR)) { try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch(_){} }
const DB_FILE     = path.join(DATA_DIR, 'data.db');
const LEGACY_JSON = path.join(DATA_DIR, 'data.json');
const SECRET_FILE = path.join(DATA_DIR, '.secret');
const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) { try { fs.mkdirSync(UPLOADS_DIR, { recursive: true }); } catch(_){} }

// ===== SECRET KEY =====
let SECRET_KEY;
if (fs.existsSync(SECRET_FILE)) {
  try { SECRET_KEY = Buffer.from(fs.readFileSync(SECRET_FILE, 'utf8'), 'hex'); }
  catch(_) { SECRET_KEY = crypto.randomBytes(32); }
} else {
  SECRET_KEY = crypto.randomBytes(32);
  try { fs.writeFileSync(SECRET_FILE, SECRET_KEY.toString('hex')); } catch(_){}
}

// ===== Crypto helpers =====
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

// ===== SQLite Init =====
const db = new Database(DB_FILE);
db.pragma('journal_mode = WAL');
db.pragma('synchronous = NORMAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    password TEXT NOT NULL,
    color TEXT,
    bio TEXT DEFAULT '',
    location TEXT DEFAULT '',
    country TEXT DEFAULT '',
    phone TEXT DEFAULT '',
    verified INTEGER DEFAULT 0,
    avatar TEXT DEFAULT '',
    cover TEXT DEFAULT '',
    created_at INTEGER,
    last_seen INTEGER,
    username_changed_at INTEGER DEFAULT 0,
    lang TEXT DEFAULT 'ar',
    theme TEXT DEFAULT 'dark',
    sound INTEGER DEFAULT 1,
    notifications INTEGER DEFAULT 1
  );

  CREATE TABLE IF NOT EXISTS tokens (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at INTEGER
  );

  CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    text TEXT,
    image TEXT,
    time INTEGER,
    deleted INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS post_likes (
    post_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    PRIMARY KEY (post_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS post_comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    text TEXT,
    time INTEGER
  );

  CREATE TABLE IF NOT EXISTS hashtags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tag TEXT NOT NULL,
    source_type TEXT,
    source_id INTEGER,
    time INTEGER
  );

  CREATE TABLE IF NOT EXISTS friendships (
    user1 INTEGER NOT NULL,
    user2 INTEGER NOT NULL,
    status TEXT NOT NULL,
    PRIMARY KEY (user1, user2)
  );

  CREATE TABLE IF NOT EXISTS dms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_id INTEGER NOT NULL,
    to_id INTEGER NOT NULL,
    text TEXT,
    image TEXT,
    time INTEGER,
    read INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS blocks (
    user1 INTEGER NOT NULL,
    user2 INTEGER NOT NULL,
    time INTEGER,
    PRIMARY KEY (user1, user2)
  );

  CREATE TABLE IF NOT EXISTS profile_views (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    viewer_id INTEGER,
    viewed_id INTEGER,
    time INTEGER
  );

  CREATE INDEX IF NOT EXISTS idx_dms_conv   ON dms(from_id, to_id, time);
  CREATE INDEX IF NOT EXISTS idx_dms_to     ON dms(to_id, read);
  CREATE INDEX IF NOT EXISTS idx_dms_ttl    ON dms(time);
  CREATE INDEX IF NOT EXISTS idx_posts_user ON posts(user_id, time);
  CREATE INDEX IF NOT EXISTS idx_posts_time ON posts(time);
  CREATE INDEX IF NOT EXISTS idx_hashtags   ON hashtags(tag, source_type, time);
  CREATE INDEX IF NOT EXISTS idx_comments   ON post_comments(post_id);
  CREATE INDEX IF NOT EXISTS idx_views      ON profile_views(viewed_id);
  CREATE INDEX IF NOT EXISTS idx_tokens_usr ON tokens(user_id);
`);

// ===== Migration from legacy data.json =====
function migrateFromJSON() {
  if (!fs.existsSync(LEGACY_JSON)) return;
  const userCount = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
  if (userCount > 0) {
    console.log('ℹ️ يوجد بيانات في SQLite — تجاهل data.json');
    return;
  }
  try {
    const raw = JSON.parse(fs.readFileSync(LEGACY_JSON, 'utf8'));
    const trx = db.transaction(() => {
      (raw.users || []).forEach(u => {
        db.prepare(`INSERT INTO users (id, username, display_name, password, color, bio, location, country, phone,
          verified, avatar, cover, created_at, last_seen, username_changed_at, lang, theme, sound, notifications)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
          u.id, u.username, u.display_name, u.password, u.color || COLORS[0],
          u.bio || '', u.location || '', u.country || '', u.phone || '',
          u.verified ? 1 : 0, u.avatar || '', u.cover || '',
          u.created_at || Date.now(), u.last_seen || Date.now(),
          u.username_changed_at || 0, u.lang || 'ar', u.theme || 'dark',
          u.sound ? 1 : 0, u.notifications ? 1 : 0
        );
      });
      (raw.tokens || []).forEach(t => {
        db.prepare('INSERT OR IGNORE INTO tokens (token, user_id, created_at) VALUES (?,?,?)')
          .run(t.token, t.user_id, t.created_at || Date.now());
      });
      (raw.posts || []).forEach(p => {
        db.prepare('INSERT INTO posts (id, user_id, text, image, time, deleted) VALUES (?,?,?,?,?,?)')
          .run(p.id, p.user_id, p.text, p.image, p.time, p.deleted || 0);
      });
      (raw.post_likes || []).forEach(l => {
        db.prepare('INSERT OR IGNORE INTO post_likes (post_id, user_id) VALUES (?,?)')
          .run(l.post_id, l.user_id);
      });
      (raw.post_comments || []).forEach(c => {
        db.prepare('INSERT INTO post_comments (id, post_id, user_id, text, time) VALUES (?,?,?,?,?)')
          .run(c.id, c.post_id, c.user_id, c.text, c.time);
      });
      (raw.hashtags || []).forEach(h => {
        db.prepare('INSERT INTO hashtags (id, tag, source_type, source_id, time) VALUES (?,?,?,?,?)')
          .run(h.id, h.tag, h.source_type, h.source_id, h.time);
      });
      (raw.friendships || []).forEach(f => {
        db.prepare('INSERT OR IGNORE INTO friendships (user1, user2, status) VALUES (?,?,?)')
          .run(f.user1, f.user2, f.status);
      });
      (raw.dms || []).forEach(d => {
        db.prepare('INSERT INTO dms (id, from_id, to_id, text, image, time, read) VALUES (?,?,?,?,?,?,?)')
          .run(d.id, d.from_id, d.to_id, d.text, d.image, d.time, d.read ? 1 : 0);
      });
      (raw.blocks || []).forEach(b => {
        db.prepare('INSERT OR IGNORE INTO blocks (user1, user2, time) VALUES (?,?,?)')
          .run(b.user1, b.user2, b.time || Date.now());
      });
      (raw.profile_views || []).forEach(v => {
        db.prepare('INSERT INTO profile_views (viewer_id, viewed_id, time) VALUES (?,?,?)')
          .run(v.viewer_id, v.viewed_id, v.time || Date.now());
      });
    });
    trx();
    fs.renameSync(LEGACY_JSON, LEGACY_JSON + '.imported');
    console.log('✅ تم استيراد data.json إلى SQLite');
  } catch (e) {
    console.error('❌ فشل استيراد data.json:', e.message);
  }
}
migrateFromJSON();

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
app.use('/uploads', express.static(UPLOADS_DIR));

// ===== Rate Limiting =====
const disableRL = process.env.RATE_LIMIT_DISABLED === 'true';
const makeLimit = (opts) => rateLimit({
  standardHeaders: true,
  legacyHeaders: false,
  skip: () => disableRL,
  ...opts
});

const limiterLogin = makeLimit({
  windowMs: 15 * 60 * 1000, max: 10,
  message: { error: 'too_many_attempts' }
});
const limiterRegister = makeLimit({
  windowMs: 60 * 60 * 1000, max: 5,
  message: { error: 'too_many_registrations' }
});
const limiterAPI = makeLimit({
  windowMs: 60 * 1000, max: 120,
  message: { error: 'too_many_requests' }
});
const limiterUpload = makeLimit({
  windowMs: 60 * 60 * 1000, max: 40,
  message: { error: 'too_many_uploads' }
});
const limiterWrite = makeLimit({
  windowMs: 60 * 1000, max: 30,
  message: { error: 'too_many_writes' }
});

app.use('/api/', limiterAPI);
app.use('/api/login', limiterLogin);
app.use('/api/register', limiterRegister);
app.post('/api/posts', limiterWrite);
app.post('/api/posts/:id/comment', limiterWrite);
app.post('/upload', limiterUpload);

// ===== Prepared Statements =====
const S = {
  findUserByUsername: db.prepare('SELECT * FROM users WHERE username = ?'),
  findUserByDisplayName: db.prepare('SELECT * FROM users WHERE display_name = ?'),
  findUserById: db.prepare('SELECT * FROM users WHERE id = ?'),
  insertUser: db.prepare(`INSERT INTO users
    (username, display_name, password, color, bio, location, country, phone, verified, created_at, last_seen, username_changed_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`),
  updateUserField: db.prepare('UPDATE users SET display_name = ?, bio = ?, location = ?, country = ?, phone = ?, avatar = ?, cover = ?, color = ?, lang = ?, theme = ?, sound = ?, notifications = ?, username = ?, username_changed_at = ?, verified = ? WHERE id = ?'),
  updateLastSeen: db.prepare('UPDATE users SET last_seen = ? WHERE id = ?'),
  updatePassword: db.prepare('UPDATE users SET password = ? WHERE id = ?'),
  deleteUser: db.prepare('DELETE FROM users WHERE id = ?'),
  listUsersExclude: db.prepare('SELECT * FROM users WHERE id != ? LIMIT ?'),

  insertToken: db.prepare('INSERT INTO tokens (token, user_id, created_at) VALUES (?,?,?)'),
  findToken: db.prepare('SELECT * FROM tokens WHERE token = ?'),
  deleteTokensByUser: db.prepare('DELETE FROM tokens WHERE user_id = ?'),
  deleteOldTokens: db.prepare('DELETE FROM tokens WHERE created_at < ?'),

  insertPost: db.prepare('INSERT INTO posts (user_id, text, image, time, deleted) VALUES (?,?,?,?,0)'),
  getPost: db.prepare('SELECT * FROM posts WHERE id = ?'),
  deletePost: db.prepare('UPDATE posts SET deleted = 1, text = ?, image = NULL WHERE id = ?'),
  postsByUser: db.prepare('SELECT * FROM posts WHERE deleted = 0 AND user_id = ? ORDER BY time DESC LIMIT ?'),

  getLike: db.prepare('SELECT 1 FROM post_likes WHERE post_id = ? AND user_id = ?'),
  insertLike: db.prepare('INSERT INTO post_likes (post_id, user_id) VALUES (?,?)'),
  deleteLike: db.prepare('DELETE FROM post_likes WHERE post_id = ? AND user_id = ?'),
  countLikes: db.prepare('SELECT COUNT(*) AS c FROM post_likes WHERE post_id = ?'),
  countComments: db.prepare('SELECT COUNT(*) AS c FROM post_comments WHERE post_id = ?'),

  insertComment: db.prepare('INSERT INTO post_comments (post_id, user_id, text, time) VALUES (?,?,?,?)'),
  commentsByPost: db.prepare('SELECT * FROM post_comments WHERE post_id = ? ORDER BY time ASC'),

  insertHashtag: db.prepare('INSERT INTO hashtags (tag, source_type, source_id, time) VALUES (?,?,?,?)'),
  hashtagsSince: db.prepare('SELECT tag, COUNT(*) AS c FROM hashtags WHERE time > ? AND source_type = ? GROUP BY tag ORDER BY c DESC LIMIT 20'),
  postIdsByHashtag: db.prepare('SELECT DISTINCT source_id FROM hashtags WHERE tag = ? AND source_type = ?'),

  findFriendship: db.prepare('SELECT * FROM friendships WHERE (user1 = ? AND user2 = ?) OR (user1 = ? AND user2 = ?)'),
  insertFriendship: db.prepare('INSERT INTO friendships (user1, user2, status) VALUES (?,?,?)'),
  updateFriendshipStatus: db.prepare('UPDATE friendships SET status = ? WHERE user1 = ? AND user2 = ?'),
  deleteFriendship: db.prepare('DELETE FROM friendships WHERE (user1 = ? AND user2 = ?) OR (user1 = ? AND user2 = ?)'),
  pendingRequestsTo: db.prepare('SELECT * FROM friendships WHERE user2 = ? AND status = ?'),
  friendsOf: db.prepare(`SELECT u.* FROM users u
    JOIN friendships f ON ((f.user1 = u.id AND f.user2 = ?) OR (f.user2 = u.id AND f.user1 = ?))
    WHERE f.status = 'accepted'`),
  friendIdsOf: db.prepare(`SELECT CASE WHEN user1 = ? THEN user2 ELSE user1 END AS id
    FROM friendships WHERE (user1 = ? OR user2 = ?) AND status = 'accepted'`),

  insertDM: db.prepare('INSERT INTO dms (from_id, to_id, text, image, time, read) VALUES (?,?,?,?,?,0)'),
  dmsBetween: db.prepare(`SELECT * FROM dms WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?) ORDER BY time ASC LIMIT 100`),
  markDMsRead: db.prepare('UPDATE dms SET read = 1 WHERE from_id = ? AND to_id = ? AND read = 0'),
  unreadCount: db.prepare('SELECT COUNT(*) AS c FROM dms WHERE from_id = ? AND to_id = ? AND read = 0'),
  lastDM: db.prepare(`SELECT * FROM dms WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?) ORDER BY time DESC LIMIT 1`),
  conversationPartners: db.prepare(`SELECT DISTINCT CASE WHEN from_id = ? THEN to_id ELSE from_id END AS id FROM dms WHERE from_id = ? OR to_id = ?`),
  deleteDMsByUser: db.prepare('DELETE FROM dms WHERE from_id = ? OR to_id = ?'),
  purgeOldDMs: db.prepare('DELETE FROM dms WHERE time < ?'),

  findBlock: db.prepare('SELECT 1 FROM blocks WHERE (user1 = ? AND user2 = ?) OR (user1 = ? AND user2 = ?)'),
  insertBlock: db.prepare('INSERT OR IGNORE INTO blocks (user1, user2, time) VALUES (?,?,?)'),
  deleteBlock: db.prepare('DELETE FROM blocks WHERE (user1 = ? AND user2 = ?) OR (user1 = ? AND user2 = ?)'),
  blocksByUser: db.prepare('SELECT * FROM blocks WHERE user1 = ?'),
  deleteBlocksByUser: db.prepare('DELETE FROM blocks WHERE user1 = ? OR user2 = ?'),

  insertView: db.prepare('INSERT INTO profile_views (viewer_id, viewed_id, time) VALUES (?,?,?)'),
  countViews: db.prepare('SELECT COUNT(*) AS c FROM profile_views WHERE viewed_id = ?'),
  deleteViewsByUser: db.prepare('DELETE FROM profile_views WHERE viewer_id = ? OR viewed_id = ?'),
  trimViews: db.prepare('DELETE FROM profile_views WHERE id NOT IN (SELECT id FROM profile_views ORDER BY id DESC LIMIT 5000)'),

  countFriends: db.prepare(`SELECT COUNT(*) AS c FROM friendships
    WHERE (user1 = ? OR user2 = ?) AND status = 'accepted'`),
  countUserPosts: db.prepare('SELECT COUNT(*) AS c FROM posts WHERE user_id = ? AND deleted = 0')
};

// ===== Helpers =====
function getUser(id) { return S.findUserById.get(id); }

function publicUser(u) {
  if (!u) return null;
  return {
    id: u.id, username: u.username, display_name: u.display_name,
    color: u.color, bio: u.bio, location: u.location, country: u.country,
    verified: !!u.verified, avatar: u.avatar, cover: u.cover || '',
    created_at: u.created_at, last_seen: u.last_seen,
    lang: u.lang, theme: u.theme, sound: !!u.sound, notifications: !!u.notifications,
    username_changed_at: u.username_changed_at || 0,
    phone: u.phone ? (u.phone.slice(0, 3) + '***' + u.phone.slice(-2)) : ''
  };
}

function isBlocked(a, b) {
  return !!S.findBlock.get(a, b, b, a);
}

function genUsername(name) {
  let base = String(name || 'user').toLowerCase().replace(/[^a-z0-9]/gi, '').slice(0, 10) || 'user';
  let candidate = base, i = 1;
  while (S.findUserByUsername.get(candidate)) {
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

function formatPost(p, viewerId) {
  if (!p) return null;
  const u = getUser(p.user_id);
  return {
    id: p.id, text: decryptText(p.text), image: p.image, time: p.time,
    user: publicUser(u),
    likes: S.countLikes.get(p.id).c,
    comments: S.countComments.get(p.id).c,
    liked: viewerId ? !!S.getLike.get(p.id, viewerId) : false
  };
}

function mapComments(postId) {
  return S.commentsByPost.all(postId).map(c => {
    const u = getUser(c.user_id);
    return {
      id: c.id, text: decryptText(c.text), time: c.time,
      user: u ? { username: u.username, display_name: u.display_name, color: u.color, verified: !!u.verified, avatar: u.avatar } : null
    };
  });
}

// ===== Auth middleware =====
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.replace('Bearer ', '') || req.query.token;
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  const t = S.findToken.get(token);
  if (!t) return res.status(401).json({ error: 'invalid_token' });
  const user = getUser(t.user_id);
  if (!user) return res.status(401).json({ error: 'user_not_found' });
  req.user = user;
  next();
}

// ===== Health =====
let startTime = Date.now();
app.get('/health', (req, res) => {
  try {
    const userCount = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
    const dmCount = db.prepare('SELECT COUNT(*) AS c FROM dms').get().c;

    let diskFreeMB = null, diskTotalMB = null;
    try {
      if (fs.statfsSync) {
        const st = fs.statfsSync(DATA_DIR);
        diskFreeMB = Math.round((st.bavail * st.bsize) / 1024 / 1024);
        diskTotalMB = Math.round((st.blocks * st.bsize) / 1024 / 1024);
      }
    } catch(_){}

    let walMB = null;
    try { if (fs.existsSync(DB_FILE + '-wal')) walMB = Math.round(fs.statSync(DB_FILE + '-wal').size / 1024 / 1024 * 100) / 100; } catch(_){}

    const healthy = diskFreeMB === null || diskFreeMB > 10;

    res.status(healthy ? 200 : 503).json({
      ok: healthy,
      uptime_s: Math.floor((Date.now() - startTime) / 1000),
      env: NODE_ENV,
      users: userCount,
      online: onlineSockets.size,
      dms: dmCount,
      disk: { free_mb: diskFreeMB, total_mb: diskTotalMB, wal_mb: walMB },
      data_dir: DATA_DIR,
      time: Date.now()
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ===== Upload =====
const storage = multer.diskStorage({
  destination: UPLOADS_DIR,
  filename: (req, file, cb) => {
    const ext = (path.extname(file.originalname) || '.jpg').toLowerCase().replace(/[^.a-z0-9]/g, '');
    cb(null, Date.now() + '_' + crypto.randomBytes(4).toString('hex') + ext);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 4 * 1024 * 1024 },
  fileFilter: (req, file, cb) => cb(null, /^image\//.test(file.mimetype))
});
app.post('/upload', auth, upload.single('image'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'invalid' });
  res.json({ url: '/uploads/' + req.file.filename });
});

// ===== AUTH ROUTES =====
app.post('/api/register', (req, res) => {
  const body = req.body || {};
  const name = String(body.display_name || '').trim().slice(0, 30);
  const pass = String(body.password || '');
  if (!name) return res.status(400).json({ error: 'name_required' });
  if (pass.length < 4) return res.status(400).json({ error: 'password_too_short' });
  if (S.findUserByDisplayName.get(name)) return res.status(409).json({ error: 'name_taken' });

  const username = genUsername(name);
  const color = /^#[0-9a-fA-F]{6}$/.test(body.color || '') ? body.color : COLORS[Math.floor(Math.random() * COLORS.length)];
  const now = Date.now();
  const info = S.insertUser.run(
    username, name, hashPassword(pass), color,
    String(body.bio || '').slice(0, 200),
    String(body.location || '').slice(0, 60),
    String(body.country || '').slice(0, 40),
    String(body.phone || '').slice(0, 20),
    0, now, now, now
  );
  const user = getUser(info.lastInsertRowid);
  const token = genToken();
  S.insertToken.run(token, user.id, now);
  res.json({ token, user: publicUser(user) });
});

app.post('/api/login', (req, res) => {
  const body = req.body || {};
  const key = String(body.username || '').trim();
  const pass = String(body.password || '');
  let user = S.findUserByUsername.get(key.toLowerCase());
  if (!user) user = S.findUserByDisplayName.get(key);
  if (!user) return res.status(401).json({ error: 'invalid_credentials' });
  if (!verifyPassword(pass, user.password)) return res.status(401).json({ error: 'invalid_credentials' });
  const token = genToken();
  const now = Date.now();
  S.insertToken.run(token, user.id, now);
  S.updateLastSeen.run(now, user.id);
  res.json({ token, user: publicUser(user) });
});

app.get('/api/me', auth, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

app.get('/api/me/stats', auth, (req, res) => {
  const uid = req.user.id;
  res.json({
    friends: S.countFriends.get(uid, uid).c,
    posts: S.countUserPosts.get(uid).c,
    views: S.countViews.get(uid).c
  });
});

app.put('/api/me', auth, (req, res) => {
  const b = req.body || {};
  const u = req.user;
  const next = {
    display_name: u.display_name, bio: u.bio, location: u.location,
    country: u.country, phone: u.phone, avatar: u.avatar, cover: u.cover,
    color: u.color, lang: u.lang, theme: u.theme, sound: u.sound,
    notifications: u.notifications, username: u.username,
    username_changed_at: u.username_changed_at, verified: u.verified
  };

  if (b.display_name !== undefined) {
    const nm = String(b.display_name).trim().slice(0, 30);
    if (!nm) return res.status(400).json({ error: 'name_required' });
    const dup = S.findUserByDisplayName.get(nm);
    if (dup && dup.id !== u.id) return res.status(409).json({ error: 'name_taken' });
    next.display_name = nm;
  }
  if (b.username !== undefined) {
    const un = String(b.username).trim().toLowerCase().slice(0, 20).replace(/[^a-z0-9_]/g, '');
    if (un.length < 3) return res.status(400).json({ error: 'username_too_short' });
    if (un !== u.username) {
      const daysSince = (Date.now() - (u.username_changed_at || 0)) / 86400000;
      if (daysSince < USERNAME_CHANGE_DAYS) {
        return res.status(429).json({ error: 'username_cooldown', days_left: Math.ceil(USERNAME_CHANGE_DAYS - daysSince) });
      }
      const dup = S.findUserByUsername.get(un);
      if (dup && dup.id !== u.id) return res.status(409).json({ error: 'username_taken' });
      next.username = un;
      next.username_changed_at = Date.now();
    }
  }
  if (b.bio !== undefined) next.bio = String(b.bio).slice(0, 200);
  if (b.location !== undefined) next.location = String(b.location).slice(0, 60);
  if (b.country !== undefined) next.country = String(b.country).slice(0, 40);
  if (b.phone !== undefined) {
    next.phone = String(b.phone).slice(0, 20);
    if (next.phone.replace(/\D/g, '').length >= 8) next.verified = 1;
  }
  if (b.avatar !== undefined) next.avatar = String(b.avatar).slice(0, 300);
  if (b.cover !== undefined) next.cover = String(b.cover).slice(0, 300);
  if (b.color !== undefined && /^#[0-9a-fA-F]{6}$/.test(b.color)) next.color = b.color;
  if (b.lang !== undefined && ['ar','en'].includes(b.lang)) next.lang = b.lang;
  if (b.theme !== undefined && ['dark','light'].includes(b.theme)) next.theme = b.theme;
  if (b.sound !== undefined) next.sound = b.sound ? 1 : 0;
  if (b.notifications !== undefined) next.notifications = b.notifications ? 1 : 0;

  S.updateUserField.run(
    next.display_name, next.bio, next.location, next.country, next.phone,
    next.avatar, next.cover, next.color, next.lang, next.theme,
    next.sound, next.notifications, next.username, next.username_changed_at,
    next.verified, u.id
  );
  res.json({ user: publicUser(getUser(u.id)) });
});

app.post('/api/change-password', auth, (req, res) => {
  const b = req.body || {};
  const oldPass = String(b.old_password || '');
  const newPass = String(b.new_password || '');
  if (!oldPass) return res.status(400).json({ error: 'old_required' });
  if (newPass.length < 4) return res.status(400).json({ error: 'password_too_short' });
  if (!verifyPassword(oldPass, req.user.password)) return res.status(401).json({ error: 'wrong_old_password' });
  S.updatePassword.run(hashPassword(newPass), req.user.id);
  res.json({ ok: true });
});

app.delete('/api/me', auth, (req, res) => {
  const uid = req.user.id;
  const trx = db.transaction(() => {
    S.deleteTokensByUser.run(uid);
    S.deleteDMsByUser.run(uid, uid);
    S.deleteBlocksByUser.run(uid, uid);
    S.deleteViewsByUser.run(uid, uid);
    db.prepare('DELETE FROM post_likes WHERE user_id = ?').run(uid);
    db.prepare('DELETE FROM post_comments WHERE user_id = ?').run(uid);
    db.prepare('DELETE FROM posts WHERE user_id = ?').run(uid);
    db.prepare('DELETE FROM friendships WHERE user1 = ? OR user2 = ?').run(uid, uid);
    S.deleteUser.run(uid);
  });
  trx();
  res.json({ ok: true });
});

// ===== BLOCKS =====
app.post('/api/block/:id', auth, (req, res) => {
  const target = parseInt(req.params.id);
  if (target === req.user.id) return res.status(400).json({ error: 'self' });
  if (!getUser(target)) return res.status(404).json({ error: 'not_found' });
  S.insertBlock.run(req.user.id, target, Date.now());
  res.json({ ok: true });
});
app.post('/api/unblock/:id', auth, (req, res) => {
  const target = parseInt(req.params.id);
  S.deleteBlock.run(req.user.id, target, target, req.user.id);
  res.json({ ok: true });
});
app.get('/api/blocks', auth, (req, res) => {
  const rows = S.blocksByUser.all(req.user.id)
    .map(b => getUser(b.user2)).filter(Boolean);
  res.json({ blocks: rows.map(publicUser) });
});

// ===== USERS =====
app.get('/api/users/search', auth, (req, res) => {
  const q = String(req.query.q || '').trim().slice(0, 40);
  if (!q) return res.json({ users: [] });
  const lq = '%' + q.toLowerCase() + '%';
  const rows = db.prepare(`
    SELECT * FROM users
    WHERE id != ? AND (LOWER(username) LIKE ? OR LOWER(display_name) LIKE ?)
    LIMIT 30
  `).all(req.user.id, lq, lq)
    .filter(u => !isBlocked(req.user.id, u.id));
  res.json({ users: rows.map(publicUser) });
});

app.get('/api/users/:id', auth, (req, res) => {
  const u = getUser(parseInt(req.params.id));
  if (!u) return res.status(404).json({ error: 'not_found' });
  const f = S.findFriendship.get(req.user.id, u.id, u.id, req.user.id);
  const isFriend = f && f.status === 'accepted';
  const blocked = isBlocked(req.user.id, u.id);
  if (u.id !== req.user.id) {
    S.insertView.run(req.user.id, u.id, Date.now());
    S.trimViews.run();
  }
  res.json({
    user: publicUser(u),
    isFriend,
    blocked,
    stats: {
      friends: S.countFriends.get(u.id, u.id).c,
      posts: S.countUserPosts.get(u.id).c,
      views: S.countViews.get(u.id).c
    }
  });
});

// ===== POSTS =====
app.post('/api/posts', auth, (req, res) => {
  const b = req.body || {};
  const t = String(b.text || '').trim().slice(0, 1000);
  const img = b.image ? String(b.image).slice(0, 300) : null;
  if (!t && !img) return res.status(400).json({ error: 'empty' });
  const now = Date.now();
  const info = S.insertPost.run(req.user.id, encryptText(t), img, now);
  const pid = info.lastInsertRowid;
  extractHashtags(t).forEach(tag => S.insertHashtag.run(tag, 'post', pid, now));
  const post = S.getPost.get(pid);
  res.json({ post: formatPost(post, req.user.id) });
});

app.get('/api/posts', auth, (req, res) => {
  const lim = Math.min(parseInt(req.query.limit) || 30, 100);
  const { username, user_id, hashtag } = req.query;
  let rows;
  if (hashtag) {
    const tag = String(hashtag).replace(/^#/, '').toLowerCase();
    const ids = S.postIdsByHashtag.all(tag, 'post').map(r => r.source_id);
    if (!ids.length) rows = [];
    else {
      const ph = ids.map(() => '?').join(',');
      rows = db.prepare(`SELECT * FROM posts WHERE deleted = 0 AND id IN (${ph}) ORDER BY time DESC LIMIT ?`)
        .all(...ids, lim);
    }
  } else if (user_id) {
    rows = S.postsByUser.all(parseInt(user_id), lim);
  } else if (username) {
    const u = S.findUserByUsername.get(username);
    if (!u) return res.json({ posts: [] });
    rows = S.postsByUser.all(u.id, lim);
  } else {
    const friendIds = S.friendIdsOf.all(req.user.id, req.user.id, req.user.id).map(r => r.id);
    const ids = [req.user.id, ...friendIds];
    const ph = ids.map(() => '?').join(',');
    rows = db.prepare(`SELECT * FROM posts WHERE deleted = 0 AND user_id IN (${ph}) ORDER BY time DESC LIMIT ?`)
      .all(...ids, lim);
  }
  res.json({ posts: rows.map(p => formatPost(p, req.user.id)) });
});

app.post('/api/posts/:id/like', auth, (req, res) => {
  const id = parseInt(req.params.id);
  const liked = !!S.getLike.get(id, req.user.id);
  if (liked) S.deleteLike.run(id, req.user.id);
  else S.insertLike.run(id, req.user.id);
  res.json({ likes: S.countLikes.get(id).c, liked: !liked });
});

app.get('/api/posts/:id/comments', auth, (req, res) => {
  res.json({ comments: mapComments(parseInt(req.params.id)) });
});
app.post('/api/posts/:id/comment', auth, (req, res) => {
  const id = parseInt(req.params.id);
  const text = String((req.body || {}).text || '').trim().slice(0, 500);
  if (!text) return res.status(400).json({ error: 'empty' });
  S.insertComment.run(id, req.user.id, encryptText(text), Date.now());
  res.json({ comments: mapComments(id) });
});
app.delete('/api/posts/:id', auth, (req, res) => {
  const p = S.getPost.get(parseInt(req.params.id));
  if (!p || p.user_id !== req.user.id) return res.status(403).json({ error: 'forbidden' });
  S.deletePost.run('', p.id);
  res.json({ ok: true });
});

// ===== TRENDS =====
app.get('/api/trends', auth, (req, res) => {
  const since = Date.now() - 7 * 24 * 3600 * 1000;
  const rows = S.hashtagsSince.all(since, 'post');
  res.json({ trends: rows.map(r => ({ tag: r.tag, c: r.c })) });
});

// ===== SUGGESTIONS =====
app.get('/api/suggestions', auth, (req, res) => {
  const uid = req.user.id;
  const friendIds = new Set(S.friendIdsOf.all(uid, uid, uid).map(r => r.id));
  const pendingRows = db.prepare(`
    SELECT CASE WHEN user1 = ? THEN user2 ELSE user1 END AS id
    FROM friendships WHERE (user1 = ? OR user2 = ?) AND status = 'pending'
  `).all(uid, uid, uid);
  const pendingIds = new Set(pendingRows.map(r => r.id));
  const list = S.listUsersExclude.all(uid, 50)
    .filter(u => !friendIds.has(u.id) && !pendingIds.has(u.id) && !isBlocked(uid, u.id))
    .slice(0, 10);
  res.json({ users: list.map(publicUser) });
});

// ===== FRIENDS =====
app.get('/api/friends', auth, (req, res) => {
  const friends = S.friendsOf.all(req.user.id, req.user.id);
  res.json({ friends: friends.map(publicUser) });
});

app.get('/api/friends/requests', auth, (req, res) => {
  const rows = S.pendingRequestsTo.all(req.user.id, 'pending');
  const list = rows.map(f => getUser(f.user1)).filter(Boolean);
  res.json({ requests: list.map(publicUser) });
});

app.post('/api/friends/request/:id', auth, (req, res) => {
  const target = parseInt(req.params.id);
  if (target === req.user.id) return res.status(400).json({ error: 'self' });
  if (isBlocked(req.user.id, target)) return res.status(403).json({ error: 'blocked' });
  if (!getUser(target)) return res.status(404).json({ error: 'not_found' });
  const exists = S.findFriendship.get(req.user.id, target, target, req.user.id);
  if (exists) return res.status(409).json({ error: 'exists', status: exists.status });
  S.insertFriendship.run(req.user.id, target, 'pending');
  onlineSockets.forEach((uid, sid) => {
    if (uid === target) {
      io.to(sid).emit('notification', { type: 'friend_request', from: publicUser(req.user), text: 'طلب صداقة جديد' });
    }
  });
  res.json({ ok: true });
});
app.post('/api/friends/accept/:id', auth, (req, res) => {
  const fromId = parseInt(req.params.id);
  const info = S.updateFriendshipStatus.run('accepted', fromId, req.user.id);
  if (!info.changes) return res.status(404).json({ error: 'not_found' });
  res.json({ ok: true });
});
app.post('/api/friends/reject/:id', auth, (req, res) => {
  const fromId = parseInt(req.params.id);
  db.prepare("DELETE FROM friendships WHERE user1 = ? AND user2 = ? AND status = 'pending'")
    .run(fromId, req.user.id);
  res.json({ ok: true });
});
app.delete('/api/friends/:id', auth, (req, res) => {
  const target = parseInt(req.params.id);
  S.deleteFriendship.run(req.user.id, target, target, req.user.id);
  res.json({ ok: true });
});

// ===== DMs =====
app.get('/api/dms/:userId', auth, (req, res) => {
  const other = parseInt(req.params.userId);
  if (other === req.user.id) return res.status(400).json({ error: 'self' });
  if (isBlocked(req.user.id, other)) return res.status(403).json({ error: 'blocked' });
  const msgs = S.dmsBetween.all(req.user.id, other, other, req.user.id);
  S.markDMsRead.run(other, req.user.id);
  res.json({
    messages: msgs.map(m => ({
      id: m.id, from_id: m.from_id, to_id: m.to_id,
      text: decryptText(m.text), image: m.image, time: m.time, read: !!m.read
    }))
  });
});

app.get('/api/dm-conversations', auth, (req, res) => {
  const uid = req.user.id;
  const partners = S.conversationPartners.all(uid, uid, uid);
  const conversations = [];
  partners.forEach(p => {
    const other = getUser(p.id);
    if (!other) return;
    const last = S.lastDM.get(uid, p.id, p.id, uid);
    const unread = S.unreadCount.get(p.id, uid).c;
    conversations.push({
      user: publicUser(other),
      last: last ? { text: decryptText(last.text), image: last.image, time: last.time, from_id: last.from_id } : null,
      unread
    });
  });
  conversations.sort((a, b) => (b.last?.time || 0) - (a.last?.time || 0));
  res.json({ conversations });
});

// ===== Socket.IO =====
const onlineSockets = new Map();

const socketRate = new Map();
function checkSocketRate(socketId, key, max, windowMs) {
  const now = Date.now();
  const id = socketId + ':' + key;
  const entry = socketRate.get(id) || { count: 0, reset: now + windowMs };
  if (now > entry.reset) { entry.count = 0; entry.reset = now + windowMs; }
  entry.count++;
  socketRate.set(id, entry);
  return entry.count <= max;
}
setInterval(() => {
  const now = Date.now();
  socketRate.forEach((v, k) => { if (now > v.reset) socketRate.delete(k); });
}, 60000);

io.on('connection', (socket) => {

  socket.on('auth', (data) => {
    const token = data && data.token;
    const t = S.findToken.get(token);
    if (!t) return socket.emit('auth-error', { error: 'invalid_token' });
    const user = getUser(t.user_id);
    if (!user) return socket.emit('auth-error', { error: 'user_not_found' });
    onlineSockets.set(socket.id, user.id);
    socket.emit('auth-ok', { user: publicUser(user) });
  });

  socket.on('check-online', (data) => {
    const targetId = data && data.userId;
    let online = false;
    onlineSockets.forEach(uid => { if (uid === targetId) online = true; });
    socket.emit('online-status', { userId: targetId, online });
  });

  socket.on('dm-send', (data) => {
    const u = onlineSockets.get(socket.id);
    if (!u) return;
    if (!checkSocketRate(socket.id, 'dm', 30, 60000)) return;
    const toId = data && data.toId;
    if (toId === u) return;
    if (isBlocked(u, toId)) return;
    const t = String((data && data.text) || '').trim().slice(0, 1000);
    const img = (data && data.image) ? String(data.image).slice(0, 300) : null;
    if (!t && !img) return;
    const now = Date.now();
    const info = S.insertDM.run(u, toId, encryptText(t), img, now);
    const out = { id: info.lastInsertRowid, from_id: u, to_id: toId, text: t, image: img, time: now, read: false };
    socket.emit('dm-message', out);
    onlineSockets.forEach((uid, sid) => {
      if (uid === toId) {
        io.to(sid).emit('dm-message', out);
        io.to(sid).emit('notification', { type: 'dm', from: publicUser(getUser(u)), text: t || '📷 صورة' });
      }
    });
  });

  socket.on('dm-read', (data) => {
    const u = onlineSockets.get(socket.id);
    if (!u) return;
    const fromId = data && data.fromId;
    S.markDMsRead.run(fromId, u);
    onlineSockets.forEach((uid, sid) => {
      if (uid === fromId) io.to(sid).emit('dm-read-receipt', { byId: u });
    });
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

  socket.on('call-start', (data) => {
    const u = onlineSockets.get(socket.id);
    if (!u) return;
    if (!checkSocketRate(socket.id, 'call', 5, 60000)) return;
    const targetId = data && data.targetId;
    if (targetId === u || isBlocked(u, targetId)) return;
    const user = getUser(u);
    onlineSockets.forEach((uid, sid) => {
      if (uid === targetId) {
        io.to(sid).emit('incoming-call', {
          fromId: socket.id, fromUserId: u,
          fromName: user.display_name, fromColor: user.color, fromAvatar: user.avatar
        });
      }
    });
  });
  socket.on('call-accept', (data) => {
    const u = onlineSockets.get(socket.id);
    if (!u) return;
    io.to(data.toId).emit('call-accepted', { fromId: socket.id, fromUserId: u, fromName: getUser(u).display_name });
  });
  socket.on('call-reject', (data) => {
    const u = onlineSockets.get(socket.id);
    if (!u) return;
    io.to(data.toId).emit('call-rejected', { fromId: socket.id, fromName: getUser(u).display_name });
  });
  socket.on('call-end', (data) => io.to(data.toId).emit('call-ended', { fromId: socket.id }));
  socket.on('webrtc-offer', (data) => io.to(data.toId).emit('webrtc-offer', { fromId: socket.id, offer: data.offer }));
  socket.on('webrtc-answer', (data) => io.to(data.toId).emit('webrtc-answer', { fromId: socket.id, answer: data.answer }));
  socket.on('webrtc-ice', (data) => io.to(data.toId).emit('webrtc-ice', { fromId: socket.id, candidate: data.candidate }));

  socket.on('disconnect', () => {
    onlineSockets.delete(socket.id);
    socketRate.forEach((v, k) => { if (k.startsWith(socket.id + ':')) socketRate.delete(k); });
  });
});

// ===== Background jobs =====
setInterval(() => {
  try {
    const cutoff = Date.now() - MESSAGE_TTL_MS;
    const info = S.purgeOldDMs.run(cutoff);
    if (info.changes) console.log('🧹 حذف ' + info.changes + ' رسالة قديمة');
  } catch (e) { console.error('TTL cleanup:', e.message); }
}, 10 * 60 * 1000);

setInterval(() => {
  try {
    const cutoff = Date.now() - 30 * 24 * 3600 * 1000;
    S.deleteOldTokens.run(cutoff);
  } catch (_){}
}, 60 * 60 * 1000);

setInterval(() => {
  try { db.pragma('wal_checkpoint(TRUNCATE)'); } catch (_){}
}, 30 * 60 * 1000);

// ===== Start =====
async function start() {
  server.listen(PORT, '0.0.0.0', () => {
    console.log('✅ السيرفر يعمل على المنفذ ' + PORT);
    console.log('📊 قاعدة البيانات: SQLite');
    console.log('💾 المسار: ' + DB_FILE);
    console.log('🌍 البيئة: ' + NODE_ENV);
    console.log('🛡️ Rate limiting: ' + (disableRL ? 'معطّل' : 'مفعّل'));
  });
}

// ===== Graceful shutdown =====
let shuttingDown = false;
async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log('\n🛑 إشارة ' + signal + ' — جارٍ الإغلاق...');

  const forceTimeout = setTimeout(() => {
    console.error('⚠️ تجاوز الوقت — إغلاق قسري');
    process.exit(1);
  }, 10000);
  forceTimeout.unref();

  try {
    await new Promise(resolve => io.close(resolve));
    console.log('✅ Socket.IO أُغلق');

    await new Promise(resolve => server.close(resolve));
    console.log('✅ HTTP أُغلق');

    try { db.pragma('wal_checkpoint(TRUNCATE)'); } catch (_){}
    try { db.close(); } catch (_){}
    console.log('✅ SQLite أُغلق');

    process.exit(0);
  } catch (e) {
    console.error('خطأ أثناء الإغلاق:', e);
    process.exit(1);
  }
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));
process.on('uncaughtException', (e) => { console.error('💥 uncaughtException:', e); });
process.on('unhandledRejection', (e) => { console.error('💥 unhandledRejection:', e); });

start();
