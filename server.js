const path = require('path');
const fs = require('fs');
const http = require('http');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const initSqlJs = require('sql.js');
const { Server } = require('socket.io');

const PORT = process.env.PORT || 3000;
const ROOMS = [
  'بغداد','البصرة','نينوى','أربيل','النجف','كربلاء','ذي قار','الأنبار',
  'بابل','ديالى','واسط','ميسان','المثنى','القادسية','صلاح الدين','كركوك',
  'دهوك','السليمانية','حلبجة'
];
const COUNTRIES = [
  'العراق','مصر','السعودية','الإمارات','الأردن','الكويت','قطر','البحرين',
  'عمان','لبنان','سوريا','فلسطين','اليمن','المغرب','تونس','الجزائر',
  'ليبيا','السودان','تركيا','إيران'
];
const COLORS = ['#f87171','#fb923c','#facc15','#4ade80','#22d3ee','#818cf8','#c084fc','#f472b6','#e11d48','#0ea5e9'];
const MAX_HISTORY = 200;

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET','POST'] },
  maxHttpBufferSize: 5 * 1024 * 1024
});

app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const DB_FILE = path.join(__dirname, 'chat.db');
const SECRET_FILE = path.join(__dirname, '.secret');
let db = null;

let SECRET_KEY;
if (fs.existsSync(SECRET_FILE)) {
  SECRET_KEY = Buffer.from(fs.readFileSync(SECRET_FILE, 'utf8'), 'hex');
} else {
  SECRET_KEY = crypto.randomBytes(32);
  fs.writeFileSync(SECRET_FILE, SECRET_KEY.toString('hex'));
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
  if (!text || !text.startsWith('enc:')) return text;
  try {
    const data = Buffer.from(text.slice(4), 'base64');
    const iv = data.slice(0, 12);
    const tag = data.slice(12, 28);
    const enc = data.slice(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', SECRET_KEY, iv);
    decipher.setAuthTag(tag);
    return decipher.update(enc, undefined, 'utf8') + decipher.final('utf8');
  } catch (_) { return '[خطأ في فك التشفير]'; }
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return salt + ':' + hash;
}
function verifyPassword(password, stored) {
  try {
    const parts = stored.split(':');
    const salt = parts[0];
    const hash = parts[1];
    const test = crypto.scryptSync(password, salt, 64).toString('hex');
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(test, 'hex'));
  } catch (_) { return false; }
}
function genToken() { return crypto.randomBytes(32).toString('hex'); }

function saveDb() { fs.writeFileSync(DB_FILE, Buffer.from(db.export())); }

async function initDb() {
  const SQL = await initSqlJs();
  db = fs.existsSync(DB_FILE) ? new SQL.Database(fs.readFileSync(DB_FILE)) : new SQL.Database();
  db.run(`
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
      created_at INTEGER,
      last_seen INTEGER,
      lang TEXT DEFAULT 'ar',
      theme TEXT DEFAULT 'dark',
      sound INTEGER DEFAULT 1,
      notifications INTEGER DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS tokens (
      token TEXT PRIMARY KEY, user_id INTEGER, created_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      room TEXT, user_id INTEGER, text TEXT, image TEXT,
      time INTEGER, deleted INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS reactions (
      msgId INTEGER, user_id INTEGER, emoji TEXT,
      PRIMARY KEY (msgId, user_id, emoji)
    );
    CREATE TABLE IF NOT EXISTS pins (
      room TEXT PRIMARY KEY, msgId INTEGER, text TEXT, user_id INTEGER, time INTEGER
    );
    CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER, text TEXT, image TEXT,
      time INTEGER, deleted INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS post_likes (
      post_id INTEGER, user_id INTEGER,
      PRIMARY KEY (post_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS post_comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      post_id INTEGER, user_id INTEGER, text TEXT, time INTEGER
    );
    CREATE TABLE IF NOT EXISTS hashtags (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tag TEXT, source_type TEXT, source_id INTEGER, time INTEGER
    );
    CREATE TABLE IF NOT EXISTS friendships (
      user1 INTEGER, user2 INTEGER, status TEXT,
      PRIMARY KEY (user1, user2)
    );
    CREATE TABLE IF NOT EXISTS dms (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      from_id INTEGER, to_id INTEGER, text TEXT, image TEXT,
      time INTEGER, read INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS notifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER, type TEXT, from_id INTEGER,
      text TEXT, time INTEGER, read INTEGER DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room, id);
    CREATE INDEX IF NOT EXISTS idx_dms_pair ON dms(from_id, to_id, id);
    CREATE INDEX IF NOT EXISTS idx_posts_user ON posts(user_id, id);
    CREATE INDEX IF NOT EXISTS idx_hashtags_tag ON hashtags(tag, id);
  `);
  saveDb();
}

function queryAll(sql, params) {
  params = params || [];
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}
function queryOne(sql, params) {
  const rows = queryAll(sql, params);
  return rows[0] || null;
}
function run(sql, params) {
  params = params || [];
  db.run(sql, params);
  const res = db.exec('SELECT last_insert_rowid() as id');
  const id = (res && res[0] && res[0].values && res[0].values[0]) ? res[0].values[0][0] : 0;
  saveDb();
  return { lastInsertRowid: id };
}

const uploadsDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

const storage = multer.diskStorage({
  destination: uploadsDir,
  filename: (req, file, cb) => {
    const ext = (path.extname(file.originalname) || '.jpg').toLowerCase();
    cb(null, Date.now() + '_' + Math.random().toString(36).slice(2, 8) + ext);
  }
});
const upload = multer({
  storage: storage,
  limits: { fileSize: 4 * 1024 * 1024 },
  fileFilter: (req, file, cb) => cb(null, /^image\//.test(file.mimetype))
});

app.post('/upload', upload.single('image'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'ملف غير صالح' });
  res.json({ url: '/uploads/' + req.file.filename });
});

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.replace('Bearer ', '') || req.query.token;
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  const row = queryOne('SELECT user_id FROM tokens WHERE token=?', [token]);
  if (!row) return res.status(401).json({ error: 'invalid_token' });
  const user = queryOne('SELECT * FROM users WHERE id=?', [row.user_id]);
  if (!user) return res.status(401).json({ error: 'user_not_found' });
  req.user = user;
  next();
}

function publicUser(u) {
  if (!u) return null;
  return {
    id: u.id, username: u.username, display_name: u.display_name,
    color: u.color, bio: u.bio, location: u.location, country: u.country,
    verified: !!u.verified, avatar: u.avatar,
    created_at: u.created_at, last_seen: u.last_seen,
    lang: u.lang, theme: u.theme, sound: !!u.sound, notifications: !!u.notifications,
    phone: u.phone ? (u.phone.slice(0, 3) + '***' + u.phone.slice(-2)) : ''
  };
}

function genUsername(displayName) {
  let base = String(displayName || 'user').toLowerCase()
    .replace(/[^a-z0-9]/gi, '').slice(0, 10) || 'user';
  let candidate = base;
  let i = 1;
  while (queryOne('SELECT id FROM users WHERE username=?', [candidate])) {
    candidate = base + i;
    i++;
    if (i > 9999) { candidate = 'user' + crypto.randomBytes(3).toString('hex'); break; }
  }
  return candidate;
}

app.post('/api/register', (req, res) => {
  const body = req.body || {};
  const name = String(body.display_name || '').trim().slice(0, 30);
  const pass = String(body.password || '');

  if (!name) return res.status(400).json({ error: 'name_required' });
  if (pass.length < 4) return res.status(400).json({ error: 'password_too_short' });
  if (queryOne('SELECT id FROM users WHERE display_name=?', [name])) {
    return res.status(409).json({ error: 'name_taken' });
  }

  const username = genUsername(name);
  const color = /^#[0-9a-fA-F]{6}$/.test(body.color || '') ? body.color : COLORS[Math.floor(Math.random() * COLORS.length)];

  const info = run(
    'INSERT INTO users (username, display_name, password, color, bio, location, country, phone, created_at, last_seen) VALUES (?,?,?,?,?,?,?,?,?,?)',
    [username, name, hashPassword(pass), color,
     String(body.bio || '').slice(0, 200),
     String(body.location || '').slice(0, 60),
     String(body.country || '').slice(0, 40),
     String(body.phone || '').slice(0, 20),
     Date.now(), Date.now()]
  );

  const token = genToken();
  run('INSERT INTO tokens (token, user_id, created_at) VALUES (?,?,?)',
    [token, info.lastInsertRowid, Date.now()]);

  const user = queryOne('SELECT * FROM users WHERE id=?', [info.lastInsertRowid]);
  res.json({ token: token, user: publicUser(user) });
});

app.post('/api/login', (req, res) => {
  const body = req.body || {};
  const key = String(body.username || '').trim();
  const pass = String(body.password || '');

  let user = queryOne('SELECT * FROM users WHERE username=?', [key.toLowerCase()]);
  if (!user) user = queryOne('SELECT * FROM users WHERE display_name=?', [key]);
  if (!user) return res.status(401).json({ error: 'invalid_credentials' });
  if (!verifyPassword(pass, user.password)) return res.status(401).json({ error: 'invalid_credentials' });

  const token = genToken();
  run('INSERT INTO tokens (token, user_id, created_at) VALUES (?,?,?)', [token, user.id, Date.now()]);
  run('UPDATE users SET last_seen=? WHERE id=?', [Date.now(), user.id]);

  res.json({ token: token, user: publicUser(user) });
});

app.get('/api/me', auth, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

app.put('/api/me', auth, (req, res) => {
  const body = req.body || {};
  const fields = [];
  const values = [];

  if (body.display_name !== undefined) {
    const nm = String(body.display_name).trim().slice(0, 30);
    if (!nm) return res.status(400).json({ error: 'name_required' });
    const dup = queryOne('SELECT id FROM users WHERE display_name=? AND id!=?', [nm, req.user.id]);
    if (dup) return res.status(409).json({ error: 'name_taken' });
    fields.push('display_name=?'); values.push(nm);
  }
  if (body.bio !== undefined) { fields.push('bio=?'); values.push(String(body.bio).slice(0, 200)); }
  if (body.location !== undefined) { fields.push('location=?'); values.push(String(body.location).slice(0, 60)); }
  if (body.country !== undefined) { fields.push('country=?'); values.push(String(body.country).slice(0, 40)); }
  if (body.phone !== undefined) {
    const ph = String(body.phone).slice(0, 20);
    fields.push('phone=?'); values.push(ph);
    if (ph.replace(/\D/g, '').length >= 8) { fields.push('verified=?'); values.push(1); }
  }
  if (body.avatar !== undefined) { fields.push('avatar=?'); values.push(String(body.avatar).slice(0, 300)); }
  if (body.color !== undefined && /^#[0-9a-fA-F]{6}$/.test(body.color)) { fields.push('color=?'); values.push(body.color); }
  if (body.lang !== undefined && ['ar','en'].indexOf(body.lang) !== -1) { fields.push('lang=?'); values.push(body.lang); }
  if (body.theme !== undefined && ['dark','light'].indexOf(body.theme) !== -1) { fields.push('theme=?'); values.push(body.theme); }
  if (body.sound !== undefined) { fields.push('sound=?'); values.push(body.sound ? 1 : 0); }
  if (body.notifications !== undefined) { fields.push('notifications=?'); values.push(body.notifications ? 1 : 0); }

  if (fields.length) {
    values.push(req.user.id);
    run('UPDATE users SET ' + fields.join(', ') + ' WHERE id=?', values);
  }

  const user = queryOne('SELECT * FROM users WHERE id=?', [req.user.id]);
  res.json({ user: publicUser(user) });
});

app.get('/api/users/search', auth, (req, res) => {
  const q = String(req.query.q || '').trim().slice(0, 40);
  if (!q) return res.json({ users: [] });
  const like = '%' + q + '%';
  const rows = queryAll(
    'SELECT * FROM users WHERE (username LIKE ? OR display_name LIKE ?) AND id!=? LIMIT 30',
    [like, like, req.user.id]
  );
  res.json({ users: rows.map(publicUser) });
});

app.get('/api/users/:id', auth, (req, res) => {
  const u = queryOne('SELECT * FROM users WHERE id=?', [req.params.id]);
  if (!u) return res.status(404).json({ error: 'not_found' });
  const isFriend = queryOne(
    'SELECT 1 FROM friendships WHERE ((user1=? AND user2=?) OR (user1=? AND user2=?)) AND status=?',
    [req.user.id, u.id, u.id, req.user.id, 'accepted']
  );
  res.json({ user: publicUser(u), isFriend: !!isFriend });
});

function extractHashtags(text) {
  const tags = [];
  const re = /#([\u0600-\u06FF\w_]{1,40})/g;
  let m;
  while ((m = re.exec(text)) !== null) tags.push(m[1].toLowerCase());
  return Array.from(new Set(tags));
}

function formatPost(p, viewerId) {
  if (!p) return null;
  const u = queryOne('SELECT * FROM users WHERE id=?', [p.user_id]);
  const likesRow = queryOne('SELECT COUNT(*) as c FROM post_likes WHERE post_id=?', [p.id]);
  const commentsRow = queryOne('SELECT COUNT(*) as c FROM post_comments WHERE post_id=?', [p.id]);
  const likes = likesRow ? likesRow.c : 0;
  const comments = commentsRow ? commentsRow.c : 0;
  const liked = viewerId ? !!queryOne('SELECT 1 FROM post_likes WHERE post_id=? AND user_id=?', [p.id, viewerId]) : false;
  return {
    id: p.id, text: decryptText(p.text), image: p.image, time: p.time,
    user: publicUser(u), likes: likes, comments: comments, liked: liked
  };
}

app.post('/api/posts', auth, (req, res) => {
  const body = req.body || {};
  const t = String(body.text || '').trim().slice(0, 1000);
  const img = body.image ? String(body.image).slice(0, 300) : null;
  if (!t && !img) return res.status(400).json({ error: 'empty' });

  const time = Date.now();
  const info = run('INSERT INTO posts (user_id, text, image, time) VALUES (?,?,?,?)',
    [req.user.id, encryptText(t), img, time]);

  extractHashtags(t).forEach(function(tag) {
    run('INSERT INTO hashtags (tag, source_type, source_id, time) VALUES (?,?,?,?)',
      [tag, 'post', info.lastInsertRowid, time]);
  });

  const post = queryOne('SELECT * FROM posts WHERE id=?', [info.lastInsertRowid]);
  res.json({ post: formatPost(post, req.user.id) });
});

app.get('/api/posts', auth, (req, res) => {
  const username = req.query.username;
  const hashtag = req.query.hashtag;
  const lim = Math.min(parseInt(req.query.limit) || 30, 100);
  let rows;

  if (hashtag) {
    const tag = String(hashtag).replace(/^#/, '').toLowerCase();
    rows = queryAll(
      "SELECT p.* FROM posts p JOIN hashtags h ON h.source_id=p.id AND h.source_type='post' " +
      "WHERE h.tag=? AND p.deleted=0 ORDER BY p.id DESC LIMIT ?",
      [tag, lim]
    );
  } else if (username) {
    const u = queryOne('SELECT id FROM users WHERE username=?', [username]);
    if (!u) return res.json({ posts: [] });
    rows = queryAll('SELECT * FROM posts WHERE user_id=? AND deleted=0 ORDER BY id DESC LIMIT ?', [u.id, lim]);
  } else {
    rows = queryAll('SELECT * FROM posts WHERE deleted=0 ORDER BY id DESC LIMIT ?', [lim]);
  }
  res.json({ posts: rows.map(function(p) { return formatPost(p, req.user.id); }) });
});

app.post('/api/posts/:id/like', auth, (req, res) => {
  const id = parseInt(req.params.id);
  const exists = queryOne('SELECT 1 FROM post_likes WHERE post_id=? AND user_id=?', [id, req.user.id]);
  if (exists) run('DELETE FROM post_likes WHERE post_id=? AND user_id=?', [id, req.user.id]);
  else run('INSERT INTO post_likes (post_id, user_id) VALUES (?,?)', [id, req.user.id]);
  const likesRow = queryOne('SELECT COUNT(*) as c FROM post_likes WHERE post_id=?', [id]);
  res.json({ likes: likesRow ? likesRow.c : 0, liked: !exists });
});

app.get('/api/posts/:id/comments', auth, (req, res) => {
  const id = parseInt(req.params.id);
  const rows = queryAll(
    'SELECT c.*, u.username, u.display_name, u.color, u.verified FROM post_comments c ' +
    'JOIN users u ON u.id=c.user_id WHERE c.post_id=? ORDER BY c.id ASC LIMIT 100', [id]
  );
  res.json({
    comments: rows.map(function(c) {
      return {
        id: c.id, text: decryptText(c.text), time: c.time,
        user: { username: c.username, display_name: c.display_name, color: c.color, verified: !!c.verified }
      };
    })
  });
});

app.post('/api/posts/:id/comment', auth, (req, res) => {
  const id = parseInt(req.params.id);
  const body = req.body || {};
  const text = String(body.text || '').trim().slice(0, 500);
  if (!text) return res.status(400).json({ error: 'empty' });
  run('INSERT INTO post_comments (post_id, user_id, text, time) VALUES (?,?,?,?)',
    [id, req.user.id, encryptText(text), Date.now()]);
  const rows = queryAll(
    'SELECT c.*, u.username, u.display_name, u.color, u.verified FROM post_comments c ' +
    'JOIN users u ON u.id=c.user_id WHERE c.post_id=? ORDER BY c.id ASC LIMIT 100', [id]
  );
  res.json({
    comments: rows.map(function(c) {
      return {
        id: c.id, text: decryptText(c.text), time: c.time,
        user: { username: c.username, display_name: c.display_name, color: c.color, verified: !!c.verified }
      };
    })
  });
});

app.get('/api/trends', auth, (req, res) => {
  const since = Date.now() - 7 * 24 * 3600 * 1000;
  const rows = queryAll(
    'SELECT tag, COUNT(*) as c FROM hashtags WHERE time > ? GROUP BY tag ORDER BY c DESC LIMIT 20',
    [since]
  );
  res.json({ trends: rows });
});

app.get('/api/friends', auth, (req, res) => {
  const rows = queryAll(
    'SELECT u.* FROM users u JOIN friendships f ' +
    'ON ((f.user1=? AND f.user2=u.id) OR (f.user2=? AND f.user1=u.id)) ' +
    "WHERE f.status='accepted' LIMIT 200",
    [req.user.id, req.user.id]
  );
  res.json({ friends: rows.map(publicUser) });
});

app.get('/api/friends/requests', auth, (req, res) => {
  const rows = queryAll(
    'SELECT u.* FROM users u JOIN friendships f ON f.user1=u.id ' +
    "WHERE f.user2=? AND f.status='pending' LIMIT 100",
    [req.user.id]
  );
  res.json({ requests: rows.map(publicUser) });
});

app.post('/api/friends/request/:id', auth, (req, res) => {
  const target = parseInt(req.params.id);
  if (target === req.user.id) return res.status(400).json({ error: 'self' });
  const u = queryOne('SELECT id FROM users WHERE id=?', [target]);
  if (!u) return res.status(404).json({ error: 'not_found' });
  const exists = queryOne(
    'SELECT * FROM friendships WHERE (user1=? AND user2=?) OR (user1=? AND user2=?)',
    [req.user.id, target, target, req.user.id]
  );
  if (exists) return res.status(409).json({ error: 'exists', status: exists.status });
  run('INSERT INTO friendships (user1, user2, status) VALUES (?,?,?)', [req.user.id, target, 'pending']);
  run('INSERT INTO notifications (user_id, type, from_id, text, time) VALUES (?,?,?,?,?)',
    [target, 'friend_request', req.user.id, 'طلب صداقة جديد', Date.now()]);

  onlineSockets.forEach(function(uid, sid) {
    if (uid === target) {
      io.to(sid).emit('notification', {
        type: 'friend_request', from: publicUser(req.user), text: 'طلب صداقة جديد'
      });
    }
  });
  res.json({ ok: true });
});

app.post('/api/friends/accept/:id', auth, (req, res) => {
  const fromId = parseInt(req.params.id);
  const f = queryOne('SELECT * FROM friendships WHERE user1=? AND user2=? AND status=?',
    [fromId, req.user.id, 'pending']);
  if (!f) return res.status(404).json({ error: 'not_found' });
  run('UPDATE friendships SET status=? WHERE user1=? AND user2=?', ['accepted', fromId, req.user.id]);
  res.json({ ok: true });
});

app.post('/api/friends/reject/:id', auth, (req, res) => {
  const fromId = parseInt(req.params.id);
  run('DELETE FROM friendships WHERE user1=? AND user2=? AND status=?', [fromId, req.user.id, 'pending']);
  res.json({ ok: true });
});

app.get('/api/dms/:userId', auth, (req, res) => {
  const other = parseInt(req.params.userId);
  const rows = queryAll(
    'SELECT * FROM dms WHERE (from_id=? AND to_id=?) OR (from_id=? AND to_id=?) ' +
    'ORDER BY id DESC LIMIT 100',
    [req.user.id, other, other, req.user.id]
  ).reverse();
  run('UPDATE dms SET read=1 WHERE to_id=? AND from_id=?', [req.user.id, other]);
  res.json({
    messages: rows.map(function(m) {
      return {
        id: m.id, from_id: m.from_id, to_id: m.to_id,
        text: decryptText(m.text), image: m.image, time: m.time, read: !!m.read
      };
    })
  });
});

app.get('/api/dm-conversations', auth, (req, res) => {
  const rows = queryAll(
    'SELECT CASE WHEN from_id=? THEN to_id ELSE from_id END as other_id, MAX(id) as last_id ' +
    'FROM dms WHERE from_id=? OR to_id=? GROUP BY other_id ORDER BY last_id DESC LIMIT 50',
    [req.user.id, req.user.id, req.user.id]
  );
  const conversations = [];
  rows.forEach(function(r) {
    const other = queryOne('SELECT * FROM users WHERE id=?', [r.other_id]);
    if (!other) return;
    const last = queryOne('SELECT * FROM dms WHERE id=?', [r.last_id]);
    const unreadRow = queryOne('SELECT COUNT(*) as c FROM dms WHERE from_id=? AND to_id=? AND read=0',
      [r.other_id, req.user.id]);
    conversations.push({
      user: publicUser(other),
      last: last ? { text: decryptText(last.text), image: last.image, time: last.time, from_id: last.from_id } : null,
      unread: unreadRow ? unreadRow.c : 0
    });
  });
  res.json({ conversations: conversations });
});

const users = new Map();
const onlineSockets = new Map();

function getUser(id) { return queryOne('SELECT * FROM users WHERE id=?', [id]); }

function broadcastUsers(room) {
  const list = [];
  const seen = new Set();
  users.forEach(function(u, sid) {
    if (u.room === room && !seen.has(u.userId)) {
      seen.add(u.userId);
      const user = getUser(u.userId);
      if (user) list.push(publicUser(user));
    }
  });
  io.to(room).emit('users', list);
}

function getReactions(msgId) {
  const rows = queryAll('SELECT emoji, COUNT(*) as c FROM reactions WHERE msgId=? GROUP BY emoji', [msgId]);
  const out = {};
  rows.forEach(function(r) { out[r.emoji] = r.c; });
  return out;
}

io.on('connection', function(socket) {
  socket.emit('rooms', ROOMS);
  socket.emit('countries', COUNTRIES);

  socket.on('auth', function(data) {
    const token = data && data.token;
    const row = queryOne('SELECT user_id FROM tokens WHERE token=?', [token]);
    if (!row) return socket.emit('auth-error', { error: 'invalid_token' });
    const user = getUser(row.user_id);
    if (!user) return socket.emit('auth-error', { error: 'user_not_found' });
    onlineSockets.set(socket.id, user.id);
    socket.emit('auth-ok', { user: publicUser(user) });
  });

  socket.on('join', function(data) {
    const userId = onlineSockets.get(socket.id);
    if (!userId) return socket.emit('join-error', { message: 'unauthorized' });
    let room = data && data.room;
    if (ROOMS.indexOf(room) === -1) room = ROOMS[0];
    const user = getUser(userId);

    const prev = users.get(socket.id);
    if (prev) {
      socket.leave(prev.room);
      socket.to(prev.room).emit('message', {
        system: true, text: user.display_name + ' غادر الدردشة', time: Date.now()
      });
      broadcastUsers(prev.room);
    }

    users.set(socket.id, { userId: userId, room: room });
    socket.join(room);
    socket.emit('joined', { room: room, user: publicUser(user) });

    const rows = queryAll(
      'SELECT m.*, u.username, u.display_name, u.color, u.verified ' +
      'FROM messages m JOIN users u ON u.id=m.user_id ' +
      'WHERE m.room=? ORDER BY m.id DESC LIMIT ?',
      [room, MAX_HISTORY]
    ).reverse();

    socket.emit('history', rows.map(function(r) {
      return {
        id: r.id,
        user: { id: r.user_id, username: r.username, display_name: r.display_name, color: r.color, verified: !!r.verified },
        text: r.deleted ? '' : decryptText(r.text),
        image: r.deleted ? null : r.image,
        time: r.time, deleted: !!r.deleted,
        reactions: getReactions(r.id), sid: null
      };
    }));

    const pin = queryOne('SELECT * FROM pins WHERE room=?', [room]);
    if (pin) {
      const pu = getUser(pin.user_id);
      socket.emit('pin', {
        room: pin.room, msgId: pin.msgId,
        name: pu ? pu.display_name : '',
        text: decryptText(pin.text), time: pin.time
      });
    } else socket.emit('pin', null);

    socket.to(room).emit('message', {
      system: true, text: user.display_name + ' انضم إلى الدردشة', time: Date.now()
    });
    broadcastUsers(room);
  });

  socket.on('message', function(payload) {
    const u = users.get(socket.id);
    if (!u) return;
    const user = getUser(u.userId);
    const text = String((payload && payload.text) || '').trim().slice(0, 1000);
    const image = (payload && payload.image) ? String(payload.image).slice(0, 300) : null;
    if (!text && !image) return;

    const time = Date.now();
    const info = run('INSERT INTO messages (room, user_id, text, image, time) VALUES (?,?,?,?,?)',
      [u.room, u.userId, encryptText(text), image, time]);

    extractHashtags(text).forEach(function(tag) {
      run('INSERT INTO hashtags (tag, source_type, source_id, time) VALUES (?,?,?,?)',
        [tag, 'message', info.lastInsertRowid, time]);
    });

    io.to(u.room).emit('message', {
      id: info.lastInsertRowid, sid: socket.id,
      user: publicUser(user),
      text: text, image: image, time: time, reactions: {}
    });
  });

  socket.on('delete', function(msgId) {
    const u = users.get(socket.id);
    if (!u) return;
    const row = queryOne('SELECT * FROM messages WHERE id=?', [msgId]);
    if (!row || row.user_id !== u.userId || row.room !== u.room) return;
    run('UPDATE messages SET deleted=1, text="", image=NULL WHERE id=?', [msgId]);
    io.to(u.room).emit('deleted', { id: msgId });
  });

  socket.on('react', function(data) {
    const u = users.get(socket.id);
    if (!u) return;
    const emoji = data && data.emoji;
    const msgId = data && data.msgId;
    const allowed = ['❤️','😂','👍','😮','😢','🔥'];
    if (allowed.indexOf(emoji) === -1) return;
    const exists = queryOne('SELECT 1 FROM reactions WHERE msgId=? AND user_id=? AND emoji=?',
      [msgId, u.userId, emoji]);
    if (exists) run('DELETE FROM reactions WHERE msgId=? AND user_id=? AND emoji=?', [msgId, u.userId, emoji]);
    else run('INSERT INTO reactions (msgId, user_id, emoji) VALUES (?,?,?)', [msgId, u.userId, emoji]);
    io.to(u.room).emit('reaction', { msgId: msgId, reactions: getReactions(msgId) });
  });

  socket.on('pin', function(msgId) {
    const u = users.get(socket.id);
    if (!u) return;
    const row = queryOne('SELECT * FROM messages WHERE id=? AND room=?', [msgId, u.room]);
    if (!row) return;
    const user = getUser(u.userId);
    run('INSERT OR REPLACE INTO pins (room, msgId, text, user_id, time) VALUES (?,?,?,?,?)',
      [u.room, msgId, row.text || '📷 صورة', u.userId, Date.now()]);
    io.to(u.room).emit('pin', {
      msgId: msgId, text: decryptText(row.text) || '📷 صورة',
      name: user ? user.display_name : '', time: Date.now()
    });
  });

  socket.on('unpin', function() {
    const u = users.get(socket.id);
    if (!u) return;
    run('DELETE FROM pins WHERE room=?', [u.room]);
    io.to(u.room).emit('pin', null);
  });

  socket.on('typing', function(isTyping) {
    const u = users.get(socket.id);
    if (!u) return;
    const user = getUser(u.userId);
    socket.to(u.room).emit('typing', { name: user ? user.display_name : '', isTyping: !!isTyping });
  });

  socket.on('dm-send', function(data) {
    const u = onlineSockets.get(socket.id);
    if (!u) return;
    const toId = data && data.toId;
    const t = String((data && data.text) || '').trim().slice(0, 1000);
    const img = (data && data.image) ? String(data.image).slice(0, 300) : null;
    if (!t && !img) return;
    const time = Date.now();
    const info = run('INSERT INTO dms (from_id, to_id, text, image, time) VALUES (?,?,?,?,?)',
      [u, toId, encryptText(t), img, time]);
    const msg = { id: info.lastInsertRowid, from_id: u, to_id: toId, text: t, image: img, time: time, read: false };
    socket.emit('dm-message', msg);
    onlineSockets.forEach(function(uid, sid) {
      if (uid === toId) {
        io.to(sid).emit('dm-message', msg);
        io.to(sid).emit('notification', {
          type: 'dm', from: publicUser(getUser(u)), text: t || '📷 صورة'
        });
      }
    });
  });

  socket.on('dm-typing', function(data) {
    const u = onlineSockets.get(socket.id);
    if (!u) return;
    const toId = data && data.toId;
    onlineSockets.forEach(function(uid, sid) {
      if (uid === toId) io.to(sid).emit('dm-typing', { fromId: u, isTyping: !!(data && data.isTyping) });
    });
  });

  socket.on('call-start', function(data) {
    const u = onlineSockets.get(socket.id);
    if (!u) return;
    const targetId = data && data.targetId;
    const user = getUser(u);
    onlineSockets.forEach(function(uid, sid) {
      if (uid === targetId) {
        io.to(sid).emit('incoming-call', {
          fromId: socket.id, fromUserId: u, fromName: user.display_name, fromColor: user.color
        });
      }
    });
  });

  socket.on('call-accept', function(data) {
    const u = onlineSockets.get(socket.id);
    if (!u) return;
    const user = getUser(u);
    io.to(data.toId).emit('call-accepted', { fromId: socket.id, fromUserId: u, fromName: user.display_name });
  });

  socket.on('call-reject', function(data) { io.to(data.toId).emit('call-rejected', { fromId: socket.id }); });
  socket.on('call-end', function(data) { io.to(data.toId).emit('call-ended', { fromId: socket.id }); });
  socket.on('webrtc-offer', function(data) { io.to(data.toId).emit('webrtc-offer', { fromId: socket.id, offer: data.offer }); });
  socket.on('webrtc-answer', function(data) { io.to(data.toId).emit('webrtc-answer', { fromId: socket.id, answer: data.answer }); });
  socket.on('webrtc-ice', function(data) { io.to(data.toId).emit('webrtc-ice', { fromId: socket.id, candidate: data.candidate }); });

  socket.on('group-call-invite', function() {
    const u = users.get(socket.id);
    if (!u) return;
    const user = getUser(u.userId);
    socket.to(u.room).emit('group-call-invite', {
      fromId: socket.id, fromUserId: u.userId,
      fromName: user.display_name, fromColor: user.color
    });
  });

  socket.on('disconnect', function() {
    const u = users.get(socket.id);
    if (u) {
      const user = getUser(u.userId);
      socket.to(u.room).emit('message', {
        system: true, text: (user ? user.display_name : '') + ' غادر الدردشة', time: Date.now()
      });
      socket.to(u.room).emit('call-peer-left', { id: socket.id });
      broadcastUsers(u.room);
    }
    users.delete(socket.id);
    onlineSockets.delete(socket.id);
  });
});

initDb().then(function() {
  server.listen(PORT, '0.0.0.0', function() {
    console.log('✅ السيرفر يعمل على المنفذ ' + PORT);
    console.log('📁 ' + ROOMS.length + ' غرفة محافظة جاهزة');
  });
}).catch(function(err) {
  console.error('❌ خطأ:', err);
  process.exit(1);
});
