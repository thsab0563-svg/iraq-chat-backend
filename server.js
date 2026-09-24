const path = require('path');
const fs = require('fs');
const http = require('http');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const { Server } = require('socket.io');

const PORT = process.env.PORT || 3000;
const ROOMS = ['بغداد','البصرة','نينوى','أربيل','النجف','كربلاء','ذي قار','الأنبار','بابل','ديالى','واسط','ميسان','المثنى','القادسية','صلاح الدين','كركوك','دهوك','السليمانية','حلبجة'];
const COUNTRIES = ['العراق','مصر','السعودية','الإمارات','الأردن','الكويت','قطر','البحرين','عمان','لبنان','سوريا','فلسطين','اليمن','المغرب','تونس','الجزائر','ليبيا','السودان','تركيا','إيران'];
const COLORS = ['#f87171','#fb923c','#facc15','#4ade80','#22d3ee','#818cf8','#c084fc','#f472b6','#e11d48','#0ea5e9'];
const MAX_HISTORY = 200;
const USERNAME_CHANGE_DAYS = 7;

// GitHub Storage
const GH_TOKEN = process.env.GH_TOKEN || '';
const GH_OWNER = process.env.GH_OWNER || '';
const GH_REPO = process.env.GH_REPO || '';
const GH_API = 'https://api.github.com';
const GH_FILE = 'data.json';

const users = new Map();
const onlineSockets = new Map();

const DATA_DIR = fs.existsSync('/data') ? '/data' : __dirname;
if (!fs.existsSync(DATA_DIR)) { try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch(_){} }
const DB_FILE = path.join(DATA_DIR, 'data.json');
const SECRET_FILE = path.join(DATA_DIR, '.secret');
const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) { try { fs.mkdirSync(UPLOADS_DIR, { recursive: true }); } catch(_){} }

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET','POST'] },
  maxHttpBufferSize: 5 * 1024 * 1024
});

app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(UPLOADS_DIR));

app.get('/health', function(req, res) {
  res.json({ ok: true, time: Date.now(), users: DB.users.length, gh: GH_TOKEN ? 'on' : 'off' });
});

let SECRET_KEY;
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
    const iv = data.slice(0, 12);
    const tag = data.slice(12, 28);
    const enc = data.slice(28);
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

const DB = {
  users: [], tokens: [], messages: [], reactions: [], pins: [],
  posts: [], post_likes: [], post_comments: [], hashtags: [],
  friendships: [], dms: [], blocks: [], profile_views: [],
  nextId: { users: 1, messages: 1, posts: 1, post_comments: 1, dms: 1, hashtags: 1, views: 1 }
};

// ============ GitHub Storage ============
let ghSha = null;
let ghReady = false;

async function githubFetch(url, options) {
  options = options || {};
  options.headers = Object.assign({
    'Authorization': 'token ' + GH_TOKEN,
    'Accept': 'application/vnd.github.v3+json',
    'User-Agent': 'iraq-chat'
  }, options.headers || {});
  const res = await fetch(url, options);
  if (!res.ok) {
    const txt = await res.text();
    throw new Error('GitHub API ' + res.status + ': ' + txt.slice(0, 200));
  }
  return await res.json();
}

async function githubLoad() {
  if (!GH_TOKEN || !GH_OWNER || !GH_REPO) {
    console.log('⚠️ GitHub غير مضبوط — سيُستخدم التخزين المحلي فقط');
    ghReady = false;
    return;
  }
  try {
    const url = GH_API + '/repos/' + GH_OWNER + '/' + GH_REPO + '/contents/' + GH_FILE;
    const data = await githubFetch(url);
    ghSha = data.sha;
    const content = Buffer.from(data.content, 'base64').toString('utf8');
    const parsed = JSON.parse(content);
    Object.assign(DB, parsed);
    console.log('✅ تم تحميل البيانات من GitHub: ' + DB.users.length + ' مستخدم');
    ghReady = true;
  } catch (e) {
    if (e.message.indexOf('404') !== -1) {
      console.log('📝 GitHub: لا يوجد ملف data.json بعد — سيُنشأ عند أول حفظ');
      ghReady = true;
    } else {
      console.error('❌ فشل تحميل من GitHub:', e.message);
      ghReady = false;
    }
  }
}

let ghSaveTimer = null;
let ghSaving = false;

function saveDb() {
  // حفظ محلي فوري
  try { fs.writeFileSync(DB_FILE, JSON.stringify(DB)); } catch (_) {}
  // رفع لـ GitHub مؤجل
  if (!ghReady) return;
  if (ghSaveTimer) return;
  ghSaveTimer = setTimeout(function() {
    ghSaveTimer = null;
    githubSave();
  }, 3000);
}

async function githubSave() {
  if (ghSaving) return;
  ghSaving = true;
  try {
    const content = Buffer.from(JSON.stringify(DB)).toString('base64');
    const url = GH_API + '/repos/' + GH_OWNER + '/' + GH_REPO + '/contents/' + GH_FILE;
    const body = {
      message: 'Update data.json - ' + new Date().toISOString(),
      content: content
    };
    if (ghSha) body.sha = ghSha;
    const data = await githubFetch(url, {
      method: 'PUT',
      body: JSON.stringify(body)
    });
    ghSha = data.content.sha;
    console.log('✅ تم الحفظ في GitHub - مستخدمون: ' + DB.users.length);
  } catch (e) {
    console.error('❌ فشل الحفظ في GitHub:', e.message);
  }
  ghSaving = false;
}

// ============ تحميل محلي مبدئي ============
if (fs.existsSync(DB_FILE)) {
  try {
    const loaded = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    Object.assign(DB, loaded);
    console.log('✅ تم تحميل البيانات المحلية: ' + DB.users.length + ' مستخدم');
  } catch (e) { console.error('DB load error:', e.message); }
}

// ============ رفع الصور ============
const storage = multer.diskStorage({
  destination: UPLOADS_DIR,
  filename: function(req, file, cb) {
    const ext = (path.extname(file.originalname) || '.jpg').toLowerCase();
    cb(null, Date.now() + '_' + Math.random().toString(36).slice(2, 8) + ext);
  }
});
const upload = multer({
  storage: storage,
  limits: { fileSize: 4 * 1024 * 1024 },
  fileFilter: function(req, file, cb) { cb(null, /^image\//.test(file.mimetype)); }
});
app.post('/upload', upload.single('image'), function(req, res) {
  if (!req.file) return res.status(400).json({ error: 'invalid' });
  res.json({ url: '/uploads/' + req.file.filename });
});

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.replace('Bearer ', '') || req.query.token;
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  const t = DB.tokens.find(function(x) { return x.token === token; });
  if (!t) return res.status(401).json({ error: 'invalid_token' });
  const user = DB.users.find(function(x) { return x.id === t.user_id; });
  if (!user) return res.status(401).json({ error: 'user_not_found' });
  req.user = user;
  next();
}

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

function genUsername(name) {
  let base = String(name || 'user').toLowerCase().replace(/[^a-z0-9]/gi, '').slice(0, 10) || 'user';
  let candidate = base; let i = 1;
  while (DB.users.find(function(u) { return u.username === candidate; })) {
    candidate = base + i; i++;
    if (i > 9999) { candidate = 'user' + crypto.randomBytes(3).toString('hex'); break; }
  }
  return candidate;
}

function getUser(id) { return DB.users.find(function(u) { return u.id === id; }); }

function isBlocked(a, b) {
  return DB.blocks.some(function(x) {
    return (x.user1 === a && x.user2 === b) || (x.user1 === b && x.user2 === a);
  });
}

// ============ API ============
app.post('/api/register', function(req, res) {
  const body = req.body || {};
  const name = String(body.display_name || '').trim().slice(0, 30);
  const pass = String(body.password || '');
  if (!name) return res.status(400).json({ error: 'name_required' });
  if (pass.length < 4) return res.status(400).json({ error: 'password_too_short' });
  if (DB.users.find(function(u) { return u.display_name === name; })) return res.status(409).json({ error: 'name_taken' });

  const username = genUsername(name);
  const user = {
    id: DB.nextId.users++, username: username, display_name: name,
    password: hashPassword(pass),
    color: /^#[0-9a-fA-F]{6}$/.test(body.color || '') ? body.color : COLORS[Math.floor(Math.random() * COLORS.length)],
    bio: String(body.bio || '').slice(0, 200),
    location: String(body.location || '').slice(0, 60),
    country: String(body.country || '').slice(0, 40),
    phone: String(body.phone || '').slice(0, 20),
    verified: 0, avatar: '', cover: '',
    created_at: Date.now(), last_seen: Date.now(),
    username_changed_at: Date.now(),
    lang: 'ar', theme: 'dark', sound: 1, notifications: 1
  };
  DB.users.push(user);
  const token = genToken();
  DB.tokens.push({ token: token, user_id: user.id, created_at: Date.now() });
  saveDb();
  res.json({ token: token, user: publicUser(user) });
});

app.post('/api/login', function(req, res) {
  const body = req.body || {};
  const key = String(body.username || '').trim();
  const pass = String(body.password || '');
  let user = DB.users.find(function(u) { return u.username === key.toLowerCase(); });
  if (!user) user = DB.users.find(function(u) { return u.display_name === key; });
  if (!user) return res.status(401).json({ error: 'invalid_credentials' });
  if (!verifyPassword(pass, user.password)) return res.status(401).json({ error: 'invalid_credentials' });
  const token = genToken();
  DB.tokens.push({ token: token, user_id: user.id, created_at: Date.now() });
  user.last_seen = Date.now();
  saveDb();
  res.json({ token: token, user: publicUser(user) });
});

app.get('/api/me', auth, function(req, res) { res.json({ user: publicUser(req.user) }); });

app.put('/api/me', auth, function(req, res) {
  const body = req.body || {};
  const u = req.user;
  if (body.display_name !== undefined) {
    const nm = String(body.display_name).trim().slice(0, 30);
    if (!nm) return res.status(400).json({ error: 'name_required' });
    const dup = DB.users.find(function(x) { return x.display_name === nm && x.id !== u.id; });
    if (dup) return res.status(409).json({ error: 'name_taken' });
    u.display_name = nm;
  }
  if (body.username !== undefined) {
    const un = String(body.username).trim().toLowerCase().slice(0, 20).replace(/[^a-z0-9_]/g, '');
    if (un.length < 3) return res.status(400).json({ error: 'username_too_short' });
    if (un !== u.username) {
      const last = u.username_changed_at || 0;
      const daysSince = (Date.now() - last) / (1000 * 60 * 60 * 24);
      if (daysSince < USERNAME_CHANGE_DAYS) {
        const daysLeft = Math.ceil(USERNAME_CHANGE_DAYS - daysSince);
        return res.status(429).json({ error: 'username_cooldown', days_left: daysLeft });
      }
      const dup = DB.users.find(function(x) { return x.username === un && x.id !== u.id; });
      if (dup) return res.status(409).json({ error: 'username_taken' });
      u.username = un;
      u.username_changed_at = Date.now();
    }
  }
  if (body.bio !== undefined) u.bio = String(body.bio).slice(0, 200);
  if (body.location !== undefined) u.location = String(body.location).slice(0, 60);
  if (body.country !== undefined) u.country = String(body.country).slice(0, 40);
  if (body.phone !== undefined) {
    u.phone = String(body.phone).slice(0, 20);
    if (u.phone.replace(/\D/g, '').length >= 8) u.verified = 1;
  }
  if (body.avatar !== undefined) u.avatar = String(body.avatar).slice(0, 300);
  if (body.cover !== undefined) u.cover = String(body.cover).slice(0, 300);
  if (body.color !== undefined && /^#[0-9a-fA-F]{6}$/.test(body.color)) u.color = body.color;
  if (body.lang !== undefined && ['ar','en'].indexOf(body.lang) !== -1) u.lang = body.lang;
  if (body.theme !== undefined && ['dark','light'].indexOf(body.theme) !== -1) u.theme = body.theme;
  if (body.sound !== undefined) u.sound = body.sound ? 1 : 0;
  if (body.notifications !== undefined) u.notifications = body.notifications ? 1 : 0;
  saveDb();
  res.json({ user: publicUser(u) });
});

app.post('/api/change-password', auth, function(req, res) {
  const body = req.body || {};
  const oldPass = String(body.old_password || '');
  const newPass = String(body.new_password || '');
  if (!oldPass) return res.status(400).json({ error: 'old_required' });
  if (newPass.length < 4) return res.status(400).json({ error: 'password_too_short' });
  if (!verifyPassword(oldPass, req.user.password)) return res.status(401).json({ error: 'wrong_old_password' });
  req.user.password = hashPassword(newPass);
  saveDb();
  res.json({ ok: true });
});

app.delete('/api/me', auth, function(req, res) {
  const uid = req.user.id;
  DB.tokens = DB.tokens.filter(function(t) { return t.user_id !== uid; });
  DB.users = DB.users.filter(function(u) { return u.id !== uid; });
  DB.messages = DB.messages.filter(function(m) { return m.user_id !== uid; });
  DB.posts = DB.posts.filter(function(p) { return p.user_id !== uid; });
  DB.dms = DB.dms.filter(function(d) { return d.from_id !== uid && d.to_id !== uid; });
  DB.friendships = DB.friendships.filter(function(f) { return f.user1 !== uid && f.user2 !== uid; });
  saveDb();
  res.json({ ok: true });
});

app.post('/api/block/:id', auth, function(req, res) {
  const target = parseInt(req.params.id);
  if (target === req.user.id) return res.status(400).json({ error: 'self' });
  const u = DB.users.find(function(x) { return x.id === target; });
  if (!u) return res.status(404).json({ error: 'not_found' });
  if (isBlocked(req.user.id, target)) return res.json({ ok: true });
  DB.blocks.push({ user1: req.user.id, user2: target, time: Date.now() });
  saveDb();
  res.json({ ok: true });
});
app.post('/api/unblock/:id', auth, function(req, res) {
  const target = parseInt(req.params.id);
  DB.blocks = DB.blocks.filter(function(b) {
    return !((b.user1 === req.user.id && b.user2 === target) || (b.user2 === req.user.id && b.user1 === target));
  });
  saveDb();
  res.json({ ok: true });
});
app.get('/api/blocks', auth, function(req, res) {
  const list = DB.blocks.filter(function(b) { return b.user1 === req.user.id; })
    .map(function(b) { return DB.users.find(function(u) { return u.id === b.user2; }); })
    .filter(Boolean);
  res.json({ blocks: list.map(publicUser) });
});

app.get('/api/users/search', auth, function(req, res) {
  const q = String(req.query.q || '').trim().slice(0, 40);
  if (!q) return res.json({ users: [] });
  const lq = q.toLowerCase();
  const list = DB.users.filter(function(u) {
    return u.id !== req.user.id && !isBlocked(req.user.id, u.id) &&
      (u.username.toLowerCase().indexOf(lq) !== -1 || u.display_name.toLowerCase().indexOf(lq) !== -1);
  }).slice(0, 30);
  res.json({ users: list.map(publicUser) });
});

app.get('/api/users/:id', auth, function(req, res) {
  const u = DB.users.find(function(x) { return x.id === parseInt(req.params.id); });
  if (!u) return res.status(404).json({ error: 'not_found' });
  const isFriend = DB.friendships.some(function(f) {
    return ((f.user1 === req.user.id && f.user2 === u.id) || (f.user2 === req.user.id && f.user1 === u.id)) && f.status === 'accepted';
  });
  const blocked = isBlocked(req.user.id, u.id);
  if (u.id !== req.user.id) {
    DB.profile_views.push({ viewer_id: req.user.id, viewed_id: u.id, time: Date.now() });
    if (DB.profile_views.length > 5000) DB.profile_views.shift();
    saveDb();
  }
  const friendsCount = DB.friendships.filter(function(f) {
    return f.status === 'accepted' && (f.user1 === u.id || f.user2 === u.id);
  }).length;
  const postsCount = DB.posts.filter(function(p) { return p.user_id === u.id && p.deleted === 0; }).length;
  const profileViewsCount = DB.profile_views.filter(function(v) { return v.viewed_id === u.id; }).length;
  res.json({
    user: publicUser(u), isFriend: isFriend, blocked: blocked,
    stats: { friends: friendsCount, posts: postsCount, views: profileViewsCount }
  });
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
  const u = DB.users.find(function(x) { return x.id === p.user_id; });
  const likes = DB.post_likes.filter(function(x) { return x.post_id === p.id; }).length;
  const comments = DB.post_comments.filter(function(x) { return x.post_id === p.id; }).length;
  const liked = viewerId ? DB.post_likes.some(function(x) { return x.post_id === p.id && x.user_id === viewerId; }) : false;
  return { id: p.id, text: decryptText(p.text), image: p.image, time: p.time, user: publicUser(u), likes: likes, comments: comments, liked: liked };
}

app.post('/api/posts', auth, function(req, res) {
  const body = req.body || {};
  const t = String(body.text || '').trim().slice(0, 1000);
  const img = body.image ? String(body.image).slice(0, 300) : null;
  if (!t && !img) return res.status(400).json({ error: 'empty' });
  const time = Date.now();
  const post = { id: DB.nextId.posts++, user_id: req.user.id, text: encryptText(t), image: img, time: time, deleted: 0 };
  DB.posts.push(post);
  extractHashtags(t).forEach(function(tag) {
    DB.hashtags.push({ id: DB.nextId.hashtags++, tag: tag, source_type: 'post', source_id: post.id, time: time });
  });
  saveDb();
  res.json({ post: formatPost(post, req.user.id) });
});

app.get('/api/posts', auth, function(req, res) {
  const username = req.query.username;
  const userId = req.query.user_id;
  const hashtag = req.query.hashtag;
  const lim = Math.min(parseInt(req.query.limit) || 30, 100);
  let posts;
  if (hashtag) {
    const tag = String(hashtag).replace(/^#/, '').toLowerCase();
    const ids = DB.hashtags.filter(function(h) { return h.tag === tag && h.source_type === 'post'; }).map(function(h) { return h.source_id; });
    posts = DB.posts.filter(function(p) { return p.deleted === 0 && ids.indexOf(p.id) !== -1; }).slice(-lim).reverse();
  } else if (userId) {
    const uid = parseInt(userId);
    posts = DB.posts.filter(function(p) { return p.deleted === 0 && p.user_id === uid; }).slice(-lim).reverse();
  } else if (username) {
    const u = DB.users.find(function(x) { return x.username === username; });
    if (!u) return res.json({ posts: [] });
    posts = DB.posts.filter(function(p) { return p.deleted === 0 && p.user_id === u.id; }).slice(-lim).reverse();
  } else {
    const myFriends = DB.friendships.filter(function(f) {
      return f.status === 'accepted' && (f.user1 === req.user.id || f.user2 === req.user.id);
    }).map(function(f) { return f.user1 === req.user.id ? f.user2 : f.user1; });
    posts = DB.posts.filter(function(p) {
      return p.deleted === 0 && (p.user_id === req.user.id || myFriends.indexOf(p.user_id) !== -1);
    }).slice(-lim).reverse();
  }
  res.json({ posts: posts.map(function(p) { return formatPost(p, req.user.id); }) });
});

app.post('/api/posts/:id/like', auth, function(req, res) {
  const id = parseInt(req.params.id);
  const idx = DB.post_likes.findIndex(function(x) { return x.post_id === id && x.user_id === req.user.id; });
  if (idx !== -1) DB.post_likes.splice(idx, 1);
  else DB.post_likes.push({ post_id: id, user_id: req.user.id });
  saveDb();
  const likes = DB.post_likes.filter(function(x) { return x.post_id === id; }).length;
  res.json({ likes: likes, liked: idx === -1 });
});

function mapComments(id) {
  return DB.post_comments.filter(function(c) { return c.post_id === id; }).map(function(c) {
    const u = DB.users.find(function(x) { return x.id === c.user_id; });
    return { id: c.id, text: decryptText(c.text), time: c.time,
      user: { username: u.username, display_name: u.display_name, color: u.color, verified: !!u.verified, avatar: u.avatar } };
  });
}
app.get('/api/posts/:id/comments', auth, function(req, res) { res.json({ comments: mapComments(parseInt(req.params.id)) }); });
app.post('/api/posts/:id/comment', auth, function(req, res) {
  const id = parseInt(req.params.id);
  const body = req.body || {};
  const text = String(body.text || '').trim().slice(0, 500);
  if (!text) return res.status(400).json({ error: 'empty' });
  DB.post_comments.push({ id: DB.nextId.post_comments++, post_id: id, user_id: req.user.id, text: encryptText(text), time: Date.now() });
  saveDb();
  res.json({ comments: mapComments(id) });
});
app.delete('/api/posts/:id', auth, function(req, res) {
  const p = DB.posts.find(function(x) { return x.id === parseInt(req.params.id); });
  if (!p || p.user_id !== req.user.id) return res.status(403).json({ error: 'forbidden' });
  p.deleted = 1; p.text = ''; p.image = null;
  saveDb();
  res.json({ ok: true });
});

app.get('/api/trends', auth, function(req, res) {
  const since = Date.now() - 7 * 24 * 3600 * 1000;
  const map = {};
  DB.hashtags.filter(function(h) { return h.time > since; }).forEach(function(h) { map[h.tag] = (map[h.tag] || 0) + 1; });
  const trends = Object.keys(map).map(function(tag) { return { tag: tag, c: map[tag] }; }).sort(function(a, b) { return b.c - a.c; }).slice(0, 20);
  res.json({ trends: trends });
});

app.get('/api/suggestions', auth, function(req, res) {
  const myFriends = DB.friendships.filter(function(f) {
    return f.status === 'accepted' && (f.user1 === req.user.id || f.user2 === req.user.id);
  }).map(function(f) { return f.user1 === req.user.id ? f.user2 : f.user1; });
  const pending = DB.friendships.filter(function(f) {
    return f.status === 'pending' && (f.user1 === req.user.id || f.user2 === req.user.id);
  }).map(function(f) { return f.user1 === req.user.id ? f.user2 : f.user1; });
  const list = DB.users.filter(function(u) {
    return u.id !== req.user.id && myFriends.indexOf(u.id) === -1 && pending.indexOf(u.id) === -1 && !isBlocked(req.user.id, u.id);
  }).slice(0, 10);
  res.json({ users: list.map(publicUser) });
});

app.get('/api/friends', auth, function(req, res) {
  const friends = DB.friendships
    .filter(function(f) { return f.status === 'accepted' && (f.user1 === req.user.id || f.user2 === req.user.id); })
    .map(function(f) { return DB.users.find(function(u) { return u.id === (f.user1 === req.user.id ? f.user2 : f.user1); }); })
    .filter(Boolean);
  res.json({ friends: friends.map(publicUser) });
});
app.get('/api/friends/requests', auth, function(req, res) {
  const requests = DB.friendships
    .filter(function(f) { return f.status === 'pending' && f.user2 === req.user.id; })
    .map(function(f) { return DB.users.find(function(u) { return u.id === f.user1; }); })
    .filter(Boolean);
  res.json({ requests: requests.map(publicUser) });
});
app.post('/api/friends/request/:id', auth, function(req, res) {
  const target = parseInt(req.params.id);
  if (target === req.user.id) return res.status(400).json({ error: 'self' });
  if (isBlocked(req.user.id, target)) return res.status(403).json({ error: 'blocked' });
  const u = DB.users.find(function(x) { return x.id === target; });
  if (!u) return res.status(404).json({ error: 'not_found' });
  const exists = DB.friendships.find(function(f) {
    return (f.user1 === req.user.id && f.user2 === target) || (f.user2 === req.user.id && f.user1 === target);
  });
  if (exists) return res.status(409).json({ error: 'exists', status: exists.status });
  DB.friendships.push({ user1: req.user.id, user2: target, status: 'pending' });
  saveDb();
  onlineSockets.forEach(function(uid, sid) {
    if (uid === target) io.to(sid).emit('notification', { type: 'friend_request', from: publicUser(req.user), text: 'طلب صداقة جديد' });
  });
  res.json({ ok: true });
});
app.post('/api/friends/accept/:id', auth, function(req, res) {
  const fromId = parseInt(req.params.id);
  const f = DB.friendships.find(function(x) { return x.user1 === fromId && x.user2 === req.user.id && x.status === 'pending'; });
  if (!f) return res.status(404).json({ error: 'not_found' });
  f.status = 'accepted';
  saveDb();
  res.json({ ok: true });
});
app.post('/api/friends/reject/:id', auth, function(req, res) {
  const fromId = parseInt(req.params.id);
  const idx = DB.friendships.findIndex(function(x) { return x.user1 === fromId && x.user2 === req.user.id && x.status === 'pending'; });
  if (idx !== -1) DB.friendships.splice(idx, 1);
  saveDb();
  res.json({ ok: true });
});
app.delete('/api/friends/:id', auth, function(req, res) {
  const target = parseInt(req.params.id);
  DB.friendships = DB.friendships.filter(function(f) {
    return !((f.user1 === req.user.id && f.user2 === target) || (f.user2 === req.user.id && f.user1 === target));
  });
  saveDb();
  res.json({ ok: true });
});

app.get('/api/dms/:userId', auth, function(req, res) {
  const other = parseInt(req.params.userId);
  if (other === req.user.id) return res.status(400).json({ error: 'self' });
  if (isBlocked(req.user.id, other)) return res.status(403).json({ error: 'blocked' });
  const msgs = DB.dms.filter(function(m) {
    return (m.from_id === req.user.id && m.to_id === other) || (m.from_id === other && m.to_id === req.user.id);
  }).slice(-100);
  msgs.forEach(function(m) { if (m.to_id === req.user.id) m.read = 1; });
  saveDb();
  res.json({ messages: msgs.map(function(m) {
    return { id: m.id, from_id: m.from_id, to_id: m.to_id, text: decryptText(m.text), image: m.image, time: m.time, read: !!m.read };
  }) });
});
app.get('/api/dm-conversations', auth, function(req, res) {
  const otherIds = new Set();
  DB.dms.forEach(function(m) {
    if (m.from_id === req.user.id) otherIds.add(m.to_id);
    else if (m.to_id === req.user.id) otherIds.add(m.from_id);
  });
  const conversations = [];
  otherIds.forEach(function(oid) {
    const other = DB.users.find(function(u) { return u.id === oid; });
    if (!other) return;
    const last = DB.dms.filter(function(m) {
      return (m.from_id === req.user.id && m.to_id === oid) || (m.from_id === oid && m.to_id === req.user.id);
    }).slice(-1)[0];
    const unread = DB.dms.filter(function(m) { return m.from_id === oid && m.to_id === req.user.id && !m.read; }).length;
    conversations.push({
      user: publicUser(other),
      last: last ? { text: decryptText(last.text), image: last.image, time: last.time, from_id: last.from_id } : null,
      unread: unread
    });
  });
  conversations.sort(function(a, b) { return (b.last ? b.last.time : 0) - (a.last ? a.last.time : 0); });
  res.json({ conversations: conversations });
});

// ============ Helper ============
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
  const out = {};
  DB.reactions.filter(function(r) { return r.msgId === msgId; }).forEach(function(r) { out[r.emoji] = (out[r.emoji] || 0) + 1; });
  return out;
}

// ============ Socket.IO ============
io.on('connection', function(socket) {
  socket.emit('rooms', ROOMS);
  socket.emit('countries', COUNTRIES);

  socket.on('auth', function(data) {
    const token = data && data.token;
    const t = DB.tokens.find(function(x) { return x.token === token; });
    if (!t) return socket.emit('auth-error', { error: 'invalid_token' });
    const user = getUser(t.user_id);
    if (!user) return socket.emit('auth-error', { error: 'user_not_found' });
    onlineSockets.set(socket.id, user.id);
    socket.emit('auth-ok', { user: publicUser(user) });
  });

  socket.on('check-online', function(data) {
    const targetId = data && data.userId;
    let online = false;
    onlineSockets.forEach(function(uid) { if (uid === targetId) online = true; });
    socket.emit('online-status', { userId: targetId, online: online });
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
      socket.to(prev.room).emit('message', { system: true, text: user.display_name + ' غادر الدردشة', time: Date.now() });
      broadcastUsers(prev.room);
    }
    users.set(socket.id, { userId: userId, room: room });
    socket.join(room);
    socket.emit('joined', { room: room, user: publicUser(user) });
    const roomMsgs = DB.messages.filter(function(m) { return m.room === room; }).slice(-MAX_HISTORY);
    socket.emit('history', roomMsgs.map(function(m) {
      const u = getUser(m.user_id);
      return {
        id: m.id,
        user: u ? { id: u.id, username: u.username, display_name: u.display_name, color: u.color, verified: !!u.verified, avatar: u.avatar } : null,
        text: m.deleted ? '' : decryptText(m.text), image: m.deleted ? null : m.image,
        time: m.time, deleted: !!m.deleted, reactions: getReactions(m.id), sid: null
      };
    }));
    const pin = DB.pins.find(function(p) { return p.room === room; });
    if (pin) {
      const pu = getUser(pin.user_id);
      socket.emit('pin', { msgId: pin.msgId, name: pu ? pu.display_name : '', text: decryptText(pin.text), time: pin.time });
    } else socket.emit('pin', null);
    socket.to(room).emit('message', { system: true, text: user.display_name + ' انضم إلى الدردشة', time: Date.now() });
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
    const msg = { id: DB.nextId.messages++, room: u.room, user_id: u.userId, text: encryptText(text), image: image, time: time, deleted: 0 };
    DB.messages.push(msg);
    extractHashtags(text).forEach(function(tag) {
      DB.hashtags.push({ id: DB.nextId.hashtags++, tag: tag, source_type: 'message', source_id: msg.id, time: time });
    });
    saveDb();
    io.to(u.room).emit('message', { id: msg.id, sid: socket.id, user: publicUser(user), text: text, image: image, time: time, reactions: {} });
  });

  socket.on('delete', function(msgId) {
    const u = users.get(socket.id);
    if (!u) return;
    const m = DB.messages.find(function(x) { return x.id === msgId; });
    if (!m || m.user_id !== u.userId || m.room !== u.room) return;
    m.deleted = 1; m.text = ''; m.image = null;
    saveDb();
    io.to(u.room).emit('deleted', { id: msgId });
  });

  socket.on('react', function(data) {
    const u = users.get(socket.id);
    if (!u) return;
    const emoji = data && data.emoji;
    const msgId = data && data.msgId;
    const allowed = ['❤️','😂','👍','😮','😢','🔥'];
    if (allowed.indexOf(emoji) === -1) return;
    const idx = DB.reactions.findIndex(function(r) { return r.msgId === msgId && r.user_id === u.userId && r.emoji === emoji; });
    if (idx !== -1) DB.reactions.splice(idx, 1);
    else DB.reactions.push({ msgId: msgId, user_id: u.userId, emoji: emoji });
    saveDb();
    io.to(u.room).emit('reaction', { msgId: msgId, reactions: getReactions(msgId) });
  });

  socket.on('pin', function(msgId) {
    const u = users.get(socket.id);
    if (!u) return;
    const m = DB.messages.find(function(x) { return x.id === msgId && x.room === u.room; });
    if (!m) return;
    const idx = DB.pins.findIndex(function(p) { return p.room === u.room; });
    const pinData = { room: u.room, msgId: msgId, text: m.text || '📷 صورة', user_id: u.userId, time: Date.now() };
    if (idx !== -1) DB.pins[idx] = pinData; else DB.pins.push(pinData);
    saveDb();
    const user = getUser(u.userId);
    io.to(u.room).emit('pin', { msgId: msgId, text: decryptText(m.text) || '📷 صورة', name: user ? user.display_name : '', time: Date.now() });
  });

  socket.on('unpin', function() {
    const u = users.get(socket.id);
    if (!u) return;
    DB.pins = DB.pins.filter(function(p) { return p.room !== u.room; });
    saveDb();
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
    if (toId === u) return;
    if (isBlocked(u, toId)) return;
    const t = String((data && data.text) || '').trim().slice(0, 1000);
    const img = (data && data.image) ? String(data.image).slice(0, 300) : null;
    if (!t && !img) return;
    const time = Date.now();
    const msg = { id: DB.nextId.dms++, from_id: u, to_id: toId, text: encryptText(t), image: img, time: time, read: 0 };
    DB.dms.push(msg);
    saveDb();
    const out = { id: msg.id, from_id: u, to_id: toId, text: t, image: img, time: time, read: false };
    socket.emit('dm-message', out);
    onlineSockets.forEach(function(uid, sid) {
      if (uid === toId) {
        io.to(sid).emit('dm-message', out);
        io.to(sid).emit('notification', { type: 'dm', from: publicUser(getUser(u)), text: t || '📷 صورة' });
      }
    });
  });

  socket.on('dm-read', function(data) {
    const u = onlineSockets.get(socket.id);
    if (!u) return;
    const fromId = data && data.fromId;
    DB.dms.forEach(function(m) { if (m.from_id === fromId && m.to_id === u && !m.read) m.read = 1; });
    saveDb();
    onlineSockets.forEach(function(uid, sid) {
      if (uid === fromId) io.to(sid).emit('dm-read-receipt', { byId: u });
    });
  });

  socket.on('dm-typing', function(data) {
    const u = onlineSockets.get(socket.id);
    if (!u) return;
    const toId = data && data.toId;
    if (toId === u) return;
    onlineSockets.forEach(function(uid, sid) {
      if (uid === toId) io.to(sid).emit('dm-typing', { fromId: u, isTyping: !!(data && data.isTyping) });
    });
  });

  socket.on('call-start', function(data) {
    const u = onlineSockets.get(socket.id);
    if (!u) return;
    const targetId = data && data.targetId;
    if (targetId === u) return;
    if (isBlocked(u, targetId)) return;
    const user = getUser(u);
    onlineSockets.forEach(function(uid, sid) {
      if (uid === targetId) {
        io.to(sid).emit('incoming-call', { fromId: socket.id, fromUserId: u, fromName: user.display_name, fromColor: user.color, fromAvatar: user.avatar });
      }
    });
  });

  socket.on('call-accept', function(data) {
    const u = onlineSockets.get(socket.id);
    if (!u) return;
    const user = getUser(u);
    io.to(data.toId).emit('call-accepted', { fromId: socket.id, fromUserId: u, fromName: user.display_name });
  });

  socket.on('call-reject', function(data) {
    const u = onlineSockets.get(socket.id);
    if (!u) return;
    const user = getUser(u);
    io.to(data.toId).emit('call-rejected', { fromId: socket.id, fromName: user ? user.display_name : '' });
  });

  socket.on('call-end', function(data) { io.to(data.toId).emit('call-ended', { fromId: socket.id }); });
  socket.on('webrtc-offer', function(data) { io.to(data.toId).emit('webrtc-offer', { fromId: socket.id, offer: data.offer }); });
  socket.on('webrtc-answer', function(data) { io.to(data.toId).emit('webrtc-answer', { fromId: socket.id, answer: data.answer }); });
  socket.on('webrtc-ice', function(data) { io.to(data.toId).emit('webrtc-ice', { fromId: socket.id, candidate: data.candidate }); });

  socket.on('disconnect', function() {
    const u = users.get(socket.id);
    if (u) {
      const user = getUser(u.userId);
      socket.to(u.room).emit('message', { system: true, text: (user ? user.display_name : '') + ' غادر الدردشة', time: Date.now() });
      socket.to(u.room).emit('call-peer-left', { id: socket.id });
      broadcastUsers(u.room);
    }
    users.delete(socket.id);
    onlineSockets.delete(socket.id);
  });
});

// حذف الرسائل القديمة بعد 48 ساعة
setInterval(function() {
  const cutoff = Date.now() - 48 * 3600 * 1000;
  const before = DB.messages.length + DB.dms.length;
  DB.messages = DB.messages.filter(function(m) { return m.time > cutoff; });
  DB.dms = DB.dms.filter(function(d) { return d.time > cutoff; });
  if (DB.messages.length + DB.dms.length !== before) saveDb();
}, 10 * 60 * 1000);

// حفظ دوري احتياطي
setInterval(function() { if (ghReady) githubSave(); }, 5 * 60 * 1000);

// التشغيل
async function start() {
  await githubLoad();
  server.listen(PORT, '0.0.0.0', function() {
    console.log('✅ السيرفر يعمل على المنفذ ' + PORT);
    console.log('📁 ' + ROOMS.length + ' غرفة جاهزة');
    console.log('💾 البيانات في: ' + DATA_DIR);
    console.log('☁️ GitHub Storage: ' + (ghReady ? 'مفعّل' : 'معطّل'));
  });
}
start();
