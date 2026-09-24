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

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET','POST'] },
  maxHttpBufferSize: 5 * 1024 * 1024
});

app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const DB_FILE = path.join(__dirname, 'data.json');
const SECRET_FILE = path.join(__dirname, '.secret');

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
  friendships: [], dms: [],
  nextId: { users: 1, messages: 1, posts: 1, post_comments: 1, dms: 1, hashtags: 1 }
};

if (fs.existsSync(DB_FILE)) {
  try { Object.assign(DB, JSON.parse(fs.readFileSync(DB_FILE, 'utf8'))); }
  catch (e) { console.error('DB load error:', e.message); }
}

let saveTimer = null;
function saveDb() {
  if (saveTimer) return;
  saveTimer = setTimeout(function() {
    saveTimer = null;
    try { fs.writeFileSync(DB_FILE, JSON.stringify(DB)); } catch (_) {}
  }, 500);
}

const uploadsDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

const storage = multer.diskStorage({
  destination: uploadsDir,
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
    verified: !!u.verified, avatar: u.avatar,
    created_at: u.created_at, last_seen: u.last_seen,
    lang: u.lang, theme: u.theme, sound: !!u.sound, notifications: !!u.notifications,
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

app.post('/api/register', function(req, res) {
  const body = req.body || {};
  const name = String(body.display_name || '').trim().slice(0, 30);
  const pass = String(body.password || '');
  if (!name) return res.status(400).json({ error: 'name_required' });
  if (pass.length < 4) return res.status(400).json({ error: 'password_too_short' });
  if (DB.users.find(function(u) { return u.display_name === name; })) return res.status(409).json({ error: 'name_taken' });

  const user = {
    id: DB.nextId.users++, username: genUsername(name), display_name: name,
    password: hashPassword(pass),
    color: /^#[0-9a-fA-F]{6}$/.test(body.color || '') ? body.color : COLORS[Math.floor(Math.random() * COLORS.length)],
    bio: String(body.bio || '').slice(0, 200),
    location: String(body.location || '').slice(0, 60),
    country: String(body.country || '').slice(0, 40),
    phone: String(body.phone || '').slice(0, 20),
    verified: 0, avatar: '', created_at: Date.now(), last_seen: Date.now(),
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
  if (body.bio !== undefined) u.bio = String(body.bio).slice(0, 200);
  if (body.location !== undefined) u.location = String(body.location).slice(0, 60);
  if (body.country !== undefined) u.country = String(body.country).slice(0, 40);
  if (body.phone !== undefined) {
    u.phone = String(body.phone).slice(0, 20);
    if (u.phone.replace(/\D/g, '').length >= 8) u.verified = 1;
  }
  if (body.avatar !== undefined) u.avatar = String(body.avatar).slice(0, 300);
  if (body.color !== undefined && /^#[0-9a-fA-F]{6}$/.test(body.color)) u.color = body.color;
  if (body.lang !== undefined && ['ar','en'].indexOf(body.lang) !== -1) u.lang = body.lang;
  if (body.theme !== undefined && ['dark','light'].indexOf(body.theme) !== -1) u.theme = body.theme;
  if (body.sound !== undefined) u.sound = body.sound ? 1 : 0;
  if (body.notifications !== undefined) u.notifications = body.notifications ? 1 : 0;
  saveDb();
  res.json({ user: publicUser(u) });
});

app.get('/api/users/search', auth, function(req, res) {
  const q = String(req.query.q || '').trim().slice(0, 40);
  if (!q) return res.json({ users: [] });
  const lq = q.toLowerCase();
  const users = DB.users.filter(function(u) {
    return u.id !== req.user.id && (u.username.toLowerCase().indexOf(lq) !== -1 || u.display_name.toLowerCase().indexOf(lq) !== -1);
  }).slice(0, 30);
  res.json({ users: users.map(publicUser) });
});

app.get('/api/users/:id', auth, function(req, res) {
  const u = DB.users.find(function(x) { return x.id === parseInt(req.params.id); });
  if (!u) return res.status(404).json({ error: 'not_found' });
  const isFriend = DB.friendships.some(function(f) {
    return ((f.user1 === req.user.id && f.user2 === u.id) || (f.user2 === req.user.id && f.user1 === u.id)) && f.status === 'accepted';
  });
  res.json({ user: publicUser(u), isFriend: isFriend });
});
