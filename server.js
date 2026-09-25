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

// ===== POSTS =====
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

// ===== DMs =====
app.get('/api/dms/:userId', auth, async (req, res) => {
  const other = parseInt(req.params.userId);
  if (other === req.user.id) return res.status(400).json({ error: 'self' });
  if (await isBlocked(req.user.id, other)) return res.status(403).json({ error: 'blocked' });
  const msgs = await q(`SELECT * FROM dms WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?) ORDER BY time ASC LIMIT 100`,
    [req.user.id, other, other, req.user.id]);
  await run('UPDATE dms SET read = 1 WHERE from_id = ? AND to_id = ? AND read = 0', [other, req.user.id]);
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

      await run('UPDATE dms SET delivered = 1 WHERE to_id = ? AND delivered = 0', [user.id]);

      const senders = await q('SELECT DISTINCT from_id FROM dms WHERE to_id = ? AND delivered = 1', [user.id]);
      senders.forEach(s => {
        onlineSockets.forEach((uid, sid) => {
          if (uid === s.from_id) io.to(sid).emit('dm-delivered', { toId: user.id });
        });
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
  try {
    await initDB();
  } catch (e) {
    console.error('❌ initDB error:', e.message);
  }
  server.listen(PORT, '0.0.0.0', () => {
    console.log('✅ Server running on port ' + PORT);
    console.log('🌍 Env: ' + NODE_ENV);
    console.log('📊 DB: Turso');
    console.log('🖼️ Storage: Base64 in DB');
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
