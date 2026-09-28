'use strict';
// CEO เมากาว 
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const { db, hashPassword, verifyPassword } = require('./db');
const migrate = require('./migrate');

const FRONTEND = path.resolve(process.env.FRONTEND_DIR || path.join(__dirname, '..', 'frontend'));
const PORT = +process.env.PORT || 3000, HOST = process.env.HOST || (process.env.RENDER ? '0.0.0.0' : '127.0.0.1');
const SECURE = process.env.COOKIE_SECURE === '1';
const SESSION_MS = 7 * 24 * 3600 * 1000, MAX_BODY = 6 * 1024 * 1024;
// โดเมนหน้าเว็บที่อนุญาตให้เรียก API ข้ามโดเมน เช่น https://breakerxxx90.github.io (คั่นด้วย , ได้หลายตัว)
const ALLOWED = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim().replace(/\/$/, '')).filter(Boolean);

// ---------- ตัวช่วยพื้นฐาน ----------
class HttpError extends Error { constructor(code, msg) { super(msg); this.code = code; } }
const MSG = { 401: 'กรุณาเข้าสู่ระบบ', 403: 'ไม่มีสิทธิ์ทำรายการนี้', 404: 'ไม่พบข้อมูล', 413: 'ไฟล์ใหญ่เกินไป (สูงสุด 5MB)' };
const fail = (code, msg) => { throw new HttpError(code, msg || MSG[code] || 'เกิดข้อผิดพลาด'); };
const R = (code, body) => ({ __r: 1, code, body });
const SEC = { 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'same-origin' };

function sendJson(res, code, obj, extra = {}) {
  const b = JSON.stringify(obj);
  res.writeHead(code, { ...SEC, 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(b), 'Cache-Control': 'no-store', ...extra });
  res.end(b);
}
const redirect = (res, to) => { res.writeHead(302, { ...SEC, Location: to }); res.end(); };

function readBody(req) {
  return new Promise((ok, no) => {
    const ch = []; let n = 0, over = false;
    req.on('data', c => { n += c.length; if (over) return; if (n > MAX_BODY) { over = true; ch.length = 0; return; } ch.push(c); });
    req.on('end', () => over ? no(new HttpError(413)) : ok(Buffer.concat(ch)));
    req.on('error', no);
  });
}

function parseMultipart(buf, boundary) {
  const fields = {}, files = {}, b = Buffer.from('--' + boundary);
  let pos = buf.indexOf(b);
  while (pos !== -1) {
    let start = pos + b.length;
    if (buf[start] === 0x2d && buf[start + 1] === 0x2d) break;
    start += 2;
    const next = buf.indexOf(b, start);
    if (next === -1) break;
    const part = buf.subarray(start, next - 2), he = part.indexOf('\r\n\r\n');
    if (he !== -1) {
      const head = part.subarray(0, he).toString('utf8'), data = part.subarray(he + 4);
      const name = (/[; ]name="([^"]*)"/.exec(head) || [])[1];
      const fn = (/filename="([^"]*)"/.exec(head) || [])[1];
      if (name !== undefined) {
        if (fn !== undefined) { if (fn) files[name] = { filename: fn, data }; }
        else fields[name] = data.toString('utf8');
      }
    }
    pos = next;
  }
  return { fields, files };
}

async function parseBody(req) {
  const buf = await readBody(req), ct = req.headers['content-type'] || '';
  if (ct.startsWith('multipart/form-data')) {
    const m = /boundary=(?:"([^"]+)"|([^;]+))/.exec(ct);
    if (!m) fail(400, 'ข้อมูลไม่ถูกต้อง');
    return parseMultipart(buf, m[1] || m[2]);
  }
  if (ct.includes('json') && buf.length) {
    let x; try { x = JSON.parse(buf.toString('utf8')); } catch { fail(400, 'ข้อมูลไม่ถูกต้อง'); }
    return { fields: x && typeof x === 'object' && !Array.isArray(x) ? x : {}, files: {} };
  }
  return { fields: {}, files: {} };
}

const cookies = req => Object.fromEntries((req.headers.cookie || '').split(';').map(s => s.trim().split(/=(.*)/s).slice(0, 2)).filter(a => a[0]));
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const tokenOf = req => { const m = /^Bearer (.+)$/i.exec(req.headers.authorization || ''); return m ? m[1].trim() : cookies(req).sid; };

// ---------- session / สิทธิ์ ----------
async function userFrom(req) {
  const t = tokenOf(req);
  if (!t) return null;
  return db.get('SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires>?', sha(t), Date.now());
}
async function startSession(ctx, uid) {
  const t = crypto.randomBytes(32).toString('hex');
  ctx.token = t;
  await db.run('DELETE FROM sessions WHERE expires<?', Date.now());
  await db.run('INSERT INTO sessions(token,user_id,expires) VALUES(?,?,?)', sha(t), uid, Date.now() + SESSION_MS);
  ctx.cookie = `sid=${t}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_MS / 1000}${SECURE ? '; Secure' : ''}`;
}
async function endSession(ctx) {
  const t = tokenOf(ctx.req);
  if (t) await db.run('DELETE FROM sessions WHERE token=?', sha(t));
  ctx.cookie = `sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${SECURE ? '; Secure' : ''}`;
}
const pub = u => ({ id: u.id, username: u.username, name: u.name, cls: u.cls, uni: u.uni, role: u.role, avatar: u.avatar || '' });

const FAILS = new Map();
const throttled = k => { const now = Date.now(), a = (FAILS.get(k) || []).filter(t => now - t < 3e5); FAILS.set(k, a); return a.length >= 5; };

// ---------- ตารางเส้นทาง ----------
const routes = [];
// auth: null = ไม่ต้องล็อกอิน | 'user' = ต้องล็อกอิน | 'admin' = ต้องเป็นแอดมิน
const route = (method, p, auth, fn) => routes.push({ method, re: new RegExp('^' + p.replace(':id', '(\\d{1,9})') + '$'), auth, fn });

async function doLogin(ctx, adminOnly) {
  const d = ctx.fields, un = String(d.username || '').trim(), pw = String(d.password || '');
  const key = `${ctx.req.socket.remoteAddress}|${un.toLowerCase()}`;
  if (throttled(key)) fail(429, 'ลองผิดหลายครั้งเกินไป กรุณารอ 5 นาที');
  const u = await db.get('SELECT * FROM users WHERE lower(username)=lower(?)', un);
  if (!u || !(await verifyPassword(pw, u.password_hash))) {
    FAILS.get(key).push(Date.now());
    fail(401, 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง');
  }
  if (adminOnly && u.role !== 'admin') fail(403, 'บัญชีนี้ไม่ใช่ผู้ดูแลระบบ');
  await startSession(ctx, u.id);
  return { user: pub(u), token: ctx.token };
}
route('POST', '/api/auth/login', null, ctx => doLogin(ctx, false));
route('POST', '/api/auth/admin-login', null, ctx => doLogin(ctx, true));
route('POST', '/api/auth/signup', null, async ctx => {
  const un = String(ctx.fields.username || '').trim(), pw = String(ctx.fields.password || '');
  if (!/^[A-Za-z0-9_.-]{3,30}$/.test(un)) fail(400, 'ชื่อผู้ใช้ต้องเป็นตัวอักษรอังกฤษ/ตัวเลข/._- ยาว 3-30 ตัว');
  if (pw.length < 8 || pw.length > 128) fail(400, 'รหัสผ่านต้องยาว 8 ตัวอักษรขึ้นไป');
  let u;
  try { u = (await db.run('INSERT INTO users(username,password_hash,name) VALUES(?,?,?) RETURNING *', un, await hashPassword(pw), un)).rows[0]; }
  catch (e) { if (e.code === '23505') fail(409, 'ชื่อผู้ใช้นี้ถูกใช้แล้ว'); throw e; }
  await startSession(ctx, u.id);
  return R(201, { user: pub(u), token: ctx.token });
});
route('POST', '/api/auth/logout', null, async ctx => { await endSession(ctx); return { ok: true }; });
route('GET', '/api/me', 'user', ctx => pub(ctx.user));
route('PUT', '/api/me', 'user', async ctx => {
  const u = ctx.user, f = ctx.fields;
  const name = String(f.name ?? u.name).trim(), cls = String(f.cls ?? u.cls).trim(), uni = String(f.uni ?? u.uni).trim();
  if (name.length < 1 || name.length > 50) fail(400, 'ชื่อต้องยาว 1-50 ตัวอักษร');
  if (cls.length > 30 || uni.length > 80) fail(400, 'ข้อมูล Class หรือ University ยาวเกินไป');
  await db.run('UPDATE users SET name=?,cls=?,uni=? WHERE id=?', name, cls, uni, u.id);
  return pub(await db.get('SELECT * FROM users WHERE id=?', u.id));
});
route('GET', '/api/admin/users', 'admin', () => db.all('SELECT id,username,name,cls,uni,role,created_at FROM users ORDER BY id'));

// ---- หมวดหมู่
const catRows = () => db.all('SELECT c.id,c.name,(SELECT COUNT(*)::int FROM activities a WHERE a.category_id=c.id) AS count FROM categories c ORDER BY c.id');
const catName = f => { const n = String(f.name || '').trim(); if (n.length < 1 || n.length > 50) fail(400, 'ชื่อหมวดหมู่ต้องยาว 1-50 ตัวอักษร'); return n; };
const dup = e => { if (e.code === '23505') fail(409, 'มีหมวดหมู่นี้อยู่แล้ว'); throw e; };
route('GET', '/api/categories', 'user', () => catRows());
route('POST', '/api/categories', 'admin', async ctx => {
  const n = catName(ctx.fields);
  try { const r = await db.run('INSERT INTO categories(name) VALUES(?) RETURNING id', n); return R(201, { id: r.rows[0].id, name: n, count: 0 }); } catch (e) { dup(e); }
});
route('PUT', '/api/categories/:id', 'admin', async ctx => {
  const n = catName(ctx.fields); let r;
  try { r = await db.run('UPDATE categories SET name=? WHERE id=?', n, ctx.params[0]); } catch (e) { dup(e); }
  if (!r.changes) fail(404);
  return { id: +ctx.params[0], name: n };
});
route('DELETE', '/api/categories/:id', 'admin', async ctx => {
  if (await db.get('SELECT 1 AS x FROM activities WHERE category_id=?', ctx.params[0])) fail(409, 'ลบไม่ได้: ยังมีกิจกรรมอยู่ในหมวดนี้');
  if (!(await db.run('DELETE FROM categories WHERE id=?', ctx.params[0])).changes) fail(404);
  return { ok: true };
});

// ---- กิจกรรม
const SEL = `SELECT a.id,a.name,a.hours,a.description,a.image,a.created_at,a.category_id,c.name AS category,
 (SELECT COUNT(*)::int FROM views v WHERE v.activity_id=a.id) AS viewers
 FROM activities a JOIN categories c ON c.id=a.category_id`;
const getAct = id => db.get(SEL + ' WHERE a.id=?', id);

async function readFields(f) {
  const name = String(f.name || '').trim();
  if (name.length < 1 || name.length > 120) fail(400, 'กรุณากรอกชื่อกิจกรรม (ไม่เกิน 120 ตัวอักษร)');
  const cid = Number(f.category_id);
  if (!Number.isInteger(cid) || cid < 1 || cid > 2147483647) fail(400, 'กรุณาเลือกหมวดหมู่');
  if (!(await db.get('SELECT 1 AS x FROM categories WHERE id=?', cid))) fail(400, 'ไม่พบหมวดหมู่นี้');
  const hours = f.hours === undefined || f.hours === '' ? 0 : Number(f.hours);
  if (!Number.isInteger(hours)) fail(400, 'จำนวนชั่วโมงต้องเป็นตัวเลข');
  if (hours < 0 || hours > 1000) fail(400, 'จำนวนชั่วโมงต้องอยู่ระหว่าง 0-1000');
  return { name, cid, hours, desc: String(f.description || '').trim().slice(0, 2000) };
}
const MIME = { jpg: 'image/jpeg', png: 'image/png', gif: 'image/gif', webp: 'image/webp' };
async function saveUpload(file) {
  const h = file.data.subarray(0, 12);
  let ext = null;
  if (h[0] === 0xff && h[1] === 0xd8 && h[2] === 0xff) ext = 'jpg';
  else if (h.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) ext = 'png';
  else if (['GIF87a', 'GIF89a'].includes(h.subarray(0, 6).toString('latin1'))) ext = 'gif';
  else if (h.subarray(0, 4).toString('latin1') === 'RIFF' && h.subarray(8, 12).toString('latin1') === 'WEBP') ext = 'webp';
  if (!ext) fail(400, 'รองรับเฉพาะไฟล์รูป JPG, PNG, GIF, WEBP');
  const name = crypto.randomUUID().replace(/-/g, '') + '.' + ext;
  await db.run('INSERT INTO uploads(name,mime,data) VALUES(?,?,?)', name, MIME[ext], file.data);
  return '/uploads/' + name;
}
function validUrl(u) {
  try { const x = new URL(u); return ['http:', 'https:'].includes(x.protocol) && u.length <= 500 && !/[\s'"<>]/.test(u); } catch { return false; }
}
const dropFile = img => img.startsWith('/uploads/') ? db.run('DELETE FROM uploads WHERE name=?', path.basename(img)).catch(() => {}) : null;
async function resolveImage(ctx, current = '') {
  const file = ctx.files.image, url = String(ctx.fields.image_url || '').trim();
  if (url && !validUrl(url)) fail(400, 'ลิงก์รูปต้องขึ้นต้นด้วย http:// หรือ https://');
  let img;
  if (file) img = await saveUpload(file);
  else if (url) img = url;
  else if (current.startsWith('/uploads/')) img = current;
  else img = '';
  if (img !== current) dropFile(current);
  return img;
}

route('GET', '/api/activities', 'user', ctx => {
  let sql = SEL + ' WHERE 1=1'; const args = [], q = ctx.query;
  if (q.get('category')) { sql += ' AND c.name=?'; args.push(q.get('category')); }
  if (q.get('q')) { sql += ' AND a.name ILIKE ?'; args.push('%' + q.get('q').trim() + '%'); }
  const limit = Math.min(parseInt(q.get('limit')) || 500, 500);
  return db.all(sql + ' ORDER BY a.id DESC LIMIT ?', ...args, limit);
});
route('POST', '/api/activities', 'admin', async ctx => {
  const { name, cid, hours, desc } = await readFields(ctx.fields), img = await resolveImage(ctx);
  const id = (await db.run('INSERT INTO activities(name,category_id,hours,description,image) VALUES(?,?,?,?,?) RETURNING id', name, cid, hours, desc, img)).rows[0].id;
  return R(201, await getAct(id));
});
route('PUT', '/api/activities/:id', 'admin', async ctx => {
  const id = ctx.params[0], old = await db.get('SELECT * FROM activities WHERE id=?', id);
  if (!old) fail(404);
  const { name, cid, hours, desc } = await readFields(ctx.fields), img = await resolveImage(ctx, old.image);
  await db.run('UPDATE activities SET name=?,category_id=?,hours=?,description=?,image=? WHERE id=?', name, cid, hours, desc, img, id);
  return getAct(id);
});
route('DELETE', '/api/activities/:id', 'admin', async ctx => {
  const old = await db.get('SELECT image FROM activities WHERE id=?', ctx.params[0]);
  if (!old) fail(404);
  await db.run('DELETE FROM activities WHERE id=?', ctx.params[0]);
  dropFile(old.image);
  return { ok: true };
});
route('POST', '/api/activities/:id/view', 'user', async ctx => {
  if (!(await getAct(ctx.params[0]))) fail(404);
  await db.run('INSERT INTO views(user_id,activity_id) VALUES(?,?) ON CONFLICT DO NOTHING', ctx.user.id, ctx.params[0]);
  return { viewers: (await getAct(ctx.params[0])).viewers };
});
// ---- รูปโปรไฟล์ (อัปโหลดไฟล์ หรือใช้ลิงก์รูป)
route('PUT', '/api/me/avatar', 'user', async ctx => {
  if (!ctx.files.image && !String(ctx.fields.image_url || '').trim()) fail(400, 'กรุณาเลือกรูปหรือใส่ลิงก์รูป');
  const img = await resolveImage(ctx, ctx.user.avatar || '');
  await db.run('UPDATE users SET avatar=? WHERE id=?', img, ctx.user.id);
  return pub(await db.get('SELECT * FROM users WHERE id=?', ctx.user.id));
});
route('DELETE', '/api/me/avatar', 'user', async ctx => {
  dropFile(ctx.user.avatar || '');
  await db.run("UPDATE users SET avatar='' WHERE id=?", ctx.user.id);
  return pub(await db.get('SELECT * FROM users WHERE id=?', ctx.user.id));
});
// ---- เข้าร่วมกิจกรรม
route('GET', '/api/me/joins', 'user', async ctx => (await db.all('SELECT activity_id FROM joins WHERE user_id=?', ctx.user.id)).map(r => r.activity_id));
route('POST', '/api/activities/:id/join', 'user', async ctx => {
  if (!(await getAct(ctx.params[0]))) fail(404);
  await db.run('INSERT INTO joins(user_id,activity_id) VALUES(?,?) ON CONFLICT DO NOTHING', ctx.user.id, ctx.params[0]);
  return { joined: true };
});
route('DELETE', '/api/activities/:id/join', 'user', async ctx => {
  await db.run('DELETE FROM joins WHERE user_id=? AND activity_id=?', ctx.user.id, ctx.params[0]);
  return { joined: false };
});

// ---------- ไฟล์หน้าเว็บ ----------
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.webp': 'image/webp', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.txt': 'text/plain; charset=utf-8' };
const USER_PAGES = new Set(['/home.html', '/activities.html', '/activity.html', '/notifications.html', '/profile.html']);

function serveFile(req, res, root, rel) {
  const file = path.resolve(root, '.' + path.sep + rel);
  if (file !== root && !file.startsWith(root + path.sep)) return sendJson(res, 404, { error: MSG[404] });
  fs.stat(file, (e, st) => {
    if (e || !st.isFile()) return sendJson(res, 404, { error: MSG[404] });
    res.writeHead(200, { ...SEC, 'Content-Type': TYPES[path.extname(file).toLowerCase()] || 'application/octet-stream', 'Content-Length': st.size });
    if (req.method === 'HEAD') return res.end();
    fs.createReadStream(file).pipe(res);
  });
}

async function serveUpload(req, res, name) {
  const r = await db.get('SELECT mime,data FROM uploads WHERE name=?', name);
  if (!r) return sendJson(res, 404, { error: MSG[404] });
  res.writeHead(200, { ...SEC, 'Content-Type': r.mime, 'Content-Length': r.data.length, 'Cache-Control': 'public, max-age=31536000, immutable' });
  res.end(req.method === 'HEAD' ? undefined : r.data);
}

// ---------- ตัวจัดการคำขอ ----------
const server = http.createServer(async (req, res) => {
  const ctx = { req, cookie: null };
  try {
    const origin = req.headers.origin;
    if (origin && ALLOWED.includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Vary', 'Origin');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
      res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
      res.setHeader('Access-Control-Max-Age', '86400');
    }
    if (req.method === 'OPTIONS') { res.writeHead(204, SEC); return res.end(); }
    const url = new URL(req.url, 'http://x'), p = decodeURIComponent(url.pathname);
    ctx.query = url.searchParams;
    ctx.user = await userFrom(req);

    if (!['GET', 'HEAD'].includes(req.method) && req.headers.origin) {   // กัน CSRF เพิ่มอีกชั้น
      let ok = ALLOWED.includes(req.headers.origin); try { ok = ok || new URL(req.headers.origin).host === req.headers.host; } catch {}
      if (!ok) fail(403);
    }

    if (p.startsWith('/api/')) {
      const r = routes.find(x => x.method === req.method && x.re.test(p));
      if (!r) fail(404);
      if (r.auth && !ctx.user) fail(401);
      if (r.auth === 'admin' && ctx.user.role !== 'admin') fail(403);
      ctx.params = r.re.exec(p).slice(1);
      Object.assign(ctx, ['POST', 'PUT', 'PATCH'].includes(req.method) ? await parseBody(req) : { fields: {}, files: {} });
      const out = await r.fn(ctx);
      const { code, body } = out && out.__r ? out : { code: 200, body: out };
      return sendJson(res, code, body, ctx.cookie ? { 'Set-Cookie': ctx.cookie } : {});
    }

    if (!['GET', 'HEAD'].includes(req.method)) fail(404);
    if (p === '/') {
      if (process.env.FRONTEND_URL) return redirect(res, process.env.FRONTEND_URL);
      if (fs.existsSync(path.join(FRONTEND, 'index.html'))) return serveFile(req, res, FRONTEND, '/index.html');
      return sendJson(res, 200, { ok: true, service: 'ceo-backend' });
    }
    if (USER_PAGES.has(p) && !ctx.user) return redirect(res, '/login.html');
    if (p === '/admin.html' && (!ctx.user || ctx.user.role !== 'admin')) return redirect(res, '/admin-login.html');
    if (p.startsWith('/uploads/')) return await serveUpload(req, res, path.basename(p));
    return serveFile(req, res, FRONTEND, p);
  } catch (e) {
    if (!(e instanceof HttpError)) console.error(e);
    const code = e instanceof HttpError ? e.code : 500;
    const extra = ctx.cookie && code < 400 ? { 'Set-Cookie': ctx.cookie } : {};
    sendJson(res, code, { error: e instanceof HttpError ? e.message : 'เซิร์ฟเวอร์ขัดข้อง' }, extra);
  }
});

migrate().then(() => server.listen(PORT, HOST, () => console.log(`เปิดที่ http://${HOST}:${PORT}`))).catch(e => { console.error('migrate ล้มเหลว:', e); process.exit(1); });
module.exports = server;