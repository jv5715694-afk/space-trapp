'use strict';
// Space Trapp - servidor (Node 18+, sem dependências)
// Uso: node server.js   (PORT=3000 por padrão)

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');
const scrypt = promisify(crypto.scrypt);

const PORT = parseInt(process.env.PORT || '3000', 10);
const PUBLIC_DIR = path.join(__dirname, 'public');
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const TRUST_PROXY = process.env.TRUST_PROXY === '1'; // use 1 atrás de nginx/Render/etc.
const SESSION_MS = 30 * 24 * 3600 * 1000;
const MAX_BODY = 10 * 1024;

// ---------- banco de dados (arquivo JSON, gravação atômica) ----------
fs.mkdirSync(DATA_DIR, { recursive: true });
let db = { users: {}, sessions: {} }; // users: chave = nick minúsculo
try { db = Object.assign(db, JSON.parse(fs.readFileSync(DB_FILE, 'utf8'))); } catch (e) {}

let dirty = false, writing = false;
function markDirty() { dirty = true; }
function flush() {
  if (!dirty || writing) return;
  dirty = false; writing = true;
  const tmp = DB_FILE + '.tmp';
  fs.writeFile(tmp, JSON.stringify(db), (err) => {
    if (err) { dirty = true; writing = false; console.error('Erro ao gravar:', err.message); return; }
    fs.rename(tmp, DB_FILE, (err2) => { writing = false; if (err2) { dirty = true; console.error(err2.message); } });
  });
}
setInterval(flush, 2000).unref();
function flushSync() { if (dirty) { try { fs.writeFileSync(DB_FILE, JSON.stringify(db)); dirty = false; } catch (e) {} } }
['SIGINT', 'SIGTERM'].forEach((s) => process.on(s, () => { flushSync(); process.exit(0); }));
process.on('exit', flushSync);

// limpeza de sessões expiradas
setInterval(() => {
  const now = Date.now();
  for (const k in db.sessions) if (db.sessions[k].exp < now) { delete db.sessions[k]; markDirty(); }
}, 3600 * 1000).unref();

// ---------- utilidades ----------
const NICK_RE = /^[A-Za-z0-9_]{3,16}$/;
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

async function hashPass(pass) {
  const salt = crypto.randomBytes(16);
  const h = await scrypt(pass, salt, 64);
  return salt.toString('hex') + ':' + h.toString('hex');
}
async function checkPass(pass, stored) {
  const [s, h] = stored.split(':');
  const calc = await scrypt(pass, Buffer.from(s, 'hex'), 64);
  const real = Buffer.from(h, 'hex');
  return calc.length === real.length && crypto.timingSafeEqual(calc, real);
}
const DUMMY_HASH = '00000000000000000000000000000000:' + '00'.repeat(64);

function cleanSave(v, prev) {
  v = v && typeof v === 'object' ? v : {};
  const int = (x, max) => Math.max(0, Math.min(max, Math.floor(Number(x)) || 0));
  const own1 = !!v.own1;
  const skin = int(v.skin, 1);
  return {
    bag: int(v.bag, 1e9),
    own1,
    glv: Math.max(1, Math.min(3, int(v.glv, 3) || 1)),
    best: int(v.best, 1e9),
    skin: skin === 1 && !own1 ? 0 : skin,
  };
}
const DEFAULT_SAVE = { bag: 0, own1: false, glv: 1, best: 0, skin: 0 };

// limite de tentativas (em memória)
const hits = new Map();
function limited(key, max, windowMs) {
  const now = Date.now();
  const arr = (hits.get(key) || []).filter((t) => now - t < windowMs);
  hits.set(key, arr);
  return arr.length >= max;
}
function hit(key) { (hits.get(key) || hits.set(key, []).get(key)).push(Date.now()); }
setInterval(() => { hits.clear(); }, 3600 * 1000).unref();

function clientIp(req) {
  if (TRUST_PROXY) {
    const x = req.headers['x-forwarded-for'];
    if (x) return String(x).split(',')[0].trim();
  }
  return req.socket.remoteAddress || '?';
}

function send(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) { reject(Object.assign(new Error('Requisição grande demais'), { code: 413 })); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch (e) { reject(Object.assign(new Error('JSON inválido'), { code: 400 })); }
    });
    req.on('error', reject);
  });
}

function authUser(req) {
  const m = /^Bearer (\S+)$/.exec(req.headers.authorization || '');
  if (!m) return null;
  const s = db.sessions[sha(m[1])];
  if (!s || s.exp < Date.now()) return null;
  const u = db.users[s.user];
  return u ? { user: u, key: sha(m[1]) } : null;
}

function newSession(userKey) {
  const token = crypto.randomBytes(32).toString('hex');
  db.sessions[sha(token)] = { user: userKey, exp: Date.now() + SESSION_MS };
  markDirty();
  return token;
}

// ---------- API ----------
async function api(req, res, route) {
  const ip = clientIp(req);

  if (route === 'register' && req.method === 'POST') {
    if (limited('reg:' + ip, 10, 3600 * 1000)) return send(res, 429, { error: 'Muitas contas criadas. Tente mais tarde.' });
    const b = await readJson(req);
    const nick = String(b.nick || '').trim();
    const pass = String(b.pass || '');
    if (!NICK_RE.test(nick)) return send(res, 400, { error: 'Nick inválido (3-16: letras, números e _)' });
    if (pass.length < 6 || pass.length > 100) return send(res, 400, { error: 'A senha precisa ter de 6 a 100 caracteres' });
    const key = nick.toLowerCase();
    if (db.users[key]) return send(res, 409, { error: 'Esse nick já está em uso' });
    hit('reg:' + ip);
    const passHash = await hashPass(pass);
    if (db.users[key]) return send(res, 409, { error: 'Esse nick já está em uso' }); // corrida durante o hash
    const save = b.save ? cleanSave(b.save) : { ...DEFAULT_SAVE };
    db.users[key] = { nick, pass: passHash, save, created: Date.now() };
    const token = newSession(key);
    markDirty();
    return send(res, 200, { token, nick, save });
  }

  if (route === 'login' && req.method === 'POST') {
    const b = await readJson(req);
    const nick = String(b.nick || '').trim();
    const pass = String(b.pass || '');
    const key = nick.toLowerCase();
    const lk = 'login:' + ip + ':' + key;
    if (limited(lk, 8, 10 * 60 * 1000)) return send(res, 429, { error: 'Muitas tentativas. Aguarde alguns minutos.' });
    const u = db.users[key];
    const ok = await checkPass(pass.slice(0, 100), u ? u.pass : DUMMY_HASH);
    if (!u || !ok) { hit(lk); return send(res, 401, { error: 'Nick ou senha incorretos' }); }
    const token = newSession(key);
    return send(res, 200, { token, nick: u.nick, save: u.save });
  }

  if (route === 'me' && req.method === 'GET') {
    const a = authUser(req);
    if (!a) return send(res, 401, { error: 'Sessão expirada' });
    return send(res, 200, { nick: a.user.nick, save: a.user.save });
  }

  if (route === 'save' && req.method === 'POST') {
    const a = authUser(req);
    if (!a) return send(res, 401, { error: 'Sessão expirada' });
    if (limited('save:' + a.key, 60, 60 * 1000)) return send(res, 429, { error: 'Calma!' });
    hit('save:' + a.key);
    const b = await readJson(req);
    const next = cleanSave(b);
    // o recorde nunca diminui; o que já foi comprado não se perde
    next.best = Math.max(next.best, a.user.save.best);
    next.own1 = next.own1 || a.user.save.own1;
    next.glv = Math.max(next.glv, a.user.save.glv);
    a.user.save = next;
    markDirty();
    return send(res, 200, { ok: true });
  }

  if (route === 'logout' && req.method === 'POST') {
    const a = authUser(req);
    if (a) { delete db.sessions[a.key]; markDirty(); }
    return send(res, 200, { ok: true });
  }

  if (route === 'ranking' && req.method === 'GET') {
    const top = Object.values(db.users)
      .map((u) => ({ nick: u.nick, best: u.save.best }))
      .filter((u) => u.best > 0)
      .sort((x, y) => y.best - x.best)
      .slice(0, 20);
    return send(res, 200, { top });
  }

  return send(res, 404, { error: 'Rota não encontrada' });
}

// ---------- arquivos estáticos (com suporte a Range para o áudio) ----------
const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif',
  '.svg': 'image/svg+xml', '.webp': 'image/webp', '.ico': 'image/x-icon', '.mp3': 'audio/mpeg', '.ogg': 'audio/ogg',
  '.wav': 'audio/wav', '.woff2': 'font/woff2',
};

function serveStatic(req, res, urlPath) {
  if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end(); }
  let rel;
  try { rel = decodeURIComponent(urlPath); } catch (e) { res.writeHead(400); return res.end(); }
  if (rel === '/' || rel === '') rel = '/index.html';
  const file = path.normalize(path.join(PUBLIC_DIR, rel));
  if (file !== PUBLIC_DIR && !file.startsWith(PUBLIC_DIR + path.sep)) { res.writeHead(403); return res.end(); }
  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('Não encontrado'); }
    const ext = path.extname(file).toLowerCase();
    const headers = {
      'Content-Type': MIME[ext] || 'application/octet-stream',
      'Accept-Ranges': 'bytes',
      'Cache-Control': ext === '.html' ? 'no-cache' : 'public, max-age=86400',
    };
    let start = 0, end = st.size - 1, code = 200;
    const r = /^bytes=(\d*)-(\d*)$/.exec(req.headers.range || '');
    if (r && (r[1] || r[2])) {
      if (r[1]) { start = parseInt(r[1], 10); if (r[2]) end = Math.min(end, parseInt(r[2], 10)); }
      else { start = Math.max(0, st.size - parseInt(r[2], 10)); }
      if (start > end || start >= st.size) { res.writeHead(416, { 'Content-Range': 'bytes */' + st.size }); return res.end(); }
      code = 206; headers['Content-Range'] = 'bytes ' + start + '-' + end + '/' + st.size;
    }
    headers['Content-Length'] = end - start + 1;
    res.writeHead(code, headers);
    if (req.method === 'HEAD') return res.end();
    fs.createReadStream(file, { start, end }).pipe(res);
  });
}

// ---------- servidor ----------
const server = http.createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'same-origin');
  const urlPath = (req.url || '/').split('?')[0];
  try {
    if (urlPath.startsWith('/api/')) return await api(req, res, urlPath.slice(5).replace(/\/$/, ''));
    return serveStatic(req, res, urlPath);
  } catch (e) {
    if (e && e.code === 413) return send(res, 413, { error: e.message });
    if (e && e.code === 400) return send(res, 400, { error: e.message });
    console.error(e);
    if (!res.headersSent) send(res, 500, { error: 'Erro interno do servidor' });
  }
});

server.listen(PORT, () => console.log('Space Trapp rodando em http://localhost:' + PORT));
