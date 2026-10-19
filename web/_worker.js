// Cloudflare Pages (advanced mode): one project serves both hostnames.
//   web.lockin-app.online  -> the Lock In web app (static files in this folder)
//                             + /api/*  friends (Cloudflare D1, binding "DB"). Everything a friend can see is
//                               end-to-end encrypted on the phones: this server only ever stores ciphertext and
//                               decides who may download which encrypted piece (and the keys wrapped for them).
//                             + /i/<code> /s/<code> /q/<code>  invite / shared-split / QR links with previews
//   ipa.lockin-app.online  -> the SideStore/AltStore source (always the latest from GitHub)
const SOURCE = 'https://raw.githubusercontent.com/Trohorm/summer-lock-in/main/source.json';
const PUTER_API = 'https://api.puter.com';
const API_VERSION = '2';

/* security headers on everything this worker returns */
const SEC = {
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'x-frame-options': 'DENY',
  'permissions-policy': 'camera=(self), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()',
  'content-security-policy': "frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'self'; upgrade-insecure-requests"
};
function secure(res, extra) {
  const h = new Headers(res.headers);
  for (const k in SEC) h.set(k, SEC[k]);
  if (extra) for (const k in extra) h.set(k, extra[k]);
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers: h });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.hostname.startsWith('ipa.')) return ipaSource(url);
    if (url.pathname.startsWith('/api/')) return secure(await api(request, env, ctx, url));
    const lm = /^\/(i|s|q)\/([A-Za-z0-9-]{4,20})\/?$/.exec(url.pathname);
    if (lm && request.method === 'GET') return secure(await landing(env, url, lm[1], lm[2], request));
    const res = await env.ASSETS.fetch(request);
    const html = (res.headers.get('content-type') || '').includes('text/html');
    return secure(res, html || url.pathname.endsWith('sw.js') ? { 'cache-control': 'no-cache' } : null);
  }
};

async function ipaSource(url) {
  const r = await fetch(SOURCE, { cf: { cacheTtl: 60, cacheEverything: true } });
  const text = await r.text();
  if (url.pathname === '/latest' || url.pathname === '/latest.ipa') {
    try { return Response.redirect(JSON.parse(text).apps[0].versions[0].downloadURL, 302); } catch (e) {}
  }
  return new Response(text, { status: r.ok ? 200 : 502, headers: {
    'content-type': 'application/json; charset=utf-8', 'access-control-allow-origin': '*', 'cache-control': 'public, max-age=60' } });
}

/* ============================== FRIENDS API ============================== */
// What a friend can be allowed to see. Defaults for new accounts: training yes, body data no.
const CATS = ['gym', 'lifts', 'split', 'diet', 'nutr', 'body', 'photos'];
const DATACATS = ['gym', 'lifts', 'split', 'diet', 'nutr', 'body'];
const DEFAULTS = { gym: true, lifts: true, split: true, diet: true, nutr: false, body: false, photos: true };
const EMOJI = ['💪', '🔥', '👏', '🫡', '🤯', '👋'];
const ABC = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';
const HOUR = 3600e3, DAY = 864e5, LINK_TTL = DAY, QR_TTL = 40e3; // QR shown for 30 s, accepted for 40 s (scan delay)

/* formats of the encrypted things the phones upload (the server can check the shape, never the content) */
const RX = {
  enc: /^e1\.[0-9a-f]{8}\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{22,}$/,   // e1.<key id>.<iv>.<ciphertext>
  pub: /^[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}$/,                     // P-256 public key x.y
  fp: /^[A-Za-z0-9_-]{22}$/,                                         // key fingerprint
  kid: /^[0-9a-f]{8}$/,
  wrap: /^[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{22,120}$/,               // a wrapped key: <iv>.<ciphertext>
  pk: /^[0-9a-f]{8}\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{22,120}$/,   // <key id>.<iv>.<ciphertext>
  small: /^[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{22,1400}$/,             // encrypted caption / gift label
  pid: /^[0-9a-f]{32}$/,
  b64: /^[A-Za-z0-9+/]+={0,2}$/,
  item: /^[A-Za-z0-9:_-]{1,64}$/,
  uid: /^[a-z0-9]{8,32}$/
};

const SCHEMA_V = '2';
const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, puid TEXT NOT NULL UNIQUE, handle TEXT NOT NULL UNIQUE, name TEXT NOT NULL DEFAULT '',
     av INTEGER NOT NULL DEFAULT 0, invite TEXT NOT NULL UNIQUE, defaults TEXT NOT NULL DEFAULT '{}', created INTEGER NOT NULL, seen INTEGER NOT NULL DEFAULT 0, pub TEXT, fp TEXT)`,
  `CREATE TABLE IF NOT EXISTS avatars(uid TEXT PRIMARY KEY, type TEXT NOT NULL, data TEXT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS links(a TEXT NOT NULL, b TEXT NOT NULL, state TEXT NOT NULL, perms TEXT, created INTEGER NOT NULL, PRIMARY KEY(a,b))`,
  `CREATE INDEX IF NOT EXISTS links_b ON links(b)`,
  `CREATE TABLE IF NOT EXISTS snaps(uid TEXT NOT NULL, cat TEXT NOT NULL, data TEXT NOT NULL, updated INTEGER NOT NULL, PRIMARY KEY(uid,cat))`,
  `CREATE TABLE IF NOT EXISTS reacts(owner TEXT NOT NULL, item TEXT NOT NULL, uid TEXT NOT NULL, emoji TEXT NOT NULL, ts INTEGER NOT NULL, PRIMARY KEY(owner,item,uid))`,
  `CREATE INDEX IF NOT EXISTS reacts_owner_ts ON reacts(owner,ts)`,
  `CREATE TABLE IF NOT EXISTS tokens(h TEXT PRIMARY KEY, id TEXT NOT NULL, exp INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS invites(code TEXT PRIMARY KEY, uid TEXT NOT NULL, kind TEXT NOT NULL, exp INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS invites_uid ON invites(uid)`,
  `CREATE TABLE IF NOT EXISTS sends(id INTEGER PRIMARY KEY AUTOINCREMENT, from_uid TEXT NOT NULL, to_uid TEXT NOT NULL, code TEXT NOT NULL, ts INTEGER NOT NULL, done INTEGER NOT NULL DEFAULT 0,
     w TEXT, meta TEXT, rfp TEXT, ofp TEXT)`,
  `CREATE INDEX IF NOT EXISTS sends_to ON sends(to_uid, done)`,
  `CREATE TABLE IF NOT EXISTS posts(id TEXT PRIMARY KEY, uid TEXT NOT NULL, ts INTEGER NOT NULL, cap TEXT NOT NULL DEFAULT '', type TEXT NOT NULL, data TEXT NOT NULL,
     pk TEXT, sk TEXT, enc INTEGER NOT NULL DEFAULT 0)`,
  `CREATE INDEX IF NOT EXISTS posts_uid ON posts(uid, ts)`,
  `CREATE TABLE IF NOT EXISTS shares(code TEXT PRIMARY KEY, uid TEXT NOT NULL, kind TEXT NOT NULL, data TEXT NOT NULL, created INTEGER NOT NULL)`,
  // a category key of <owner>, wrapped so only <reader> can unwrap it
  `CREATE TABLE IF NOT EXISTS keyring(owner TEXT NOT NULL, reader TEXT NOT NULL, cat TEXT NOT NULL, kid TEXT NOT NULL, w TEXT NOT NULL, ofp TEXT NOT NULL, rfp TEXT NOT NULL, ts INTEGER NOT NULL,
     PRIMARY KEY(owner,reader,cat))`,
  `CREATE INDEX IF NOT EXISTS keyring_reader ON keyring(reader)`,
  `CREATE TABLE IF NOT EXISTS rl(k TEXT PRIMARY KEY, n INTEGER NOT NULL, reset INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT)`
];
// columns added after the first release (fresh databases get them from SCHEMA, the ALTERs then just fail)
const MIGRATE = [
  'ALTER TABLE users ADD COLUMN pub TEXT', 'ALTER TABLE users ADD COLUMN fp TEXT',
  'ALTER TABLE posts ADD COLUMN pk TEXT', 'ALTER TABLE posts ADD COLUMN sk TEXT', 'ALTER TABLE posts ADD COLUMN enc INTEGER NOT NULL DEFAULT 0',
  'ALTER TABLE sends ADD COLUMN w TEXT', 'ALTER TABLE sends ADD COLUMN meta TEXT', 'ALTER TABLE sends ADD COLUMN rfp TEXT', 'ALTER TABLE sends ADD COLUMN ofp TEXT'
];
let schemaReady = null;
function ensureSchema(db) {
  if (!schemaReady) schemaReady = (async () => {
    let v = null;
    try { v = await db.prepare("SELECT v FROM meta WHERE k='schema'").first(); } catch (e) {}
    if (v && v.v === SCHEMA_V) return;
    await db.batch(SCHEMA.map(s => db.prepare(s)));
    for (const q of MIGRATE) { try { await db.prepare(q).run(); } catch (e) { /* already there */ } }
    await db.prepare("INSERT OR REPLACE INTO meta(k,v) VALUES('schema',?)").bind(SCHEMA_V).run();
  })().catch(e => { schemaReady = null; throw e; });
  return schemaReady;
}

class HttpError extends Error { constructor(status, code, message) { super(message); this.status = status; this.code = code; } }
const J = (o, status) => new Response(JSON.stringify(o), { status: status || 200, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' } });
const err = (status, code, message) => J({ error: code, message }, status);
const parse = s => { try { return s ? JSON.parse(s) : null; } catch (e) { return null; } };
const clean = (s, n) => String(s == null ? '' : s).replace(/[\u0000-\u001f\u007f<>]/g, '').replace(/\s+/g, ' ').trim().slice(0, n);
const normCode = c => String(c || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 16);
function code(n) { const a = new Uint8Array(n * 2); crypto.getRandomValues(a); let s = ''; for (const x of a) { if (x < 248 && s.length < n) s += ABC[x % ABC.length]; } return s.length === n ? s : code(n); }
const pub = u => ({ id: u.id, handle: u.handle, name: u.name || u.handle, av: u.av || 0 });
const b64u = buf => { let s = ''; for (const x of new Uint8Array(buf)) s += String.fromCharCode(x); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
async function fpOf(p) { return b64u((await crypto.subtle.digest('SHA-256', new TextEncoder().encode(p))).slice(0, 16)); }
function cleanPerms(p) { const o = {}; if (p && typeof p === 'object') for (const c of CATS) if (typeof p[c] === 'boolean') o[c] = p[c]; return o; }
/* effective permissions = per-friend override, else the owner's defaults, else the app defaults */
function eff(defaults, overrides) {
  const d = typeof defaults === 'string' ? parse(defaults) || {} : defaults || {}, o = typeof overrides === 'string' ? parse(overrides) || {} : overrides || {}, r = {};
  for (const c of CATS) r[c] = typeof o[c] === 'boolean' ? o[c] : typeof d[c] === 'boolean' ? d[c] : DEFAULTS[c];
  return r;
}
/* only encrypted pieces are ever handed out (snapshots from before encryption are ignored) */
function encSum(s) { const o = {}; if (s && typeof s === 'object') for (const k of [...CATS, 'live']) if (typeof s[k] === 'string' && RX.enc.test(s[k])) o[k] = s[k]; return o; }
function encFeed(f) { return Array.isArray(f) ? f.filter(it => it && typeof it === 'object' && typeof it.e === 'string' && RX.enc.test(it.e)) : []; }
function filterSum(s, can) {
  const o = {};
  for (const c of CATS) if (can[c] && s[c] != null) o[c] = s[c];
  if (can.gym && s.live) o.live = s.live;
  return o;
}
function filterFeed(f, can) {
  const out = [];
  for (const it of f) {
    if (!can[it.c]) continue;
    const o = Object.assign({}, it);
    if (o.x && typeof o.x === 'object') { const x = {}; for (const c in o.x) if (can[c]) x[c] = o.x[c]; o.x = x; }
    out.push(o);
  }
  return out;
}
async function sha256(s) {
  const b = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
}
async function readBody(req) {
  const t = await req.text();
  if (t.length > 1800000) throw new HttpError(413, 'too_big', 'That is too much data at once.');
  if (!t) return {};
  const b = parse(t);
  if (!b || typeof b !== 'object') throw new HttpError(400, 'bad_json', 'Bad request.');
  return b;
}
/* SELECT … IN (…) in chunks (D1 allows 100 bound values per statement) */
async function selectIn(db, head, ids, tail, pre) {
  const out = [];
  for (let i = 0; i < ids.length; i += 80) {
    const part = ids.slice(i, i + 80);
    const r = await db.prepare(head + '(' + part.map(() => '?').join(',') + ')' + (tail || '')).bind(...(pre || []), ...part).all();
    out.push(...(r.results || []));
  }
  return out;
}
/* rate limits: a counter per key and time window (stops guessing codes, request spam and abuse) */
const ipOf = req => req.headers.get('cf-connecting-ip') || 'local';
async function limit(db, key, max, ms) {
  const now = Date.now();
  const r = await db.prepare('INSERT INTO rl(k,n,reset) VALUES(?,1,?) ON CONFLICT(k) DO UPDATE SET n=CASE WHEN reset<? THEN 1 ELSE n+1 END, reset=CASE WHEN reset<? THEN ? ELSE reset END RETURNING n')
    .bind(key, now + ms, now, now, now + ms).first();
  if (Math.random() < 0.01) await db.prepare('DELETE FROM rl WHERE reset<?').bind(now - HOUR).run();
  if (r && r.n > max) throw new HttpError(429, 'slow_down', 'Too many tries — wait a minute and try again.');
}

/* ---------- identity: the Puter sign-in token, verified with Puter, cached by hash (never stored) ---------- */
const MEM = new Map();
async function who(req, env, ctx) {
  const m = /^Bearer\s+(.+)$/i.exec(req.headers.get('authorization') || '');
  const tok = m && m[1].trim();
  if (!tok || tok.length > 4096) return null;
  const db = env.DB, h = await sha256(tok), now = Date.now();
  const hit = MEM.get(h);
  if (hit && hit.exp > now) return hit;
  const row = await db.prepare('SELECT id, exp FROM tokens WHERE h=?').bind(h).first();
  if (row && row.exp > now) { MEM.set(h, row); return row; }
  await limit(db, 'ip:' + ipOf(req) + ':auth', 40, 60e3);
  let r;
  try { r = await fetch((env.PUTER_API || PUTER_API) + '/whoami', { headers: { authorization: 'Bearer ' + tok, accept: 'application/json' } }); }
  catch (e) { throw new HttpError(502, 'auth_unreachable', 'Couldn’t check your sign-in — try again in a moment.'); }
  if (r.status === 401 || r.status === 403) return null;
  if (!r.ok) throw new HttpError(502, 'auth_unreachable', 'Couldn’t check your sign-in — try again in a moment.');
  const u = await r.json().catch(() => null);
  if (!u || !u.username) return null;
  const id = await ensureUser(db, String(u.uuid || 'u:' + u.username).slice(0, 80), String(u.username));
  const w = { id, exp: now + HOUR };
  if (MEM.size > 1000) MEM.clear();
  MEM.set(h, w);
  const st = [db.prepare('INSERT OR REPLACE INTO tokens(h,id,exp) VALUES(?,?,?)').bind(h, id, w.exp)];
  if (Math.random() < 0.05) st.push(db.prepare('DELETE FROM tokens WHERE exp<?').bind(now));
  const p = db.batch(st).catch(() => {});
  if (ctx && ctx.waitUntil) ctx.waitUntil(p); else await p;
  return w;
}
async function ensureUser(db, puid, uname) {
  const u = await db.prepare('SELECT id FROM users WHERE puid=?').bind(puid).first();
  if (u) return u.id;
  let base = String(uname || '').toLowerCase().replace(/[^a-z0-9_.]/g, '').slice(0, 20);
  if (base.length < 3) base = 'lifter';
  for (let i = 0; i < 8; i++) {
    const id = crypto.randomUUID().replace(/-/g, '').slice(0, 16);
    const handle = i === 0 ? base : base.slice(0, 15) + (1000 + Math.floor(Math.random() * 9000));
    try {
      await db.prepare('INSERT INTO users(id,puid,handle,name,invite,defaults,created) VALUES(?,?,?,?,?,?,?)')
        .bind(id, puid, handle, '', code(8), JSON.stringify(DEFAULTS), Date.now()).run();
      return id;
    } catch (e) {
      const again = await db.prepare('SELECT id FROM users WHERE puid=?').bind(puid).first();
      if (again) return again.id;
      if (!/unique/i.test(String(e && e.message))) throw e;
    }
  }
  throw new HttpError(500, 'server', 'Couldn’t create your profile.');
}

/* ---------- router ---------- */
const LINKQ = `SELECT l.b AS id, l.state, l.perms AS mine, l.created, u.handle, u.name, u.av, u.defaults, u.pub, u.fp, r.perms AS theirs
  FROM links l JOIN users u ON u.id=l.b LEFT JOIN links r ON r.a=l.b AND r.b=l.a`;
async function api(req, env, ctx, url) {
  if (!env.DB) return err(503, 'not_ready', 'Friends aren’t switched on yet.');
  const db = env.DB, M = req.method, p = url.pathname.replace(/\/+$/, '');
  let m;
  try {
    await ensureSchema(db);
    /* public: avatars, invite previews, shared splits (encrypted — the key is only in the link) */
    if (M === 'GET' && (m = /^\/api\/avatar\/([a-z0-9]{8,32})$/.exec(p))) return await avatarOut(db, m[1], url);
    if (M === 'GET' && (m = /^\/api\/invite\/([A-Za-z0-9-]{4,20})$/.exec(p))) {
      await limit(db, 'ip:' + ipOf(req) + ':pub', 60, 60e3);
      const u = await db.prepare("SELECT u.id,u.handle,u.name,u.av,i.exp FROM invites i JOIN users u ON u.id=i.uid WHERE i.code=? AND i.kind='link' AND i.exp>?").bind(normCode(m[1]), Date.now()).first();
      return u ? J({ user: pub(u), exp: u.exp }) : err(410, 'invite_expired', 'This invite has expired — links work for 24 hours. Ask for a new one.');
    }
    if (M === 'GET' && (m = /^\/api\/share\/([A-Za-z0-9-]{4,20})$/.exec(p))) {
      await limit(db, 'ip:' + ipOf(req) + ':pub', 60, 60e3);
      const s = await db.prepare('SELECT s.kind, s.data, s.created, u.id, u.handle, u.name, u.av FROM shares s JOIN users u ON u.id=s.uid WHERE s.code=?').bind(normCode(m[1])).first();
      if (!s) return err(404, 'share_invalid', 'That link doesn’t work any more.');
      const enc = RX.enc.test(s.data);
      return J({ kind: s.kind, data: enc ? s.data : parse(s.data), enc, created: s.created, from: pub(s) });
    }
    /* everything else: the current app, signed in with Puter */
    if ((req.headers.get('x-lockin') || '') !== API_VERSION) return err(426, 'update', 'Lock In was updated — close and reopen the app to keep using friends.');
    const me = await who(req, env, ctx);
    if (!me) return err(401, 'auth', 'Sign in again to use friends.');
    const id = me.id;
    const b = (M === 'POST' || M === 'PUT') ? await readBody(req) : null;
    switch (M + ' ' + p) {
      case 'GET /api/me': return J(await meOut(db, id));
      case 'PUT /api/me': return await putMe(db, id, b);
      case 'DELETE /api/me': return await deleteMe(db, id);
      case 'POST /api/invite/link': {
        await limit(db, 'u:' + id + ':link', 30, 10 * 60e3);
        const c = code(10), exp = Date.now() + LINK_TTL;
        await db.batch([db.prepare('DELETE FROM invites WHERE exp<?').bind(Date.now()),
                        db.prepare("INSERT INTO invites(code,uid,kind,exp) VALUES(?,?,'link',?)").bind(c, id, exp)]);
        return J({ code: c, exp });
      }
      case 'POST /api/invite/qr': {
        // one live QR per person: a new one replaces the last, so a photo of an old code is useless
        await limit(db, 'u:' + id + ':qr', 40, 10 * 60e3);
        const c = code(12), exp = Date.now() + QR_TTL;
        await db.batch([db.prepare("DELETE FROM invites WHERE uid=? AND kind='qr'").bind(id),
                        db.prepare("INSERT INTO invites(code,uid,kind,exp) VALUES(?,?,'qr',?)").bind(c, id, exp)]);
        return J({ code: c, exp, show: 30 });
      }
      case 'PUT /api/snap': return await putSnap(db, id, b);
      case 'GET /api/friends': return J(await friendsOut(db, id));
      case 'POST /api/friends/add': await limit(db, 'u:' + id + ':add', 30, 10 * 60e3); return await addFriend(db, id, b);
      case 'POST /api/friends/respond': return await respond(db, id, b);
      case 'POST /api/react': await limit(db, 'u:' + id + ':react', 150, 60e3); return await react(db, id, b);
      case 'POST /api/seen': await db.prepare('UPDATE users SET seen=? WHERE id=?').bind(Date.now(), id).run(); return J({ ok: true });
      case 'POST /api/share': return await share(db, id, b);
      case 'POST /api/posts': await limit(db, 'u:' + id + ':post', 40, HOUR); return await addPost(db, id, b);
      case 'GET /api/posts': return await listPosts(db, id, String(url.searchParams.get('u') || id));
      case 'GET /api/lookup': {
        await limit(db, 'u:' + id + ':lookup', 40, 10 * 60e3);
        const h = String(url.searchParams.get('h') || '').toLowerCase().replace(/^@/, '').trim();
        const u = /^[a-z0-9_.]{3,20}$/.test(h) && await db.prepare('SELECT id,handle,name,av FROM users WHERE handle=?').bind(h).first();
        if (!u) return err(404, 'no_user', 'Nobody has that username.');
        const l = await db.prepare('SELECT state FROM links WHERE a=? AND b=?').bind(id, u.id).first();
        return J({ user: pub(u), state: u.id === id ? 'self' : l ? l.state : 'none' });
      }
    }
    if ((m = /^\/api\/posts\/([a-f0-9]{16,32})(\/img)?$/.exec(p))) {
      if (m[2] && M === 'GET') return await postImg(db, id, m[1]);
      if (!m[2] && M === 'PUT') return await upgradePost(db, id, m[1], b);
      if (!m[2] && M === 'DELETE') { await db.prepare('DELETE FROM posts WHERE id=? AND uid=?').bind(m[1], id).run(); return J({ ok: true }); }
    }
    if ((m = /^\/api\/sends\/(\d{1,12})\/done$/.exec(p)) && M === 'POST') {
      await db.prepare('UPDATE sends SET done=1 WHERE id=? AND to_uid=?').bind(+m[1], id).run();
      return J({ ok: true });
    }
    if ((m = /^\/api\/friends\/([a-z0-9]{8,32})(\/perms)?$/.exec(p))) {
      if (!m[2] && M === 'GET') return await profile(db, id, m[1]);
      if (!m[2] && M === 'DELETE') {
        await db.prepare('DELETE FROM links WHERE (a=? AND b=?) OR (a=? AND b=?)').bind(id, m[1], m[1], id).run();
        return J({ ok: true });
      }
      if (m[2] && M === 'PUT') return await setPerms(db, id, m[1], b);
    }
    return err(404, 'not_found', 'Unknown request.');
  } catch (e) {
    if (e instanceof HttpError) return err(e.status, e.code, e.message);
    console.log('api error', (e && e.stack) || e);
    return err(500, 'server', 'Something went wrong — try again in a moment.');
  }
}

/* ---------- me ---------- */
async function meOut(db, id) {
  const u = await db.prepare('SELECT id,handle,name,av,defaults,created,seen,pub,fp FROM users WHERE id=?').bind(id).first();
  if (!u) throw new HttpError(404, 'no_profile', 'Profile not found.');
  return { id: u.id, handle: u.handle, name: u.name, av: u.av, defaults: eff(u.defaults), created: u.created, seen: u.seen, pub: u.pub || null, fp: u.fp || null };
}
async function putMe(db, id, b) {
  const sets = [], vals = [], extra = [];
  if ('name' in b) { sets.push('name=?'); vals.push(clean(b.name, 30)); }
  if ('handle' in b) {
    const h = String(b.handle || '').toLowerCase().replace(/^@/, '').trim();
    if (!/^[a-z0-9_.]{3,20}$/.test(h)) throw new HttpError(400, 'bad_handle', 'Usernames are 3–20 letters, numbers, _ or .');
    sets.push('handle=?'); vals.push(h);
  }
  if ('defaults' in b) { sets.push('defaults=?'); vals.push(JSON.stringify(eff(cleanPerms(b.defaults)))); }
  if ('pub' in b) {
    const k = String(b.pub || '');
    if (!RX.pub.test(k)) throw new HttpError(400, 'bad_key', 'That encryption key isn’t valid.');
    sets.push('pub=?', 'fp=?'); vals.push(k, await fpOf(k));
  }
  if ('avatar' in b) {
    if (!b.avatar) { extra.push(db.prepare('DELETE FROM avatars WHERE uid=?').bind(id)); sets.push('av=0'); }
    else {
      const m = /^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/=]+)$/.exec(String(b.avatar));
      if (!m) throw new HttpError(400, 'bad_avatar', 'That photo couldn’t be used.');
      if (m[2].length > 200000) throw new HttpError(413, 'too_big', 'That photo is too large.');
      extra.push(db.prepare('INSERT OR REPLACE INTO avatars(uid,type,data) VALUES(?,?,?)').bind(id, m[1], m[2]));
      sets.push('av=?'); vals.push(Math.floor(Date.now() / 1000));
    }
  }
  try {
    const st = [...extra];
    if (sets.length) st.push(db.prepare('UPDATE users SET ' + sets.join(',') + ' WHERE id=?').bind(...vals, id));
    if (st.length) await db.batch(st);
  } catch (e) {
    if (/unique/i.test(String(e && e.message))) throw new HttpError(409, 'handle_taken', 'That username is taken.');
    throw e;
  }
  return J(await meOut(db, id));
}
async function avatarOut(db, id, url) {
  const r = await db.prepare('SELECT a.type, a.data, u.av FROM avatars a JOIN users u ON u.id=a.uid WHERE a.uid=?').bind(id).first();
  if (!r) return new Response('', { status: 404, headers: { 'cache-control': 'public, max-age=120' } });
  const bin = Uint8Array.from(atob(r.data), c => c.charCodeAt(0));
  const v = url.searchParams.get('v');
  return new Response(bin, { headers: { 'content-type': r.type,
    'cache-control': v && +v === r.av ? 'public, max-age=31536000, immutable' : 'public, max-age=300' } });
}

/* ---------- what you share: encrypted summary pieces, activity feed, one blob per category, wrapped keys ---------- */
async function putSnap(db, id, b) {
  const now = Date.now(), st = [];
  const bad = () => new HttpError(400, 'bad_snap', 'Bad data.');
  const putRow = (c, s) => st.push(db.prepare('INSERT OR REPLACE INTO snaps(uid,cat,data,updated) VALUES(?,?,?,?)').bind(id, c, s, now));
  const delRow = c => st.push(db.prepare('DELETE FROM snaps WHERE uid=? AND cat=?').bind(id, c));
  if ('sum' in b) {
    const v = b.sum;
    if (v === null) delRow('sum');
    else {
      if (!v || typeof v !== 'object' || Array.isArray(v)) throw bad();
      const o = {};
      for (const k of [...CATS, 'live']) if (k in v) { if (typeof v[k] !== 'string' || !RX.enc.test(v[k]) || v[k].length > 30000) throw bad(); o[k] = v[k]; }
      putRow('sum', JSON.stringify(o));
    }
  }
  if ('feed' in b) {
    const v = b.feed;
    if (v === null) delRow('feed');
    else {
      if (!Array.isArray(v)) throw bad();
      const items = [];
      for (const it of v.slice(0, 60)) {
        if (!it || typeof it !== 'object' || !RX.item.test(String(it.id)) || !CATS.includes(it.c) || (it.t !== 'w' && it.t !== 'd') || typeof it.ts !== 'number' ||
            typeof it.e !== 'string' || !RX.enc.test(it.e) || it.e.length > 12000) continue;
        const o = { id: it.id, c: it.c, t: it.t, ts: it.ts, e: it.e };
        if (it.x && typeof it.x === 'object') { const x = {}; for (const c of CATS) if (typeof it.x[c] === 'string' && RX.enc.test(it.x[c]) && it.x[c].length < 6000) x[c] = it.x[c]; if (Object.keys(x).length) o.x = x; }
        items.push(o);
      }
      const s = JSON.stringify(items);
      if (s.length > 400000) throw new HttpError(413, 'too_big', 'That is too much data at once.');
      putRow('feed', s);
    }
  }
  for (const c of DATACATS) {
    if (!(c in b)) continue;
    const v = b[c];
    if (v === null) { delRow(c); continue; }
    if (typeof v !== 'string' || !RX.enc.test(v)) throw bad();
    if (v.length > 200000) throw new HttpError(413, 'too_big', 'That is too much data at once.');
    putRow(c, v);
  }
  /* keys: the owner wraps each category key for every friend allowed to see that category */
  if (b.keys && typeof b.keys === 'object') {
    const del = Array.isArray(b.keys.del) ? [...new Set(b.keys.del.filter(c => CATS.includes(c)))] : [];
    const put = Array.isArray(b.keys.put) ? b.keys.put.slice(0, 600) : [];
    for (const c of del) st.push(db.prepare('DELETE FROM keyring WHERE owner=? AND cat=?').bind(id, c));
    if (put.length) {
      const u = await db.prepare('SELECT fp FROM users WHERE id=?').bind(id).first();
      if (!u || !u.fp) throw new HttpError(409, 'no_key', 'Set up encryption first.');
      const fr = new Set(((await db.prepare("SELECT b FROM links WHERE a=? AND state='friend'").bind(id).all()).results || []).map(r => r.b));
      const rows = put.filter(k => k && fr.has(k.r) && CATS.includes(k.c) && RX.kid.test(String(k.k)) && RX.wrap.test(String(k.w)) && RX.fp.test(String(k.rf)));
      for (let i = 0; i < rows.length; i += 12) {
        const part = rows.slice(i, i + 12);
        st.push(db.prepare('INSERT OR REPLACE INTO keyring(owner,reader,cat,kid,w,ofp,rfp,ts) VALUES ' + part.map(() => '(?,?,?,?,?,?,?,?)').join(','))
          .bind(...part.flatMap(k => [id, k.r, k.c, k.k, k.w, u.fp, k.rf, now])));
      }
    }
  }
  /* photo-post keys re-wrapped after the photos key changed */
  if (Array.isArray(b.posts)) {
    const rows = b.posts.slice(0, 120).filter(x => x && RX.pid.test(String(x.id)) && RX.pk.test(String(x.pk)));
    for (let i = 0; i < rows.length; i += 30) {
      const part = rows.slice(i, i + 30);
      st.push(db.prepare('UPDATE posts SET pk=CASE id ' + part.map(() => 'WHEN ? THEN ?').join(' ') + ' ELSE pk END WHERE uid=? AND id IN (' + part.map(() => '?').join(',') + ')')
        .bind(...part.flatMap(x => [x.id, x.pk]), id, ...part.map(x => x.id)));
    }
  }
  if (st.length) await db.batch(st);
  return J({ ok: true, ts: now });
}

/* ---------- friends list, requests, activity feed, reactions inbox, keys ---------- */
async function friendsOut(db, me) {
  const now = Date.now();
  const rows = (await db.prepare(LINKQ + ' WHERE l.a=? ORDER BY l.created DESC LIMIT 300').bind(me).all()).results || [];
  const meRow = await meOut(db, me);
  const friends = rows.filter(r => r.state === 'friend'), fids = friends.map(f => f.id), fset = new Set(fids);
  const owners = [...fids, me];
  const canSee = {};
  for (const r of friends) canSee[r.id] = eff(r.defaults, r.theirs);
  const snaps = await selectIn(db, "SELECT uid, cat, data, updated FROM snaps WHERE cat IN ('sum','feed') AND uid IN ", owners);
  const reacts = await selectIn(db, 'SELECT owner, item, uid, emoji FROM reacts WHERE ts>? AND owner IN ', owners, '', [now - 21 * DAY]);
  const inboxRows = (await db.prepare(`SELECT r.item, r.emoji, r.ts, u.id, u.handle, u.name, u.av FROM reacts r JOIN users u ON u.id=r.uid
      WHERE r.owner=? AND r.uid<>? ORDER BY r.ts DESC LIMIT 40`).bind(me, me).all()).results || [];
  const keyRows = fids.length ? await selectIn(db, 'SELECT owner, cat, kid, w, ofp, rfp FROM keyring WHERE reader=? AND owner IN ', fids, '', [me]) : [];
  const ring = (await db.prepare('SELECT reader AS r, cat AS c, kid AS k, rfp AS rf, ofp AS "of" FROM keyring WHERE owner=?').bind(me).all()).results || [];
  const postOwners = [me, ...fids.filter(f => canSee[f].photos)];
  const postRows = await selectIn(db, 'SELECT id, uid, ts, cap, pk, sk, enc FROM posts WHERE ts>? AND uid IN ', postOwners, ' ORDER BY ts DESC LIMIT 60', [now - 21 * DAY]);
  const gifts = (await db.prepare(`SELECT s.id, s.code, s.ts, s.w, s.meta, s.rfp, s.ofp, CASE WHEN s.w IS NULL THEN sh.data ELSE NULL END AS data,
      u.id AS uid, u.handle, u.name, u.av FROM sends s JOIN shares sh ON sh.code=s.code JOIN users u ON u.id=s.from_uid
      WHERE s.to_uid=? AND s.done=0 AND s.ts>? ORDER BY s.ts DESC LIMIT 10`).bind(me, now - 30 * DAY).all()).results || [];
  const S = {};
  for (const s of snaps) (S[s.uid] = S[s.uid] || {})[s.cat] = { d: parse(s.data), t: s.updated };
  const K = {};
  for (const k of keyRows) if (canSee[k.owner] && canSee[k.owner][k.cat]) (K[k.owner] = K[k.owner] || {})[k.cat] = { k: k.kid, w: k.w, of: k.ofp, rf: k.rfp };
  const out = { now, me: meRow, ring, friends: [], incoming: [], outgoing: [], feed: [], inbox: [],
    gifts: gifts.map(g => {
      const o = { id: g.id, code: g.code, ts: g.ts, from: pub({ id: g.uid, handle: g.handle, name: g.name, av: g.av }) };
      if (g.w) Object.assign(o, { w: g.w, meta: g.meta || '', rf: g.rfp || '', of: g.ofp || '' });
      else { const d = parse(g.data) || {}; o.name = String(d.name || 'Split').slice(0, 40); o.days = Array.isArray(d.days) ? d.days.length : 0; }
      return o;
    }) };
  for (const x of postRows) {
    if (x.uid !== me && !x.enc) continue;   // photos from before encryption stay hidden until their owner's app re-encrypts them
    const it = { id: 'p' + x.id, c: 'photos', t: 'p', ts: x.ts, cap: x.cap, pk: x.pk || '', enc: x.enc ? 1 : 0, by: x.uid };
    if (x.uid === me) it.sk = x.sk || '';
    out.feed.push(it);
  }
  for (const r of rows) {
    const u = pub(r);
    if (r.state === 'in') out.incoming.push(Object.assign(u, { ts: r.created }));
    else if (r.state === 'out') out.outgoing.push(Object.assign(u, { ts: r.created }));
    else {
      const can = canSee[r.id], s = S[r.id] || {};
      out.friends.push(Object.assign(u, { since: r.created, can, perms: cleanPerms(parse(r.mine)), sum: filterSum(encSum(s.sum && s.sum.d), can),
        upd: s.sum ? s.sum.t : 0, pub: r.pub || null, fp: r.fp || null, keys: K[r.id] || {} }));
      for (const it of filterFeed(encFeed(s.feed && s.feed.d), can)) out.feed.push(Object.assign(it, { by: r.id }));
    }
  }
  // your own items only as ids: the app shows them from your device and just needs the reactions
  for (const it of encFeed(S[me] && S[me].feed && S[me].feed.d)) out.feed.push({ id: it.id, c: it.c, t: it.t, ts: it.ts, by: me });
  out.feed.sort((a, b) => b.ts - a.ts);
  out.feed = out.feed.slice(0, 90);
  const R = {};
  for (const x of reacts) (R[x.owner + '|' + x.item] = R[x.owner + '|' + x.item] || []).push(x);
  for (const it of out.feed) {
    const list = R[it.by + '|' + it.id] || [];
    it.re = {}; it.who = [];
    for (const x of list) {
      it.re[x.emoji] = (it.re[x.emoji] || 0) + 1;
      if (x.uid === me) it.mine = x.emoji;
      if (x.uid === me || fset.has(x.uid)) it.who.push([x.uid, x.emoji]);
    }
  }
  out.inbox = inboxRows.map(x => ({ item: x.item, emoji: x.emoji, ts: x.ts, from: pub(x) }));
  return out;
}

async function addFriend(db, me, b) {
  let t, instant = false;
  const viaInvite = kind => db.prepare("SELECT u.id,u.handle,u.name,u.av FROM invites i JOIN users u ON u.id=i.uid WHERE i.code=? AND i.kind=? AND i.exp>?")
    .bind(normCode(kind === 'qr' ? b.qr : b.link), kind, Date.now()).first();
  if (b.qr) {
    t = await viaInvite('qr');
    if (!t) throw new HttpError(410, 'qr_expired', 'That code expired — codes change every 30 seconds. Scan it again.');
    instant = true;
  } else if (b.link) {
    t = await viaInvite('link');
    if (!t) throw new HttpError(410, 'invite_expired', 'This invite has expired — links work for 24 hours. Ask for a new one.');
  } else if (b.handle) {
    const h = String(b.handle).toLowerCase().replace(/^@/, '').trim();
    t = /^[a-z0-9_.]{3,20}$/.test(h) && await db.prepare('SELECT id,handle,name,av FROM users WHERE handle=?').bind(h).first();
    if (!t) throw new HttpError(404, 'no_user', 'Nobody has that username.');
  } else throw new HttpError(400, 'bad', 'Scan a QR code, open an invite link or type a username.');
  if (t.id === me) throw new HttpError(400, 'self', 'That’s your own code 🙂');
  const cur = await db.prepare('SELECT state FROM links WHERE a=? AND b=?').bind(me, t.id).first();
  const now = Date.now();
  let state;
  if (cur && cur.state === 'friend') state = 'friend';
  else if (instant || (cur && cur.state === 'in')) {
    // scanning someone's live QR in person is their consent; an incoming request is accepted by adding back
    const up = 'INSERT INTO links(a,b,state,perms,created) VALUES(?,?,\'friend\',NULL,?) ON CONFLICT(a,b) DO UPDATE SET state=\'friend\', created=excluded.created';
    await db.batch([db.prepare(up).bind(me, t.id, now), db.prepare(up).bind(t.id, me, now)]);
    state = 'friend';
  } else if (cur && cur.state === 'out') state = 'out';
  else {
    const n = await db.prepare("SELECT COUNT(*) AS n FROM links WHERE a=?").bind(me).first();
    if (n && n.n >= 300) throw new HttpError(429, 'too_many', 'You’ve reached the friend limit.');
    await db.batch([
      db.prepare("INSERT OR REPLACE INTO links(a,b,state,perms,created) VALUES(?,?,'out',NULL,?)").bind(me, t.id, now),
      db.prepare("INSERT OR REPLACE INTO links(a,b,state,perms,created) VALUES(?,?,'in',NULL,?)").bind(t.id, me, now)]);
    state = 'out';
  }
  return J({ state, user: pub(t) });
}
/* delete the friends profile: frees the username, removes friends, requests, shared data, keys and reactions */
async function deleteMe(db, id) {
  await db.batch([
    db.prepare('DELETE FROM links WHERE a=? OR b=?').bind(id, id),
    db.prepare('DELETE FROM snaps WHERE uid=?').bind(id),
    db.prepare('DELETE FROM reacts WHERE owner=? OR uid=?').bind(id, id),
    db.prepare('DELETE FROM avatars WHERE uid=?').bind(id),
    db.prepare('DELETE FROM shares WHERE uid=?').bind(id),
    db.prepare('DELETE FROM invites WHERE uid=?').bind(id),
    db.prepare('DELETE FROM posts WHERE uid=?').bind(id),
    db.prepare('DELETE FROM sends WHERE from_uid=? OR to_uid=?').bind(id, id),
    db.prepare('DELETE FROM keyring WHERE owner=? OR reader=?').bind(id, id),
    db.prepare('DELETE FROM tokens WHERE id=?').bind(id),
    db.prepare('DELETE FROM users WHERE id=?').bind(id)]);
  for (const [k, v] of MEM) if (v.id === id) MEM.delete(k);
  return J({ ok: true });
}
async function respond(db, me, b) {
  const other = String((b && b.id) || '');
  const cur = await db.prepare('SELECT state FROM links WHERE a=? AND b=?').bind(me, other).first();
  if (!cur || cur.state !== 'in') throw new HttpError(404, 'no_request', 'That request is gone.');
  if (b.accept) {
    const now = Date.now();
    await db.batch([db.prepare("UPDATE links SET state='friend', created=? WHERE a=? AND b=?").bind(now, me, other),
                    db.prepare("UPDATE links SET state='friend', created=? WHERE a=? AND b=?").bind(now, other, me)]);
  } else await db.prepare('DELETE FROM links WHERE (a=? AND b=?) OR (a=? AND b=?)').bind(me, other, other, me).run();
  return J({ ok: true, state: b.accept ? 'friend' : 'none' });
}
async function setPerms(db, me, other, b) {
  const cur = await db.prepare('SELECT state FROM links WHERE a=? AND b=?').bind(me, other).first();
  if (!cur) throw new HttpError(404, 'not_friends', 'You’re not connected with this person.');
  const o = b && b.perms ? cleanPerms(b.perms) : {};
  await db.prepare('UPDATE links SET perms=? WHERE a=? AND b=?').bind(Object.keys(o).length ? JSON.stringify(o) : null, me, other).run();
  return J({ ok: true, perms: o });
}
async function profile(db, me, fid) {
  const r = await db.prepare(LINKQ + ' WHERE l.a=? AND l.b=?').bind(me, fid).first();
  if (!r || r.state !== 'friend') throw new HttpError(404, 'not_friends', 'You’re not friends with this person.');
  const can = eff(r.defaults, r.theirs), cats = ['sum', ...DATACATS.filter(c => can[c])];
  const rows = (await db.prepare('SELECT cat, data, updated FROM snaps WHERE uid=? AND cat IN (' + cats.map(() => '?').join(',') + ')').bind(fid, ...cats).all()).results || [];
  const keys = (await db.prepare('SELECT cat, kid, w, ofp, rfp FROM keyring WHERE owner=? AND reader=?').bind(fid, me).all()).results || [];
  const K = {};
  for (const k of keys) if (can[k.cat]) K[k.cat] = { k: k.kid, w: k.w, of: k.ofp, rf: k.rfp };
  const data = {};
  let sum = {}, upd = 0;
  for (const x of rows) {
    if (x.cat === 'sum') { sum = filterSum(encSum(parse(x.data)), can); upd = x.updated; }
    else if (RX.enc.test(x.data)) data[x.cat] = x.data;
  }
  return J({ user: pub(r), since: r.created, can, perms: cleanPerms(parse(r.mine)), sum, data, upd, pub: r.pub || null, fp: r.fp || null, keys: K });
}
async function react(db, me, b) {
  const owner = String((b && b.owner) || ''), item = String((b && b.item) || '').slice(0, 64), emoji = b && b.emoji ? String(b.emoji) : '';
  if (emoji && !EMOJI.includes(emoji)) throw new HttpError(400, 'bad', 'Unknown reaction.');
  if (!owner || owner === me || !item) throw new HttpError(400, 'bad', 'Bad reaction.');
  const r = await db.prepare(LINKQ + ' WHERE l.a=? AND l.b=?').bind(me, owner).first();
  if (!r || r.state !== 'friend') throw new HttpError(403, 'not_friends', 'Only friends can react.');
  if (item === 'nudge') {
    const key = 'nudge:' + new Date().toISOString().slice(0, 10);
    const res = await db.prepare("INSERT OR IGNORE INTO reacts(owner,item,uid,emoji,ts) VALUES(?,?,?,'👋',?)").bind(owner, key, me, Date.now()).run();
    return J({ ok: true, item: key, already: !(res.meta && res.meta.changes) });
  }
  const can = eff(r.defaults, r.theirs);
  if (/^p[a-f0-9]{16,32}$/.test(item)) {
    const ps = await db.prepare('SELECT 1 AS ok FROM posts WHERE id=? AND uid=? AND enc=1').bind(item.slice(1), owner).first();
    if (!ps || !can.photos) throw new HttpError(404, 'gone', 'That post isn’t available any more.');
  } else {
    const f = await db.prepare("SELECT data FROM snaps WHERE uid=? AND cat='feed'").bind(owner).first();
    const it = f && encFeed(parse(f.data)).find(x => x.id === item);
    if (!it || !can[it.c]) throw new HttpError(404, 'gone', 'That post isn’t available any more.');
  }
  const st = [emoji ? db.prepare('INSERT OR REPLACE INTO reacts(owner,item,uid,emoji,ts) VALUES(?,?,?,?,?)').bind(owner, item, me, emoji, Date.now())
                    : db.prepare('DELETE FROM reacts WHERE owner=? AND item=? AND uid=?').bind(owner, item, me)];
  if (Math.random() < 0.03) st.push(db.prepare('DELETE FROM reacts WHERE ts<?').bind(Date.now() - 90 * DAY));
  await db.batch(st);
  return J({ ok: true, item });
}
/* shared splits: encrypted on the phone with a key that only travels inside the link (or wrapped for one friend) */
async function share(db, me, b) {
  if (!b || b.kind !== 'split' || typeof b.data !== 'string' || !RX.enc.test(b.data)) throw new HttpError(400, 'bad', 'Nothing to share.');
  if (b.data.length > 160000) throw new HttpError(413, 'too_big', 'That split is too large to share.');
  const c = normCode(b.code);
  if (c.length !== 8 || [...c].some(ch => !ABC.includes(ch))) throw new HttpError(400, 'bad', 'Bad share code.');
  const n = await db.prepare('SELECT COUNT(*) AS n FROM shares WHERE uid=? AND created>?').bind(me, Date.now() - DAY).first();
  if (n && n.n >= 60) throw new HttpError(429, 'slow_down', 'That’s a lot of sharing for one day — try again tomorrow.');
  const now = Date.now(), meta = typeof b.meta === 'string' && RX.small.test(b.meta) ? b.meta : null;
  const st = [db.prepare('INSERT INTO shares(code,uid,kind,data,created) VALUES(?,?,?,?,?)').bind(c, me, b.kind, b.data, now)];
  const to = Array.isArray(b.to) ? b.to.slice(0, 50).filter(x => x && RX.uid.test(String(x.id)) && RX.wrap.test(String(x.w)) && RX.fp.test(String(x.rf))) : [];
  let sent = 0;
  if (to.length) {
    const u = await db.prepare('SELECT fp FROM users WHERE id=?').bind(me).first();
    const ok = new Set((await selectIn(db, "SELECT b FROM links WHERE a=? AND state='friend' AND b IN ", to.map(x => x.id), '', [me])).map(x => x.b));
    for (const x of to) if (ok.has(x.id)) { st.push(db.prepare('INSERT INTO sends(from_uid,to_uid,code,ts,w,meta,rfp,ofp) VALUES(?,?,?,?,?,?,?,?)').bind(me, x.id, c, now, x.w, meta, x.rf, (u && u.fp) || '')); sent++; }
  }
  try { await db.batch(st); }
  catch (e) { if (/unique|constraint/i.test(String(e && e.message))) throw new HttpError(409, 'code_taken', 'Try again.'); throw e; }
  return J({ code: c, sent });
}

/* ---------- progress-photo posts: encrypted image + caption, the post key wrapped with the owner's photos key ---------- */
async function canSeePhotos(db, me, owner) {
  if (owner === me) return true;
  const r = await db.prepare(LINKQ + ' WHERE l.a=? AND l.b=?').bind(me, owner).first();
  return !!(r && r.state === 'friend' && eff(r.defaults, r.theirs).photos);
}
function postFields(b) {
  const img = String((b && b.img) || ''), cap = String((b && b.cap) || ''), pk = String((b && b.pk) || ''), sk = String((b && b.sk) || '');
  if (!RX.b64.test(img) || img.length < 100 || (cap && !RX.small.test(cap)) || !RX.pk.test(pk) || !RX.wrap.test(sk)) throw new HttpError(400, 'bad_image', 'That photo couldn’t be used.');
  if (img.length > 1500000) throw new HttpError(413, 'too_big', 'That photo is too large.');
  return { img, cap, pk, sk };
}
async function addPost(db, me, b) {
  const id = String((b && b.id) || '');
  if (!RX.pid.test(id)) throw new HttpError(400, 'bad_image', 'That photo couldn’t be used.');
  const f = postFields(b), ts = Date.now();
  const n = await db.prepare('SELECT COUNT(*) AS n FROM posts WHERE uid=?').bind(me).first();
  const st = [db.prepare("INSERT INTO posts(id,uid,ts,cap,type,data,pk,sk,enc) VALUES(?,?,?,?,'e',?,?,?,1)").bind(id, me, ts, f.cap, f.img, f.pk, f.sk)];
  if (n && n.n >= 60) st.unshift(db.prepare('DELETE FROM posts WHERE id IN (SELECT id FROM posts WHERE uid=? ORDER BY ts ASC LIMIT ?)').bind(me, n.n - 59));
  try { await db.batch(st); }
  catch (e) { if (/unique|constraint/i.test(String(e && e.message))) throw new HttpError(409, 'exists', 'Try again.'); throw e; }
  return J({ id, ts });
}
/* a photo posted before encryption, re-uploaded encrypted by its owner's app */
async function upgradePost(db, me, pid, b) {
  const f = postFields(b);
  const r = await db.prepare("UPDATE posts SET data=?, cap=?, pk=?, sk=?, type='e', enc=1 WHERE id=? AND uid=?").bind(f.img, f.cap, f.pk, f.sk, pid, me).run();
  if (!(r.meta && r.meta.changes)) throw new HttpError(404, 'gone', 'That post isn’t there any more.');
  return J({ ok: true });
}
async function listPosts(db, me, owner) {
  if (!RX.uid.test(owner) || !(await canSeePhotos(db, me, owner))) throw new HttpError(403, 'private', 'Progress photos are private.');
  const mine = owner === me;
  const r = (await db.prepare('SELECT id, ts, cap, pk, ' + (mine ? 'sk, ' : '') + 'enc FROM posts WHERE uid=?' + (mine ? '' : ' AND enc=1') + ' ORDER BY ts DESC LIMIT 60').bind(owner).all()).results || [];
  return J({ posts: r, mine });
}
async function postImg(db, me, id) {
  const r = await db.prepare('SELECT uid, type, data, enc FROM posts WHERE id=?').bind(id).first();
  if (!r || (!r.enc && r.uid !== me) || !(await canSeePhotos(db, me, r.uid))) return new Response('', { status: 404 });
  return new Response(Uint8Array.from(atob(r.data), c => c.charCodeAt(0)), { headers: {
    'content-type': r.enc ? 'application/octet-stream' : r.type, 'cache-control': r.enc ? 'private, max-age=604800' : 'private, no-store' } });
}

/* ============================== INVITE / SHARE LINKS ============================== */
// /i/<code> and /s/<code>: a tiny page with link-preview tags (Messages, WhatsApp, AirDrop show the name and photo),
// then straight into the app. On an iPhone outside the app it offers the app or the browser.
// Shared splits are encrypted: the key is the part after # in the link, which browsers never send to a server,
// so this page decrypts the preview on the phone.
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
async function landing(env, url, kind, raw, req) {
  const c = normCode(raw), isInvite = kind === 'i', isQR = kind === 'q', isSplit = kind === 's';
  let name = '', avatar = '', encShare = false, title = isInvite ? 'This invite has expired' : isQR ? 'Scan this code in Lock In' : 'A training split for you',
    desc = 'Train together on Lock In — workouts, streaks, PRs and splits.', sub = isInvite ? 'Invite links work for 24 hours — ask for a new one.' : isQR ? 'Friends → Add friends → Scan. Codes change every 30 seconds.' : '';
  if (env.DB) {
    try {
      await ensureSchema(env.DB);
      await limit(env.DB, 'ip:' + ipOf(req) + ':pub', 60, 60e3);
      if (isInvite) {
        const u = await env.DB.prepare("SELECT u.id,u.handle,u.name,u.av FROM invites i JOIN users u ON u.id=i.uid WHERE i.code=? AND i.kind='link' AND i.exp>?").bind(c, Date.now()).first();
        if (u) { name = u.name || u.handle; title = 'Add ' + name + ' on Lock In'; sub = '@' + u.handle + ' · they accept your request in the app'; if (u.av) avatar = '/api/avatar/' + u.id + '?v=' + u.av; }
      } else if (isSplit) {
        const s = await env.DB.prepare('SELECT s.data, u.id, u.handle, u.name, u.av FROM shares s JOIN users u ON u.id=s.uid WHERE s.code=?').bind(c).first();
        if (s) {
          name = s.name || s.handle;
          if (RX.enc.test(s.data)) {
            encShare = true; title = name + ' shared a training split';
            desc = 'Open it in Lock In to see it and add it to your splits. It’s end-to-end encrypted — only people with the link can read it.';
            sub = '🔒 End-to-end encrypted';
          } else {
            const d = parse(s.data) || {}, days = Array.isArray(d.days) ? d.days.length : 0;
            title = name + ' shared a split: ' + (d.name || 'Training split');
            desc = days + ' training days' + (Array.isArray(d.days) ? ' — ' + d.days.map(x => x && x.name).filter(Boolean).slice(0, 6).join(', ') : '') + '. Open it in Lock In to use it.';
            sub = d.name || '';
          }
          if (s.av) avatar = '/api/avatar/' + s.id + '?v=' + s.av;
        }
      }
    } catch (e) {}
  }
  const target = '/#' + (isInvite ? 'add=' : isQR ? 'qr=' : 'split=') + c, scheme = 'lockin://' + (isInvite ? 'add/' : 'split/') + c;
  const img = url.origin + (avatar || '/icon-512.png'), initial = esc((name || 'L').trim().charAt(0).toUpperCase());
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>${esc(title)}</title><meta name="description" content="${esc(desc)}">
<meta property="og:type" content="website"><meta property="og:site_name" content="Lock In">
<meta property="og:title" content="${esc(title)}"><meta property="og:description" content="${esc(desc)}">
<meta property="og:image" content="${esc(img)}"><meta property="og:url" content="${esc(url.origin + url.pathname)}">
<meta name="twitter:card" content="summary"><meta name="theme-color" content="#0e1013"><meta name="referrer" content="no-referrer">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<script>(function(){var k=${isSplit ? '/^#([A-Za-z0-9]{11})$/.exec(location.hash)' : 'null'},suf=k?'-'+k[1]:'';
window.__t=${JSON.stringify(target)}+suf;window.__s=${JSON.stringify(scheme)}+suf;
var inApp=!!(window.webkit&&window.webkit.messageHandlers&&window.webkit.messageHandlers.lockin);
if(inApp||!/iPhone|iPad|iPod/.test(navigator.userAgent))location.replace(window.__t);})();</script>
<style>
:root{color-scheme:dark}*{box-sizing:border-box;margin:0}
body{min-height:100vh;display:grid;place-items:center;padding:24px;background:radial-gradient(80% 60% at 50% 0%,rgba(91,147,255,.22),transparent 70%),#0e1013;color:#e9ecf1;font:16px/1.4 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;text-align:center}
main{width:100%;max-width:360px}
.av{width:104px;height:104px;margin:0 auto 18px;border-radius:50%;display:grid;place-items:center;font-size:42px;font-weight:800;color:#fff;overflow:hidden;
 background:linear-gradient(135deg,#6ea6ff,#7b6cff);box-shadow:0 0 0 3px #0e1013,0 0 0 6px rgba(110,166,255,.55),0 20px 50px rgba(91,147,255,.35)}
.av img{width:100%;height:100%;object-fit:cover}
h1{font-size:24px;letter-spacing:-.02em;margin-bottom:6px}p{color:#a6aeba;font-size:14.5px}
.days{margin-top:14px;display:flex;flex-wrap:wrap;gap:6px;justify-content:center}.days span{padding:5px 10px;border-radius:99px;background:rgba(255,255,255,.07);font-size:12.5px;color:#d9e4f8}
a{display:block;padding:15px;border-radius:16px;font-weight:700;text-decoration:none;margin-top:10px}
.p{background:linear-gradient(135deg,#6ea6ff,#5b7dff 55%,#7b6cff);color:#fff;box-shadow:0 10px 30px rgba(91,147,255,.35)}
.g{background:rgba(255,255,255,.07);color:#e9ecf1;border:1px solid rgba(255,255,255,.12)}
small{display:block;margin-top:18px;color:#7d8592;font-size:12.5px}
</style></head><body><main>
<div class="av">${avatar ? `<img src="${esc(avatar)}" alt="">` : initial}</div>
<h1 id="h1">${esc(title)}</h1><p id="sub">${esc(sub || desc)}</p><div class="days" id="days"></div>
<div style="height:22px"></div>
${isQR ? '' : `<a class="p" id="oa" href="${esc(scheme)}">Open in the Lock In app</a>`}
<a class="${isQR ? 'p' : 'g'}" id="ob" href="${esc(isQR ? '/' : target)}">${isQR ? 'Open Lock In' : 'Continue in the browser'}</a>
<small>${isInvite ? 'Invite links work for 24 hours. Your request needs their OK.' : isQR ? 'QR codes only work from the scanner inside Lock In.' : 'Opens the split in Lock In so you can add it to your splits.'}</small>
</main>
<script>(function(){var a=document.getElementById('oa'),b=document.getElementById('ob');${isQR ? '' : 'if(a)a.href=window.__s;if(b)b.href=window.__t;'}
${encShare ? `var m=/^#([A-Za-z0-9]{11})$/.exec(location.hash),C=${JSON.stringify(c)},E=new TextEncoder();
if(!m||!window.crypto||!crypto.subtle){if(!m)document.getElementById('sub').textContent='This link is missing its key — ask for the full link again.';return;}
function u(s){s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';var r=atob(s),x=new Uint8Array(r.length);for(var i=0;i<r.length;i++)x[i]=r.charCodeAt(i);return x;}
fetch('/api/share/'+C).then(function(r){return r.json();}).then(function(j){var p=String(j.data||'').split('.');
 return crypto.subtle.importKey('raw',E.encode(m[1]),'HKDF',false,['deriveKey']).then(function(hk){return crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt:E.encode('lockin-share-v1|'+C),info:E.encode('split')},hk,{name:'AES-GCM',length:256},false,['decrypt']);})
 .then(function(k){return crypto.subtle.decrypt({name:'AES-GCM',iv:u(p[2]),additionalData:E.encode('share|'+C)},k,u(p[3]));})
 .then(function(buf){var d=JSON.parse(new TextDecoder().decode(buf)),days=Array.isArray(d.days)?d.days:[];
   document.getElementById('h1').textContent=String(d.name||'Training split').slice(0,60);
   document.getElementById('sub').textContent=days.length+' training days · 🔒 end-to-end encrypted';
   var box=document.getElementById('days');days.slice(0,8).forEach(function(x){var s=document.createElement('span');s.textContent=String((x&&x.name)||'Day').slice(0,30);box.appendChild(s);});});
}).catch(function(){document.getElementById('sub').textContent='Couldn’t open this split — the link may be incomplete.';});` : ''}
})();</script></body></html>`;
  return new Response(html, { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-cache' } });
}
