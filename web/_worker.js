// Cloudflare Pages (advanced mode): one project serves both hostnames.
//   web.lockin-app.online  -> the Lock In web app (static files in this folder)
//                             + /api/*  friends: profiles, privacy, activity, reactions (Cloudflare D1, binding "DB")
//                             + /i/<code> and /s/<code>  invite / shared-split links with rich previews
//   ipa.lockin-app.online  -> the SideStore/AltStore source (always the latest from GitHub)
const SOURCE = 'https://raw.githubusercontent.com/Trohorm/summer-lock-in/main/source.json';
const PUTER_API = 'https://api.puter.com';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.hostname.startsWith('ipa.')) return ipaSource(url);
    if (url.pathname.startsWith('/api/')) return api(request, env, ctx, url);
    const lm = /^\/(i|s)\/([A-Za-z0-9-]{4,20})\/?$/.exec(url.pathname);
    if (lm && request.method === 'GET') return landing(env, url, lm[1], lm[2]);
    const res = await env.ASSETS.fetch(request);
    if ((res.headers.get('content-type') || '').includes('text/html') || url.pathname.endsWith('sw.js')) {
      const h = new Headers(res.headers); h.set('cache-control', 'no-cache');
      return new Response(res.body, { status: res.status, headers: h });
    }
    return res;
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
const CATS = ['gym', 'lifts', 'split', 'diet', 'nutr', 'body'];
const DEFAULTS = { gym: true, lifts: true, split: true, diet: true, nutr: false, body: false };
const EMOJI = ['💪', '🔥', '👏', '🫡', '🤯', '👋'];
const ABC = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';
const HOUR = 3600e3, DAY = 864e5;

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, puid TEXT NOT NULL UNIQUE, handle TEXT NOT NULL UNIQUE, name TEXT NOT NULL DEFAULT '',
     av INTEGER NOT NULL DEFAULT 0, invite TEXT NOT NULL UNIQUE, defaults TEXT NOT NULL DEFAULT '{}', created INTEGER NOT NULL, seen INTEGER NOT NULL DEFAULT 0)`,
  `CREATE TABLE IF NOT EXISTS avatars(uid TEXT PRIMARY KEY, type TEXT NOT NULL, data TEXT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS links(a TEXT NOT NULL, b TEXT NOT NULL, state TEXT NOT NULL, perms TEXT, created INTEGER NOT NULL, PRIMARY KEY(a,b))`,
  `CREATE INDEX IF NOT EXISTS links_b ON links(b)`,
  `CREATE TABLE IF NOT EXISTS snaps(uid TEXT NOT NULL, cat TEXT NOT NULL, data TEXT NOT NULL, updated INTEGER NOT NULL, PRIMARY KEY(uid,cat))`,
  `CREATE TABLE IF NOT EXISTS reacts(owner TEXT NOT NULL, item TEXT NOT NULL, uid TEXT NOT NULL, emoji TEXT NOT NULL, ts INTEGER NOT NULL, PRIMARY KEY(owner,item,uid))`,
  `CREATE INDEX IF NOT EXISTS reacts_owner_ts ON reacts(owner,ts)`,
  `CREATE TABLE IF NOT EXISTS tokens(h TEXT PRIMARY KEY, id TEXT NOT NULL, exp INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS shares(code TEXT PRIMARY KEY, uid TEXT NOT NULL, kind TEXT NOT NULL, data TEXT NOT NULL, created INTEGER NOT NULL)`
];
let schemaReady = null;
function ensureSchema(db) {
  if (!schemaReady) schemaReady = db.batch(SCHEMA.map(s => db.prepare(s))).catch(e => { schemaReady = null; throw e; });
  return schemaReady;
}

class HttpError extends Error { constructor(status, code, message) { super(message); this.status = status; this.code = code; } }
const J = (o, status) => new Response(JSON.stringify(o), { status: status || 200, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' } });
const err = (status, code, message) => J({ error: code, message }, status);
const parse = s => { try { return s ? JSON.parse(s) : null; } catch (e) { return null; } };
const clean = (s, n) => String(s == null ? '' : s).replace(/[\u0000-\u001f\u007f<>]/g, '').replace(/\s+/g, ' ').trim().slice(0, n);
const normCode = c => String(c || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 12);
function code(n) { const a = new Uint8Array(n); crypto.getRandomValues(a); let s = ''; for (const x of a) s += ABC[x % ABC.length]; return s; }
const pub = u => ({ id: u.id, handle: u.handle, name: u.name || u.handle, av: u.av || 0 });
function cleanPerms(p) { const o = {}; if (p && typeof p === 'object') for (const c of CATS) if (typeof p[c] === 'boolean') o[c] = p[c]; return o; }
/* effective permissions = per-friend override, else the owner's defaults, else the app defaults */
function eff(defaults, overrides) {
  const d = typeof defaults === 'string' ? parse(defaults) || {} : defaults || {}, o = typeof overrides === 'string' ? parse(overrides) || {} : overrides || {}, r = {};
  for (const c of CATS) r[c] = typeof o[c] === 'boolean' ? o[c] : typeof d[c] === 'boolean' ? d[c] : DEFAULTS[c];
  return r;
}
function filterSum(s, can) {
  if (!s || typeof s !== 'object') return {};
  const o = {};
  for (const c of CATS) if (can[c] && s[c] != null) o[c] = s[c];
  if (can.gym && s.live) o.live = s.live;
  return o;
}
function filterFeed(f, can) {
  if (!Array.isArray(f)) return [];
  const out = [];
  for (const it of f) {
    if (!it || typeof it !== 'object' || !can[it.c]) continue;
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
  if (t.length > 400000) throw new HttpError(413, 'too_big', 'That is too much data at once.');
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
const LINKQ = `SELECT l.b AS id, l.state, l.perms AS mine, l.created, u.handle, u.name, u.av, u.defaults, r.perms AS theirs
  FROM links l JOIN users u ON u.id=l.b LEFT JOIN links r ON r.a=l.b AND r.b=l.a`;
async function api(req, env, ctx, url) {
  if (!env.DB) return err(503, 'not_ready', 'Friends aren’t switched on yet.');
  const db = env.DB, M = req.method, p = url.pathname.replace(/\/+$/, '');
  let m;
  try {
    await ensureSchema(db);
    /* public: avatars, invite previews, shared splits */
    if (M === 'GET' && (m = /^\/api\/avatar\/([a-z0-9]{8,32})$/.exec(p))) return await avatarOut(db, m[1], url);
    if (M === 'GET' && (m = /^\/api\/invite\/([A-Za-z0-9-]{4,20})$/.exec(p))) {
      const u = await db.prepare('SELECT id,handle,name,av FROM users WHERE invite=?').bind(normCode(m[1])).first();
      return u ? J({ user: pub(u) }) : err(404, 'invite_invalid', 'That invite doesn’t work any more — ask for a new one.');
    }
    if (M === 'GET' && (m = /^\/api\/share\/([A-Za-z0-9-]{4,20})$/.exec(p))) {
      const s = await db.prepare('SELECT s.kind, s.data, s.created, u.id, u.handle, u.name, u.av FROM shares s JOIN users u ON u.id=s.uid WHERE s.code=?').bind(normCode(m[1])).first();
      return s ? J({ kind: s.kind, data: parse(s.data), created: s.created, from: pub(s) }) : err(404, 'share_invalid', 'That link doesn’t work any more.');
    }
    /* everything else needs a signed-in Puter account */
    const me = await who(req, env, ctx);
    if (!me) return err(401, 'auth', 'Sign in again to use friends.');
    const id = me.id;
    const b = (M === 'POST' || M === 'PUT') ? await readBody(req) : null;
    switch (M + ' ' + p) {
      case 'GET /api/me': return J(await meOut(db, id));
      case 'PUT /api/me': return await putMe(db, id, b);
      case 'POST /api/me/invite': await db.prepare('UPDATE users SET invite=? WHERE id=?').bind(code(8), id).run(); return J(await meOut(db, id));
      case 'PUT /api/snap': return await putSnap(db, id, b);
      case 'GET /api/friends': return J(await friendsOut(db, id));
      case 'POST /api/friends/add': return await addFriend(db, id, b);
      case 'POST /api/friends/respond': return await respond(db, id, b);
      case 'POST /api/react': return await react(db, id, b);
      case 'POST /api/seen': await db.prepare('UPDATE users SET seen=? WHERE id=?').bind(Date.now(), id).run(); return J({ ok: true });
      case 'POST /api/share': return await share(db, id, b);
      case 'GET /api/lookup': {
        const h = String(url.searchParams.get('h') || '').toLowerCase().replace(/^@/, '').trim();
        const u = /^[a-z0-9_.]{3,20}$/.test(h) && await db.prepare('SELECT id,handle,name,av FROM users WHERE handle=?').bind(h).first();
        if (!u) return err(404, 'no_user', 'Nobody has that username.');
        const l = await db.prepare('SELECT state FROM links WHERE a=? AND b=?').bind(id, u.id).first();
        return J({ user: pub(u), state: u.id === id ? 'self' : l ? l.state : 'none' });
      }
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
  const u = await db.prepare('SELECT id,handle,name,av,invite,defaults,created,seen FROM users WHERE id=?').bind(id).first();
  if (!u) throw new HttpError(404, 'no_profile', 'Profile not found.');
  return { id: u.id, handle: u.handle, name: u.name, av: u.av, invite: u.invite, defaults: eff(u.defaults), created: u.created, seen: u.seen };
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

/* ---------- what you share: a small summary + activity feed + one detail blob per category ---------- */
const SNAPCATS = ['sum', 'feed', ...CATS];
async function putSnap(db, id, b) {
  const now = Date.now(), st = [];
  for (const c of SNAPCATS) {
    if (!(c in b)) continue;
    let v = b[c];
    if (v === null) { st.push(db.prepare('DELETE FROM snaps WHERE uid=? AND cat=?').bind(id, c)); continue; }
    if (!v || typeof v !== 'object') throw new HttpError(400, 'bad_snap', 'Bad data.');
    if (c === 'feed') {
      if (!Array.isArray(v)) throw new HttpError(400, 'bad_snap', 'Bad data.');
      v = v.filter(it => it && typeof it === 'object' && typeof it.id === 'string' && it.id.length <= 64 && CATS.includes(it.c) && typeof it.ts === 'number').slice(0, 60);
    }
    const s = JSON.stringify(v);
    if (s.length > 90000) throw new HttpError(413, 'too_big', 'That is too much data at once.');
    st.push(db.prepare('INSERT OR REPLACE INTO snaps(uid,cat,data,updated) VALUES(?,?,?,?)').bind(id, c, s, now));
  }
  if (st.length) await db.batch(st);
  return J({ ok: true, ts: now });
}

/* ---------- friends list, requests, activity feed, reactions inbox ---------- */
async function friendsOut(db, me) {
  const now = Date.now();
  const rows = (await db.prepare(LINKQ + ' WHERE l.a=? ORDER BY l.created DESC LIMIT 300').bind(me).all()).results || [];
  const meRow = await meOut(db, me);
  const friends = rows.filter(r => r.state === 'friend'), fids = friends.map(f => f.id), fset = new Set(fids);
  const owners = [...fids, me];
  const snaps = await selectIn(db, "SELECT uid, cat, data, updated FROM snaps WHERE cat IN ('sum','feed') AND uid IN ", owners);
  const reacts = await selectIn(db, 'SELECT owner, item, uid, emoji FROM reacts WHERE ts>? AND owner IN ', owners, '', [now - 21 * DAY]);
  const inboxRows = (await db.prepare(`SELECT r.item, r.emoji, r.ts, u.id, u.handle, u.name, u.av FROM reacts r JOIN users u ON u.id=r.uid
      WHERE r.owner=? AND r.uid<>? ORDER BY r.ts DESC LIMIT 40`).bind(me, me).all()).results || [];
  const S = {};
  for (const s of snaps) (S[s.uid] = S[s.uid] || {})[s.cat] = { d: parse(s.data), t: s.updated };
  const out = { now, me: meRow, friends: [], incoming: [], outgoing: [], feed: [], inbox: [] };
  for (const r of rows) {
    const u = pub(r);
    if (r.state === 'in') out.incoming.push(Object.assign(u, { ts: r.created }));
    else if (r.state === 'out') out.outgoing.push(Object.assign(u, { ts: r.created }));
    else {
      const can = eff(r.defaults, r.theirs), s = S[r.id] || {};
      out.friends.push(Object.assign(u, { since: r.created, can, perms: cleanPerms(parse(r.mine)), sum: filterSum(s.sum && s.sum.d, can), upd: s.sum ? s.sum.t : 0 }));
      for (const it of filterFeed(s.feed && s.feed.d, can)) out.feed.push(Object.assign(it, { by: r.id }));
    }
  }
  const all = eff({}, { gym: true, lifts: true, split: true, diet: true, nutr: true, body: true });
  for (const it of filterFeed(S[me] && S[me].feed && S[me].feed.d, all)) out.feed.push(Object.assign(it, { by: me }));
  out.feed.sort((a, b) => b.ts - a.ts);
  out.feed = out.feed.slice(0, 80);
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
  let t;
  if (b.invite) {
    t = await db.prepare('SELECT id,handle,name,av FROM users WHERE invite=?').bind(normCode(b.invite)).first();
    if (!t) throw new HttpError(404, 'invite_invalid', 'That invite doesn’t work any more — ask for a new one.');
  } else if (b.handle) {
    const h = String(b.handle).toLowerCase().replace(/^@/, '').trim();
    t = /^[a-z0-9_.]{3,20}$/.test(h) && await db.prepare('SELECT id,handle,name,av FROM users WHERE handle=?').bind(h).first();
    if (!t) throw new HttpError(404, 'no_user', 'Nobody has that username.');
  } else throw new HttpError(400, 'bad', 'Scan a code, open an invite link or type a username.');
  if (t.id === me) throw new HttpError(400, 'self', 'That’s your own code 🙂');
  const cur = await db.prepare('SELECT state FROM links WHERE a=? AND b=?').bind(me, t.id).first();
  const now = Date.now();
  let state;
  if (cur && cur.state === 'friend') state = 'friend';
  else if (b.invite || (cur && cur.state === 'in')) {
    // an invite link is the owner's consent; an incoming request is accepted by adding back
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
  const can = eff(r.defaults, r.theirs), cats = ['sum', ...CATS.filter(c => can[c])];
  const rows = (await db.prepare('SELECT cat, data, updated FROM snaps WHERE uid=? AND cat IN (' + cats.map(() => '?').join(',') + ')').bind(fid, ...cats).all()).results || [];
  const data = {};
  let sum = {}, upd = 0;
  for (const x of rows) { const v = parse(x.data); if (x.cat === 'sum') { sum = filterSum(v, can); upd = x.updated; } else data[x.cat] = v; }
  return J({ user: pub(r), since: r.created, can, perms: cleanPerms(parse(r.mine)), sum, data, upd });
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
  const f = await db.prepare("SELECT data FROM snaps WHERE uid=? AND cat='feed'").bind(owner).first();
  const it = f && (parse(f.data) || []).find(x => x && x.id === item);
  if (!it || !can[it.c]) throw new HttpError(404, 'gone', 'That post isn’t available any more.');
  const st = [emoji ? db.prepare('INSERT OR REPLACE INTO reacts(owner,item,uid,emoji,ts) VALUES(?,?,?,?,?)').bind(owner, item, me, emoji, Date.now())
                    : db.prepare('DELETE FROM reacts WHERE owner=? AND item=? AND uid=?').bind(owner, item, me)];
  if (Math.random() < 0.03) st.push(db.prepare('DELETE FROM reacts WHERE ts<?').bind(Date.now() - 90 * DAY));
  await db.batch(st);
  return J({ ok: true, item });
}
async function share(db, me, b) {
  if (!b || b.kind !== 'split' || !b.data || typeof b.data !== 'object') throw new HttpError(400, 'bad', 'Nothing to share.');
  const s = JSON.stringify(b.data);
  if (s.length > 60000) throw new HttpError(413, 'too_big', 'That split is too large to share.');
  const n = await db.prepare('SELECT COUNT(*) AS n FROM shares WHERE uid=? AND created>?').bind(me, Date.now() - DAY).first();
  if (n && n.n >= 40) throw new HttpError(429, 'slow_down', 'That’s a lot of sharing for one day — try again tomorrow.');
  const c = code(8);
  await db.prepare('INSERT INTO shares(code,uid,kind,data,created) VALUES(?,?,?,?,?)').bind(c, me, b.kind, s, Date.now()).run();
  return J({ code: c });
}

/* ============================== INVITE / SHARE LINKS ============================== */
// /i/<code> and /s/<code>: a tiny page with link-preview tags (Messages, WhatsApp, AirDrop show the name and photo),
// then straight into the app. On an iPhone outside the app it offers the app or the browser.
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
async function landing(env, url, kind, raw) {
  const c = normCode(raw), isInvite = kind === 'i';
  let name = '', avatar = '', title = isInvite ? 'Join me on Lock In' : 'A training split for you', desc = 'Train together on Lock In — workouts, streaks, PRs and splits.', sub = '';
  if (env.DB) {
    try {
      await ensureSchema(env.DB);
      if (isInvite) {
        const u = await env.DB.prepare('SELECT id,handle,name,av FROM users WHERE invite=?').bind(c).first();
        if (u) { name = u.name || u.handle; title = 'Add ' + name + ' on Lock In'; sub = '@' + u.handle; if (u.av) avatar = '/api/avatar/' + u.id + '?v=' + u.av; }
      } else {
        const s = await env.DB.prepare('SELECT s.data, u.id, u.handle, u.name, u.av FROM shares s JOIN users u ON u.id=s.uid WHERE s.code=?').bind(c).first();
        if (s) {
          const d = parse(s.data) || {}, days = Array.isArray(d.days) ? d.days.length : 0;
          name = s.name || s.handle; title = name + ' shared a split: ' + (d.name || 'Training split');
          desc = days + ' training days' + (Array.isArray(d.days) ? ' — ' + d.days.map(x => x && x.name).filter(Boolean).slice(0, 6).join(', ') : '') + '. Open it in Lock In to use it.';
          sub = d.name || ''; if (s.av) avatar = '/api/avatar/' + s.id + '?v=' + s.av;
        }
      }
    } catch (e) {}
  }
  const target = '/#' + (isInvite ? 'add=' : 'split=') + c, scheme = 'lockin://' + (isInvite ? 'add/' : 'split/') + c;
  const img = url.origin + (avatar || '/icon-512.png'), initial = esc((name || 'L').trim().charAt(0).toUpperCase());
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>${esc(title)}</title><meta name="description" content="${esc(desc)}">
<meta property="og:type" content="website"><meta property="og:site_name" content="Lock In">
<meta property="og:title" content="${esc(title)}"><meta property="og:description" content="${esc(desc)}">
<meta property="og:image" content="${esc(img)}"><meta property="og:url" content="${esc(url.origin + url.pathname)}">
<meta name="twitter:card" content="summary"><meta name="theme-color" content="#0e1013">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<script>(function(){var inApp=!!(window.webkit&&window.webkit.messageHandlers&&window.webkit.messageHandlers.lockin);
if(inApp||!/iPhone|iPad|iPod/.test(navigator.userAgent))location.replace(${JSON.stringify(target)});})();</script>
<style>
:root{color-scheme:dark}*{box-sizing:border-box;margin:0}
body{min-height:100vh;display:grid;place-items:center;padding:24px;background:radial-gradient(80% 60% at 50% 0%,rgba(91,147,255,.22),transparent 70%),#0e1013;color:#e9ecf1;font:16px/1.4 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;text-align:center}
main{width:100%;max-width:360px}
.av{width:104px;height:104px;margin:0 auto 18px;border-radius:50%;display:grid;place-items:center;font-size:42px;font-weight:800;color:#fff;overflow:hidden;
 background:linear-gradient(135deg,#6ea6ff,#7b6cff);box-shadow:0 0 0 3px #0e1013,0 0 0 6px rgba(110,166,255,.55),0 20px 50px rgba(91,147,255,.35)}
.av img{width:100%;height:100%;object-fit:cover}
h1{font-size:24px;letter-spacing:-.02em;margin-bottom:6px}p{color:#a6aeba;font-size:14.5px}
.code{margin:18px 0 22px;font:700 22px/1 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.18em;color:#d9e4f8}
a{display:block;padding:15px;border-radius:16px;font-weight:700;text-decoration:none;margin-top:10px}
.p{background:linear-gradient(135deg,#6ea6ff,#5b7dff 55%,#7b6cff);color:#fff;box-shadow:0 10px 30px rgba(91,147,255,.35)}
.g{background:rgba(255,255,255,.07);color:#e9ecf1;border:1px solid rgba(255,255,255,.12)}
small{display:block;margin-top:18px;color:#7d8592;font-size:12.5px}
</style></head><body><main>
<div class="av">${avatar ? `<img src="${esc(avatar)}" alt="">` : initial}</div>
<h1>${esc(title)}</h1><p>${esc(sub || desc)}</p>
${isInvite ? `<div class="code">${esc(c.slice(0, 4) + '-' + c.slice(4))}</div>` : '<div style="height:22px"></div>'}
<a class="p" href="${esc(scheme)}">Open in the Lock In app</a>
<a class="g" href="${esc(target)}">Continue in the browser</a>
<small>${isInvite ? 'Already in Lock In? Friends → Add friends → Username, then type this code.' : 'Opens the split in Lock In so you can add it to your splits.'}</small>
</main></body></html>`;
  return new Response(html, { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-cache' } });
}
