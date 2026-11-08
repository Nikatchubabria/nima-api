/* NIMA Studio – account + subscription API as a Netlify Function (free tier, state in Netlify Blobs).
 * Same endpoints as the standalone license-server/server.js. Config = Netlify environment variables. */
import crypto from 'node:crypto';
import { getStore } from '@netlify/blobs';

const E = process.env, DAY = 864e5;
const PRICE_TEXT = E.PRICE_TEXT || '$19 / month', PLAN_NAME = E.PLAN_NAME || 'Pro';
const CHECKOUT_URL = E.CHECKOUT_URL || '', CHECKOUT_URL_YEARLY = E.CHECKOUT_URL_YEARLY || '', PRICE_YEARLY = E.PRICE_YEARLY || '';
const STRIPE_SECRET = E.STRIPE_WEBHOOK_SECRET || '', DODO_SECRET = E.DODO_WEBHOOK_SECRET || '', PAY_SECRET = E.PAY_WEBHOOK_SECRET || '';
const PERIOD_DAYS = +E.PERIOD_DAYS || 31, TRIAL_DAYS = +E.TRIAL_DAYS || 0, OFFLINE_MS = (+E.OFFLINE_HOURS || 72) * 3600e3;
const ADMIN_KEY = E.ADMIN_KEY || '';
const OWNER_USER = (E.OWNER_USER || 'admin').toLowerCase(), OWNER_PASSWORD = E.OWNER_PASSWORD || '';
const OWNER_EMAILS = (E.OWNER_EMAILS || 'nchubabria5@gmail.com').toLowerCase().split(',').map(x => x.trim()).filter(Boolean);
const GOOGLE_ID = E.GOOGLE_CLIENT_ID || '', GOOGLE_SECRET = E.GOOGLE_CLIENT_SECRET || '';
const PUBLIC_URL_ENV = (E.PUBLIC_URL || '').replace(/\/+$/, '');

const ADMIN_HTML = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>HCG accounts</title>\n<style>\nbody{margin:0;font:15px system-ui,sans-serif;background:#0b0d10;color:#e8ebf0}\n.w{max-width:1100px;margin:0 auto;padding:24px 16px}h1{font-size:22px;margin:0 0 16px}\ninput,button{font:inherit;padding:9px 12px;border-radius:8px;border:1px solid #2b303a;background:#151922;color:#fff}\nbutton{cursor:pointer}button.p{background:#1f9d8f;border-color:#1f9d8f}button.d{background:#8a2b2b;border-color:#8a2b2b}\ntable{width:100%;border-collapse:collapse;margin-top:14px}th,td{padding:8px 10px;border-bottom:1px solid #20242d;text-align:left;vertical-align:middle}th{color:#8e97a8;font-weight:600;font-size:13px}\n.ok{color:#4fe39a}.no{color:#ff8f8f}.mut{color:#8e97a8}.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}\n</style></head><body><div class=\"w\"><h1>Accounts &amp; subscriptions</h1>\n<div class=\"row\"><input id=\"k\" type=\"password\" placeholder=\"Admin key\" style=\"min-width:260px\"><button class=\"p\" id=\"go\">Open</button><input id=\"q\" placeholder=\"Search e-mail / name\" style=\"flex:1\"><span class=\"mut\" id=\"cnt\"></span></div>\n<div id=\"msg\" class=\"no\" style=\"margin-top:10px\"></div>\n<table><thead><tr><th>E-mail</th><th>Name</th><th>Registered</th><th>Subscription</th><th>Reset code</th><th>Actions</th></tr></thead><tbody id=\"tb\"></tbody></table></div>\n<script>\nvar K=sessionStorage.getItem('ak')||'',U=[];document.getElementById('k').value=K;\nfunction api(p,b){return fetch(p,{method:'POST',headers:{'content-type':'application/json','x-admin-key':K},body:JSON.stringify(b||{})}).then(function(r){return r.json()})}\nfunction esc(s){return String(s==null?'':s).replace(/[&<>\"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;'}[c]})}\nfunction load(){K=document.getElementById('k').value;sessionStorage.setItem('ak',K);api('/api/admin/users').then(function(r){if(!r.ok){document.getElementById('msg').textContent=r.error||'error';return}document.getElementById('msg').textContent='';U=r.users;draw()})}\nfunction draw(){var q=document.getElementById('q').value.toLowerCase(),now=Date.now(),L=U.filter(function(u){return !q||(u.email+' '+u.name).toLowerCase().indexOf(q)>=0});\ndocument.getElementById('cnt').textContent=L.length+' / '+U.length+' accounts \u00b7 '+U.filter(function(u){return u.subUntil>now}).length+' active';\ndocument.getElementById('tb').innerHTML=L.map(function(u){var on=u.subUntil>now,left=Math.ceil((u.subUntil-now)/864e5);\nreturn '<tr><td>'+esc(u.email)+(u.banned?' <b class=no>(blocked)</b>':'')+'</td><td>'+esc(u.name)+'</td><td class=mut>'+new Date(u.createdAt).toLocaleDateString()+'</td><td>'+(on?'<span class=ok>active \u00b7 '+left+' days left</span> <span class=mut>('+esc(u.source||'')+')</span>':'<span class=mut>none</span>')+'</td><td>'+esc(u.resetCode||'')+'</td><td class=row>'+\n'<button class=p data-a=grant data-d=30 data-i=\"'+u.id+'\">+30 days</button><button data-a=grant data-d=365 data-i=\"'+u.id+'\">+1 year</button><button data-a=revoke data-i=\"'+u.id+'\">Revoke</button><button data-a=ban data-i=\"'+u.id+'\">'+(u.banned?'Unblock':'Block')+'</button><button class=d data-a=delete data-i=\"'+u.id+'\">Delete</button></td></tr>'}).join('')}\ndocument.getElementById('go').onclick=load;document.getElementById('q').oninput=draw;\ndocument.getElementById('tb').onclick=function(e){var b=e.target.closest('button');if(!b)return;var a=b.dataset.a,i=b.dataset.i,u=U.filter(function(x){return x.id===i})[0];\nif(a==='delete'&&!confirm('Delete '+u.email+' permanently?'))return;\nvar body={id:i};if(a==='grant')body.days=+b.dataset.d;if(a==='ban')body.banned=!u.banned;api('/api/admin/'+a,body).then(function(r){if(!r.ok)alert(r.error);load()})};\nif(K)load();\n</script></body></html>\n";

const store = () => getStore({ name: 'nima', consistency: 'strong' });
const b64u = b => Buffer.from(b).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
const sha = t => crypto.createHash('sha256').update(t).digest('hex');
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 64, { N: 16384, r: 8, p: 1 }).toString('hex');
const newPw = pw => { const salt = crypto.randomBytes(16).toString('hex'); return { salt, hash: hashPw(pw, salt) }; };
const normEmail = e => String(e || '').trim().toLowerCase();
const validEmail = e => /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/.test(e) && e.length <= 254;
const teq = (a, b) => { a = Buffer.from(String(a)); b = Buffer.from(String(b)); return a.length === b.length && crypto.timingSafeEqual(a, b); };

/* signing keys: created once, kept in the blob store forever */
let keysCache = null;
async function getKeys() {
  if (keysCache) return keysCache;
  const s = store();
  let k = await s.get('keys', { type: 'json' });
  if (!k) {
    const kp = crypto.generateKeyPairSync('ed25519');
    const nk = { priv: kp.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'), pub: kp.publicKey.export({ type: 'spki', format: 'der' }).toString('base64') };
    await s.setJSON('keys', nk, { onlyIfNew: true });          // if two requests race, the first wins
    k = await s.get('keys', { type: 'json' });
  }
  k.PRIV = crypto.createPrivateKey({ key: Buffer.from(k.priv, 'base64'), format: 'der', type: 'pkcs8' });
  return (keysCache = k);
}

/* best-effort rate limiter (per warm instance) */
const hits = new Map();
function limited(key, max, win) {
  const now = Date.now(), a = (hits.get(key) || []).filter(t => now - t < win); a.push(now); hits.set(key, a);
  if (hits.size > 3000) for (const [k, v] of hits) if (!v.length || now - v[v.length - 1] > win) hits.delete(k);
  return a.length > max;
}

const J = (code, o) => ({ code, type: 'application/json', body: JSON.stringify(o) });
const fail = (code, msg) => J(code, { ok: false, error: msg });
const HTML = (code, h) => ({ code, type: 'text/html; charset=utf-8', body: h });
const donePage = (ok, m) => '<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width"><title>Sign-in</title><body style="font-family:system-ui;background:#0f1318;color:#eef1f5;display:grid;place-items:center;height:100vh;margin:0"><div style="text-align:center;padding:20px"><h2>' + (ok ? '✓ Signed in' : 'Sign-in failed') + '</h2><p>' + String(m).replace(/[<>&]/g, '') + '</p></div>';

async function route(c, S) {
  const { db, keys } = S, { p, M, h } = c;
  const touch = () => { S.dirty = true; };
  const findByEmail = e => Object.values(db.users).find(u => u.email === e);
  const signLicense = u => {
    const now = Date.now(), sub = u.sub && u.sub.until > now ? u.sub.until : 0;
    const pl = { uid: u.id, email: u.email, name: u.name, plan: sub ? PLAN_NAME : '', sub, iat: now, chk: now + OFFLINE_MS };
    const body = b64u(JSON.stringify(pl));
    return body + '.' + b64u(crypto.sign(null, Buffer.from(body), keys.PRIV));
  };
  const pub = u => ({ id: u.id, email: u.email, name: u.name, createdAt: u.createdAt, sub: u.sub && u.sub.until > Date.now() ? { until: u.sub.until, source: u.sub.source } : null });
  const session = (u, token) => J(200, { ok: true, token, user: pub(u), license: signLicense(u), price: PRICE_TEXT, plan: PLAN_NAME, canPay: !!(CHECKOUT_URL || CHECKOUT_URL_YEARLY), canYearly: !!CHECKOUT_URL_YEARLY, priceYearly: PRICE_YEARLY });
  const newSession = (u, device) => {
    const tok = crypto.randomBytes(32).toString('hex');
    db.sessions[sha(tok)] = { uid: u.id, device: String(device || '').slice(0, 60), at: Date.now(), exp: Date.now() + 60 * DAY };
    Object.entries(db.sessions).filter(([, s]) => s.uid === u.id).sort((a, b) => b[1].at - a[1].at).slice(5).forEach(([k]) => delete db.sessions[k]);
    for (const [k, s] of Object.entries(db.sessions)) if (s.exp < Date.now()) delete db.sessions[k];
    touch(); return tok;
  };
  const extend = (u, days, source, untilAbs) => { const now = Date.now(), base = u.sub && u.sub.until > now ? u.sub.until : now; u.sub = { until: untilAbs || base + days * DAY, source: source || 'manual', at: now }; touch(); };
  const dropSessions = (uid, except) => { for (const k of Object.keys(db.sessions)) if (db.sessions[k].uid === uid && k !== except) delete db.sessions[k]; };
  const isAdmin = () => ADMIN_KEY && teq(h('x-admin-key'), ADMIN_KEY);

  /* owner account (always subscribed). OWNER_PASSWORD env var is applied whenever it changes */
  {
    let o = Object.values(db.users).find(u => u.email === OWNER_USER);
    const fp = sha('pw:' + OWNER_PASSWORD);
    if (!o) { const id = 'u' + (db.nextId++), pwd = newPw(OWNER_PASSWORD || crypto.randomBytes(18).toString('hex')); o = db.users[id] = { id, email: OWNER_USER, name: 'Admin', salt: pwd.salt, hash: pwd.hash, createdAt: Date.now(), ownerFp: fp }; touch(); }
    else if (OWNER_PASSWORD && o.ownerFp !== fp) { Object.assign(o, newPw(OWNER_PASSWORD), { ownerFp: fp }); touch(); }
    if (!o.owner || o.banned || !o.sub || o.sub.until < 4102444800000) { o.owner = true; o.banned = false; o.sub = { until: 4102444800000, source: 'owner', at: Date.now() }; touch(); }
  }

  if (M === 'GET' && (p === '/' || p === '/health' || p === '/api/health')) return J(200, { ok: true, service: 'nima-license', time: Date.now() });
  if (M === 'GET' && p === '/admin') return HTML(200, ADMIN_HTML);
  if (M === 'GET' && p === '/api/live') {          // public: who is LIVE with NIMA Studio right now (website)
    const st = store(), now = Date.now(), { blobs } = await st.list({ prefix: 'live/' });
    const rows = (await Promise.all(blobs.slice(0, 200).map(x => st.get(x.key, { type: 'json' }).catch(() => null)))).filter(Boolean);
    const isPaid = r => { const u = r.uid && db.users[r.uid]; return !!(u && !u.banned && u.sub && u.sub.until > now); };
    const onlyPaid = c.q.get('paid') === '1';      // ?paid=1 -> only streamers with an active subscription (duel list)
    const live = rows.filter(r => now - r.ts < 5 * 60e3 && (!onlyPaid || isPaid(r))).sort((x, y) => y.viewers - x.viewers);
    for (const r of rows) if (now - r.ts > 864e5) st.delete('live/' + r.name).catch(() => {});
    return Object.assign(J(200, { ok: true, count: live.length, viewers: live.reduce((t, r) => t + r.viewers, 0), streamers: live.slice(0, 40).map(r => ({ name: r.name, viewers: r.viewers })) }), { headers: { 'access-control-allow-origin': '*', 'cache-control': 'public, max-age=30' } });
  }
  if (M === 'GET' && p === '/api/pubkey') return J(200, { ok: true, publicKey: keys.pub, price: PRICE_TEXT, plan: PLAN_NAME, canPay: !!CHECKOUT_URL, google: !!(GOOGLE_ID && GOOGLE_SECRET) });

  /* ---- Google sign-in ---- */
  const redirectUri = (PUBLIC_URL_ENV || c.origin) + '/api/google/callback';
  if (M === 'GET' && p === '/api/google/start') {
    if (!GOOGLE_ID || !GOOGLE_SECRET) return HTML(200, donePage(false, 'Google sign-in is not set up on the server yet.'));
    const state = c.q.get('state') || ''; if (!/^[0-9a-f]{32,64}$/.test(state) || limited('gs:' + c.ip, 30, 3600e3)) return fail(400, 'bad state');
    for (const [k, v] of Object.entries(db.gpend)) if (Date.now() - v.at > 10 * 60e3) delete db.gpend[k];
    db.gpend[state] = { at: Date.now(), result: null }; touch();
    return { code: 302, headers: { location: 'https://accounts.google.com/o/oauth2/v2/auth?' + new URLSearchParams({ client_id: GOOGLE_ID, redirect_uri: redirectUri, response_type: 'code', scope: 'openid email profile', state, prompt: 'select_account' }) }, body: '' };
  }
  if (M === 'GET' && p === '/api/google/callback') {
    const state = c.q.get('state') || '', code = c.q.get('code') || '', g = db.gpend[state];
    if (!g || !code) return HTML(200, donePage(false, 'The sign-in was cancelled or expired. Close this window and try again in the app.'));
    try {
      const t = await (await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ code, client_id: GOOGLE_ID, client_secret: GOOGLE_SECRET, redirect_uri: redirectUri, grant_type: 'authorization_code' }) })).json();
      if (!t.access_token) throw new Error(t.error_description || t.error || 'Google refused the sign-in.');
      const info = await (await fetch('https://openidconnect.googleapis.com/v1/userinfo', { headers: { authorization: 'Bearer ' + t.access_token } })).json();
      if (!info.email || info.email_verified === false) throw new Error('Your Google e-mail is not verified.');
      const email = normEmail(info.email); let u = findByEmail(email);
      if (!u) {
        const id = 'u' + (db.nextId++), pwd = newPw(crypto.randomBytes(24).toString('hex'));
        u = db.users[id] = { id, email, name: String(info.name || email.split('@')[0]).slice(0, 40), salt: pwd.salt, hash: pwd.hash, createdAt: Date.now(), google: info.sub || true, sub: TRIAL_DAYS ? { until: Date.now() + TRIAL_DAYS * DAY, source: 'trial', at: Date.now() } : null };
      } else if (!u.google) u.google = info.sub || true;
      if (OWNER_EMAILS.includes(email)) { u.owner = true; u.banned = false; u.sub = { until: 4102444800000, source: 'owner', at: Date.now() }; }
      if (u.banned) throw new Error('This account is blocked.');
      g.result = { ok: true, uid: u.id }; touch();
      return HTML(200, donePage(true, 'You can close this window and return to the app.'));
    } catch (e) { g.result = { ok: false, error: e.message }; touch(); return HTML(200, donePage(false, e.message)); }
  }
  if (M !== 'POST') return fail(405, 'method');

  const raw = c.raw;
  if (p === '/api/stripe-webhook') {
    const pr = {}; String(h('stripe-signature')).split(',').forEach(x => { const [k, v] = x.split('='); (pr[k] = pr[k] || []).push(v); });
    const t = (pr.t || [])[0];
    const ok = STRIPE_SECRET && t && Math.abs(Date.now() / 1000 - +t) <= 600 && (pr.v1 || []).some(v => v && teq(v, crypto.createHmac('sha256', STRIPE_SECRET).update(t + '.' + raw).digest('hex')));
    if (!ok) return fail(400, 'bad signature');
    let ev; try { ev = JSON.parse(raw); } catch (_) { return fail(400, 'bad json'); }
    const o = ev.data && ev.data.object || {};
    if (['checkout.session.completed', 'invoice.paid', 'invoice.payment_succeeded'].includes(ev.type)) {
      let u = o.client_reference_id && db.users[o.client_reference_id];
      const em = normEmail(o.customer_email || (o.customer_details && o.customer_details.email)); if (!u && em) u = findByEmail(em);
      if (u && !(ev.type === 'checkout.session.completed' && o.payment_status && o.payment_status !== 'paid')) {
        const end = o.lines && o.lines.data && o.lines.data[0] && o.lines.data[0].period && o.lines.data[0].period.end;
        extend(u, PERIOD_DAYS, 'stripe', end && end * 1000 > Date.now() ? end * 1000 + DAY : 0);
      }
    }
    return J(200, { ok: true, received: true });
  }
  if (p === '/api/dodo-webhook') {
    const id = h('webhook-id'), ts = h('webhook-timestamp'), sg = h('webhook-signature');
    if (!DODO_SECRET || !id || Math.abs(Date.now() / 1000 - +ts) > 600) return fail(400, 'bad signature');
    const key = /^whsec_/.test(DODO_SECRET) ? Buffer.from(DODO_SECRET.slice(6), 'base64') : Buffer.from(DODO_SECRET);
    const want = crypto.createHmac('sha256', key).update(id + '.' + ts + '.' + raw).digest('base64');
    if (!sg.split(' ').some(x => teq(x.split(',')[1] || '', want))) return fail(400, 'bad signature');
    let ev; try { ev = JSON.parse(raw); } catch (_) { return fail(400, 'bad json'); }
    const d = ev.data || {}, type = String(ev.type || ''), md = d.metadata || {}, em = normEmail((d.customer && d.customer.email) || d.email || '');
    const t = db.users[md.uid] || (em && findByEmail(em)); if (!t) return fail(404, 'user not found');
    if (/^subscription\.(active|renewed|plan_changed|updated)$/.test(type) && (!d.status || d.status === 'active') && d.next_billing_date)
      extend(t, 0, 'dodo:' + type, Math.max(t.sub && t.sub.until > Date.now() ? t.sub.until : 0, new Date(d.next_billing_date).getTime() + DAY));
    else if (type === 'payment.succeeded' && !d.subscription_id) extend(t, PERIOD_DAYS, 'dodo');
    else return J(200, { ok: true, ignored: type });
    return J(200, { ok: true });
  }
  if (p === '/api/pay-webhook') {
    const sig = h('x-signature') || h('x-pay-signature'), want = PAY_SECRET ? crypto.createHmac('sha256', PAY_SECRET).update(raw).digest('hex') : '';
    if (!PAY_SECRET || !teq(sig, want)) return fail(400, 'bad signature');
    let ev; try { ev = JSON.parse(raw); } catch (_) { return fail(400, 'bad json'); }
    const meta = ev.meta || {}, at = (ev.data && ev.data.attributes) || {}, name = meta.event_name || ev.event || '';
    const uid = (meta.custom_data && meta.custom_data.uid) || ev.uid || '', em = normEmail(at.user_email || ev.email || '');
    const t = db.users[uid] || (em && findByEmail(em)); if (!t) return fail(404, 'user not found');
    if (/^subscription_(created|updated|payment_success|resumed|unpaused)$/.test(name) && /^(active|on_trial|paid)$/.test(at.status || 'active') && at.renews_at)
      extend(t, 0, 'pay:' + name, Math.max(t.sub && t.sub.until > Date.now() ? t.sub.until : 0, new Date(at.renews_at).getTime() + DAY));
    else if (name === 'paid') extend(t, Math.max(1, Math.min(400, +ev.days || PERIOD_DAYS)), 'pay');
    else return J(200, { ok: true, ignored: name });
    return J(200, { ok: true });
  }
  let b = {}; try { b = JSON.parse(raw || '{}') || {}; } catch (_) { return fail(400, 'bad json'); }

  /* ---- admin ---- */
  if (p.startsWith('/api/admin/')) {
    if (limited('adm:' + c.ip, 60, 60e3)) return fail(429, 'slow down');
    /* the admin is either the secret key (old /admin page) or a logged-in session of an owner e-mail (the Admin tab inside the app) */
    const mb = /^Bearer ([0-9a-f]{64})$/.exec(h('authorization')), sx = mb && db.sessions[sha(mb[1])], ux = sx && sx.exp > Date.now() && db.users[sx.uid];
    const byUser = ux && !ux.banned && OWNER_EMAILS.includes(ux.email) ? ux : null;
    if (!isAdmin() && !byUser) return fail(403, 'Admin only');
    const lastSeen = {}; for (const k of Object.keys(db.sessions)) { const x = db.sessions[k]; if (!lastSeen[x.uid] || x.at > lastSeen[x.uid]) lastSeen[x.uid] = x.at; }
    if (p === '/api/admin/users') return J(200, { ok: true, me: byUser ? byUser.id : '', users: Object.values(db.users).map(x => Object.assign(pub(x), { banned: !!x.banned, owner: !!x.owner, lastSeen: lastSeen[x.id] || 0, subUntil: x.sub ? x.sub.until : 0, source: x.sub && x.sub.source, resetCode: x.reset && x.reset.exp > Date.now() ? x.reset.code : '' })).sort((a, z) => z.createdAt - a.createdAt) });
    const t = db.users[b.id] || findByEmail(normEmail(b.email)); if (!t) return fail(404, 'user not found');
    const self = byUser && t.id === byUser.id;
    if (p === '/api/admin/set') {      // exact: until = a date (ms), or days counted from today (0 = switch off)
      if (b.until) { const u = +b.until; if (!(u > 0)) return fail(400, 'bad date'); t.sub = { until: u, source: 'admin', at: Date.now() }; }
      else { const d = Math.max(0, Math.min(3650, Math.floor(+b.days || 0))); t.sub = d ? { until: Date.now() + d * DAY, source: 'admin', at: Date.now() } : null; }
      touch(); return J(200, { ok: true, user: pub(t) });
    }
    if (p === '/api/admin/update') {
      if (b.name != null) t.name = String(b.name).trim().slice(0, 40) || t.name;
      if (b.email != null) { const e = normEmail(b.email); if (!validEmail(e)) return fail(400, 'Enter a valid e-mail.'); const o = findByEmail(e); if (o && o.id !== t.id) return fail(409, 'This e-mail is already used by another account.'); t.email = e; }
      touch(); return J(200, { ok: true, user: pub(t) });
    }
    if (self && (p === '/api/admin/revoke' || p === '/api/admin/ban' || p === '/api/admin/delete')) return fail(400, 'You cannot do this to your own account.');
    if (p === '/api/admin/grant') { extend(t, Math.max(1, Math.min(3650, +b.days || 30)), 'admin'); return J(200, { ok: true, user: pub(t) }); }
    if (p === '/api/admin/revoke') { t.sub = null; touch(); return J(200, { ok: true }); }
    if (p === '/api/admin/ban') { t.banned = b.banned !== false; if (t.banned) dropSessions(t.id); touch(); return J(200, { ok: true }); }
    if (p === '/api/admin/delete') { delete db.users[t.id]; dropSessions(t.id); touch(); return J(200, { ok: true }); }
    if (p === '/api/admin/password') { const n = String(b.password || ''); if (n.length < 6) return fail(400, 'min 8 characters'); Object.assign(t, newPw(n)); touch(); return J(200, { ok: true }); }
    return fail(404, 'unknown');
  }

  /* ---- public ---- */
  if (p === '/api/google/poll') {
    const st = String(b.state || ''), g = db.gpend[st]; if (!g) return fail(404, 'Sign-in expired. Try again.');
    if (!g.result) return J(200, { ok: true, pending: true });
    delete db.gpend[st]; touch(); if (!g.result.ok) return fail(400, g.result.error);
    const u = db.users[g.result.uid]; if (!u) return fail(400, 'Account not found.');
    return session(u, newSession(u, b.device));
  }
  if (p === '/api/register') {
    if (limited('reg:' + c.ip, 10, 3600e3)) return fail(429, 'Too many sign-ups from this address, try later.');
    const email = normEmail(b.email), name = String(b.name || '').trim().slice(0, 40), pw = String(b.password || '');
    if (!validEmail(email)) return fail(400, 'Enter a valid e-mail address.');
    if (pw.length < 6 || pw.length > 200) return fail(400, 'Password must be at least 6 characters.');
    if (findByEmail(email)) return fail(409, 'This e-mail is already registered. Log in instead.');
    const id = 'u' + (db.nextId++), pwd = newPw(pw);
    const user = db.users[id] = { id, email, name: name || email.split('@')[0], salt: pwd.salt, hash: pwd.hash, createdAt: Date.now(), sub: TRIAL_DAYS ? { until: Date.now() + TRIAL_DAYS * DAY, source: 'trial', at: Date.now() } : null };
    return session(user, newSession(user, b.device));
  }
  if (p === '/api/login') {
    const email = normEmail(b.email);
    if (limited('log:' + c.ip + ':' + email, 10, 15 * 60e3)) return fail(429, 'Too many attempts. Wait 15 minutes.');
    const user = findByEmail(email);
    if (!user || !teq(hashPw(String(b.password || ''), user.salt), user.hash)) { hashPw('x', 'y'); return fail(401, 'Wrong e-mail or password.'); }
    if (user.banned) return fail(403, 'This account is blocked.');
    return session(user, newSession(user, b.device));
  }
  if (p === '/api/forgot') {     // e-mails the code via Resend when RESEND_API_KEY is set; otherwise the admin sees it in /admin
    const email = normEmail(b.email);
    if (limited('fg:' + c.ip, 8, 3600e3)) return fail(429, 'Too many requests.');
    const user = findByEmail(email);
    if (user) {
      user.reset = { code: String(crypto.randomInt(0, 1e6)).padStart(6, '0'), exp: Date.now() + 15 * 60e3, tries: 0 }; touch();
      const RK = E.RESEND_API_KEY || '', FROM = E.MAIL_FROM || 'NIMA Studio <onboarding@resend.dev>';
      if (RK) {   // e-mail the code (Resend); without a key the code stays visible to the admin in /admin
        try {
          const r = await fetch('https://api.resend.com/emails', { method: 'POST', headers: { authorization: 'Bearer ' + RK, 'content-type': 'application/json' }, body: JSON.stringify({ from: FROM, to: [user.email], subject: 'NIMA Studio password reset code', text: 'Your NIMA Studio password reset code is ' + user.reset.code + '\n\nIt is valid for 15 minutes. If you did not ask for it, ignore this e-mail.', html: '<p>Your NIMA Studio password reset code:</p><p style="font-size:28px;font-weight:700;letter-spacing:4px">' + user.reset.code + '</p><p>It is valid for 15 minutes. If you did not ask for it, ignore this e-mail.</p>' }) });
          if (!r.ok) console.error('resend', r.status, await r.text());
        } catch (e) { console.error('resend', e && e.message); }
      }
    }
    return J(200, { ok: true });
  }
  if (p === '/api/reset') {
    const email = normEmail(b.email), user = findByEmail(email), pw = String(b.password || '');
    if (limited('rs:' + c.ip + email, 10, 3600e3)) return fail(429, 'Too many attempts.');
    if (pw.length < 6) return fail(400, 'Password must be at least 6 characters.');
    if (!user || !user.reset || user.reset.exp < Date.now() || user.reset.tries >= 5) return fail(400, 'The code is wrong or expired.');
    user.reset.tries++; touch();
    if (!teq(String(b.code || '').padEnd(6, ' '), user.reset.code)) return fail(400, 'The code is wrong or expired.');
    Object.assign(user, newPw(pw)); user.reset = null; dropSessions(user.id);
    return session(user, newSession(user, b.device));
  }
  const m = /^Bearer ([0-9a-f]{64})$/.exec(h('authorization'));
  const ses = m && db.sessions[sha(m[1])], au = ses && ses.exp > Date.now() && db.users[ses.uid];
  const a = au && !au.banned ? { u: au, key: sha(m[1]) } : null;
  if (p === '/api/live/ping') {
    if (!a) return fail(401, 'Please log in again.');
    const name = String(b.name || '').trim().replace(/^@/, '').toLowerCase();
    if (!/^[a-z0-9_.]{2,40}$/.test(name)) return fail(400, 'bad name');
    const viewers = Math.max(0, Math.min(1e7, Math.floor(+b.viewers || 0)));
    await store().setJSON('live/' + name, { name, viewers, ts: Date.now(), uid: a.u.id });
    return J(200, { ok: true });
  }
  /* per-account app settings (games, looks, overlays choices): one JSON blob per user, so they follow the account to any PC */
  if (p === '/api/settings') {
    if (!a) return fail(401, 'Please log in again.');
    if (b && b.set) {
      const txt = JSON.stringify(b.data || {});
      if (txt.length > 4e6) return fail(413, 'Settings are too large.');
      await store().setJSON('settings/' + a.u.id, { ts: Date.now(), data: b.data || {} });
      return J(200, { ok: true });
    }
    const got = await store().get('settings/' + a.u.id, { type: 'json' }).catch(() => null);
    return J(200, { ok: true, data: (got && got.data) || null, ts: (got && got.ts) || 0 });
  }
  if (p === '/api/me') { if (!a) return fail(401, 'Please log in again.'); return session(a.u, ''); }
  if (p === '/api/logout') { if (a) { delete db.sessions[a.key]; touch(); } return J(200, { ok: true }); }
  if (p === '/api/change-password') {
    if (!a) return fail(401, 'Please log in again.');
    if (!teq(hashPw(String(b.old || ''), a.u.salt), a.u.hash)) return fail(400, 'Current password is wrong.');
    const pw = String(b.password || ''); if (pw.length < 6) return fail(400, 'Password must be at least 6 characters.');
    Object.assign(a.u, newPw(pw)); dropSessions(a.u.id, a.key); touch(); return J(200, { ok: true });
  }
  if (p === '/api/checkout') {
    if (!a) return fail(401, 'Please log in again.');
    const CU = b.plan === 'yearly' && CHECKOUT_URL_YEARLY ? CHECKOUT_URL_YEARLY : CHECKOUT_URL;
    if (!CU) return fail(503, 'Payments are not set up yet. Contact the seller to activate your subscription.');
    const url = CU.replace(/\{uid\}/g, encodeURIComponent(a.u.id)).replace(/\{email\}/g, encodeURIComponent(a.u.email));
    return J(200, { ok: true, url: /[?&]client_reference_id=/.test(url) || /\{uid\}/.test(CU) ? url : url + (url.includes('?') ? '&' : '?') + 'client_reference_id=' + encodeURIComponent(a.u.id) + '&prefilled_email=' + encodeURIComponent(a.u.email) });
  }
  return fail(404, 'unknown endpoint');
}

/* Duel relay (fallback when two game windows cannot connect directly): each side writes its own small message list and reads the other's.
 * No account database is touched, so polling is cheap. Rooms are random, short-lived and size-capped. */
const RF = (code, msg) => new Response(JSON.stringify({ ok: false, error: msg }), { status: code, headers: { 'content-type': 'application/json' } });
async function duelRelay(raw, ip) {
  let b; try { b = JSON.parse(raw); } catch (_) { return RF(400, 'bad request'); }
  const room = String(b.room || ''), role = b.role === 'h' ? 'h' : b.role === 'g' ? 'g' : '';
  if (!/^[a-z0-9]{6,24}$/.test(room) || !role) return RF(400, 'bad room');
  if (limited('rl:' + ip, 400, 60e3)) return RF(429, 'slow down');
  const st = store(), mine = 'duel/' + room + '/' + role, theirs = 'duel/' + room + '/' + (role === 'h' ? 'g' : 'h');
  const send = (Array.isArray(b.send) ? b.send : []).slice(0, 60).filter(m => m && typeof m === 'object' && JSON.stringify(m).length < 700);
  if (send.length) {
    const cur = (await st.get(mine, { type: 'json' }).catch(() => null)) || { n: 0, msgs: [] };
    for (const m of send) { cur.n++; cur.msgs.push({ i: cur.n, m }); }
    cur.msgs = cur.msgs.slice(-200); cur.ts = Date.now();
    await st.setJSON(mine, cur);
  }
  const since = Math.max(0, Math.floor(+b.since) || 0);
  const o = await st.get(theirs, { type: 'json' }).catch(() => null);
  const msgs = o ? o.msgs.filter(x => x.i > since).slice(0, 100) : [];
  return new Response(JSON.stringify({ ok: true, msgs: msgs.map(x => x.m), next: msgs.length ? msgs[msgs.length - 1].i : since }), { status: 200, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
}

/* Auto-update feed for the app (generic provider): the app asks us for latest.yml instead of scraping github.com web pages,
 * which are slow / flaky for some users. We read the newest release through the GitHub API and cache it for 5 minutes; the package file name in
 * latest.yml stays relative, so the app asks us for it and we redirect it to the GitHub download. (If this endpoint fails, the app falls back to its old GitHub feed.) */
async function updateFeed() {
  const st = store(), c = await st.get('upd/cache', { type: 'json' }).catch(() => null);
  if (c && c.yml && Date.now() - c.ts < 5 * 60e3) return c.yml;
  const H = { 'user-agent': 'nima-api', accept: 'application/vnd.github+json' };
  if (process.env.GH_TOKEN) H.authorization = 'Bearer ' + process.env.GH_TOKEN;
  const r = await fetch('https://api.github.com/repos/Nikatchubabria/nima-studio-download/releases/latest', { headers: H });
  if (!r.ok) { if (c && c.yml) return c.yml; throw new Error('github ' + r.status); }
  const rel = await r.json(), A = rel.assets || [];
  const ya = A.find(a => a.name === 'latest.yml'), pa = A.find(a => /\.nsis\.7z$/.test(a.name));
  if (!ya || !pa) { if (c && c.yml) return c.yml; throw new Error('release incomplete'); }
  const y = await fetch(ya.url, { headers: Object.assign({}, H, { accept: 'application/octet-stream' }) });
  if (!y.ok) { if (c && c.yml) return c.yml; throw new Error('yml ' + y.status); }
  let yml = await y.text();
  if (!/^version:\s*\S+/m.test(yml)) throw new Error('bad yml');
  await st.setJSON('upd/cache', { ts: Date.now(), yml }).catch(() => {});
  return yml;
}

export default async (req, context) => {
  try {
    const u = new URL(req.url), M = req.method;
    let p = u.pathname.replace(/^\/\.netlify\/functions\/api/, '') || '/';
    { const mm = M === 'GET' && p.match(/^\/api\/update\/(nima-studio-(\d+\.\d+\.\d+)-x64\.nsis\.7z)$/); if (mm) return new Response(null, { status: 302, headers: { location: 'https://github.com/Nikatchubabria/nima-studio-download/releases/download/v' + mm[2] + '/' + mm[1], 'cache-control': 'no-store' } }); }
    if (M === 'GET' && /^\/api\/update\/.*\.blockmap$/.test(p)) return RF(404, 'no blockmap');
    if (M === 'GET' && p === '/api/update/latest.yml') { try { return new Response(await updateFeed(), { status: 200, headers: { 'content-type': 'text/yaml; charset=utf-8', 'cache-control': 'public, max-age=60' } }); } catch (e) { return RF(502, 'update feed unavailable'); } }
    if (M === 'POST' && p === '/api/duel/relay') { const len0 = +req.headers.get('content-length') || 0; if (len0 > 40000) return RF(413, 'too large'); return await duelRelay((await req.text()).slice(0, 40000), (context && context.ip) || String(req.headers.get('x-nf-client-connection-ip') || '')); }
    if (M === 'POST') { const len = +req.headers.get('content-length') || 0; if (len > 1e6) return new Response(JSON.stringify({ ok: false, error: 'too large' }), { status: 413 }); }
    const raw = M === 'POST' ? (await req.text()).slice(0, 1e6) : '';
    const c = { M, p, origin: u.origin, q: u.searchParams, raw, h: n => String(req.headers.get(n) || ''), ip: (context && context.ip) || String(req.headers.get('x-nf-client-connection-ip') || req.headers.get('x-forwarded-for') || '').split(',')[0].trim() };
    const keys = await getKeys(), s = store();
    for (let attempt = 0; attempt < 6; attempt++) {
      const r = await s.getWithMetadata('db', { type: 'json' });
      const db = Object.assign({ users: {}, sessions: {}, nextId: 1, gpend: {} }, r ? r.data : {});
      db.gpend = db.gpend || {};
      const S = { db, keys, dirty: false }, out = await route(c, S);
      if (S.dirty) {
        const w = r ? await s.setJSON('db', db, { onlyIfMatch: r.etag }) : await s.setJSON('db', db, { onlyIfNew: true });
        if (w && w.modified === false) { await new Promise(z => setTimeout(z, 30 + Math.random() * 120)); continue; }   // somebody else wrote first: redo on fresh data
      }
      const headers = Object.assign({ 'content-type': out.type || 'application/json', 'cache-control': 'no-store' }, out.headers || {});
      return new Response(out.body, { status: out.code, headers });
    }
    return new Response(JSON.stringify({ ok: false, error: 'busy, try again' }), { status: 503, headers: { 'content-type': 'application/json' } });
  } catch (e) {
    console.error('error', e && e.stack || e);
    return new Response(JSON.stringify({ ok: false, error: 'server error' }), { status: 500, headers: { 'content-type': 'application/json' } });
  }
};

export const config = { path: ['/api/*', '/admin', '/health'] };
