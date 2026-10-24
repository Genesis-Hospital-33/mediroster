// MediRoster server logic: accounts, permissions, roster, attendance, email.
// Storage layout (Netlify Blobs), built so many people can use it at once without overwriting each other:
//   cfg                      departments, shift templates, hospital zone      (Master only writes)
//   staff                    list of all staff (no passcodes)                 (Master only writes)
//   acct/<id>                passcode hash, temp passcode, flags, lockout     (one per person)
//   pend/<id>                one marker per pending passcode-reset request
//   onb/<id>                 one marker per queued welcome email (bulk import)
//   roster/<monday>/<0-f>    shifts for one week, split into 16 parts
//   att/<date>/<id>/<hhmm>/<metres>   one record per clock-in (details live in the key name)
//   attp/<id>/<date>/<hhmm>/<metres>  same, for each person's own history
//   sent/<date>              which reminder emails were already sent
//   logs, maillog            activity logs (newest first, capped)
import { scryptSync, randomBytes, randomInt, timingSafeEqual, createHash, createHmac } from 'node:crypto';

export const MASTER_ID = 'EMP-2026-M01';
class HttpError extends Error { constructor(status, message) { super(message); this.status = status; } }
const fail = (status, message) => { throw new HttpError(status, message); };

/* ---------- passwords and session tokens ---------- */
const hashPass = (p) => { const s = randomBytes(16).toString('hex'); return s + ':' + scryptSync(p, s, 32).toString('hex'); };
const verifyPass = (p, h) => {
  try { const [s, x] = String(h).split(':'); const a = scryptSync(p, s, 32), b = Buffer.from(x, 'hex'); return a.length === b.length && timingSafeEqual(a, b); }
  catch (e) { return false; }
};
const sha = (v) => createHash('sha256').update(String(v)).digest();
const safeEq = (a, b) => timingSafeEqual(sha(a), sha(b));
const strong = (x) => typeof x === 'string' && x.length >= 8 && x.length <= 64 && /[A-Za-z]/.test(x) && /\d/.test(x);
function tempPass() {
  const L = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz', D = '23456789', A = L + D;
  const c = [L[randomInt(L.length)], D[randomInt(D.length)]];
  while (c.length < 8) c.push(A[randomInt(A.length)]);
  for (let i = 7; i > 0; i--) { const j = randomInt(i + 1); [c[i], c[j]] = [c[j], c[i]]; }
  return c.join('');
}
const zoneOf = (env) => { const z = String(env.TIMEZONE || '').trim(); try { new Intl.DateTimeFormat('en-GB', { timeZone: z }); return z; } catch (e) { return 'Asia/Kolkata'; } };
const goodUrl = (u) => { const t = String(u || '').trim().replace(/\/+$/, ''); return /^https?:\/\/[^\s]+$/.test(t) ? t : ''; };
const SESSION_HOURS = 12;
const key = (env) => sha('mediroster|' + (env.SESSION_SECRET || '') + '|' + (env.MASTER_PASSCODE || ''));
const sign = (env, uid) => { const p = uid + '|' + (Date.now() + SESSION_HOURS * 3600e3); return Buffer.from(p).toString('base64url') + '.' + createHmac('sha256', key(env)).update(p).digest('hex'); };
function unsign(env, tk) {
  try {
    const [b, mac] = String(tk).split('.'); const p = Buffer.from(b, 'base64url').toString();
    const good = createHmac('sha256', key(env)).update(p).digest('hex');
    if (mac.length !== good.length || !timingSafeEqual(Buffer.from(mac), Buffer.from(good))) return null;
    const [uid, exp] = p.split('|'); return Number(exp) > Date.now() ? uid : null;
  } catch (e) { return null; }
}

/* ---------- email: Gmail (no domain needed) or Resend (needs a verified domain) ---------- */
export async function sendMail(env, to, subject, text) {
  if (env.GMAIL_USER && env.GMAIL_APP_PASSWORD) {
    try {
      const { default: nodemailer } = await import('nodemailer');
      const tr = nodemailer.createTransport({
        host: 'smtp.gmail.com', port: 465, secure: true, connectionTimeout: 8000, socketTimeout: 8000,
        auth: { user: env.GMAIL_USER, pass: String(env.GMAIL_APP_PASSWORD).replace(/\s+/g, '') },
      });
      await tr.sendMail({ from: `${env.EMAIL_FROM_NAME || 'MediRoster'} <${env.GMAIL_USER}>`, to, subject, text });
      return { ok: true, status: 200 };
    } catch (e) { return { ok: false, status: String(e.responseCode || e.code || e.message).slice(0, 80) }; }
  }
  if (!env.RESEND_API_KEY) return { ok: false, status: 'no email service configured' };
  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + env.RESEND_API_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: env.EMAIL_FROM || 'MediRoster <onboarding@resend.dev>', to: [to], subject, text }),
    });
    return { ok: r.ok, status: r.status };
  } catch (e) { return { ok: false, status: e.message }; }
}
const onboardText = (site, id, pw) => `Welcome to MediRoster. Your official hospital staff account has been provisioned. Please click this link to set up your profile: ${site}. Use your temporary credentials to log in: Staff ID: ${id}, Temporary Passcode: ${pw}.\n\nTo copy your credentials, press and hold a line below, then choose Copy:\n\nStaff ID:\n${id}\n\nTemporary Passcode:\n${pw}` + (site ? `\n\nQuick sign-in (fills in both for you): ${site}/#u=${id}&p=${pw}` : '');
const SOON_TEXT = 'Reminder: Your shift is about to start in about 30 minutes. Please get ready and make sure you are logged into your dashboard so you can clock in via the designated hospital geofence.';
const START_TEXT = 'Your shift has started. Please ensure you are logged into your dashboard and have clocked in via the designated hospital geofence.';

/* ---------- small helpers ---------- */
const asList = (v) => (Array.isArray(v) ? v : v ? [v] : []);
const clean = (x, max) => String(x == null ? '' : x).trim().slice(0, max);
const ymd = (ms) => new Date(ms).toISOString().slice(0, 10);
const validDate = (d) => /^\d{4}-\d{2}-\d{2}$/.test(d) && !isNaN(Date.parse(d + 'T00:00:00Z'));
const mondayOf = (d) => { const t = Date.parse(d + 'T00:00:00Z'); return ymd(t - ((new Date(t).getUTCDay() + 6) % 7) * 864e5); };
const shardOf = (id) => { let h = 0; for (const c of String(id)) h = (h * 31 + c.charCodeAt(0)) >>> 0; return (h % 16).toString(16); };
const SHARDS = '0123456789abcdef'.split('');
function wall(date, tz) {
  const f = new Intl.DateTimeFormat('en-CA', { timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' });
  const o = {}; f.formatToParts(date).forEach((p) => { o[p.type] = p.value; });
  return { y: +o.year, m: +o.month, d: +o.day, h: +o.hour, mi: +o.minute };
}
const todayIn = (tz, at = new Date()) => { const w = wall(at, tz); return ymd(Date.UTC(w.y, w.m - 1, w.d)); };
const stamp = (tz, at = new Date()) => at.toLocaleString('en-GB', { timeZone: tz });
function dist(a, b, c, d) {
  const R = 6371e3, r = (x) => (x * Math.PI) / 180, p = r(c - a), q = r(d - b);
  const h = Math.sin(p / 2) ** 2 + Math.cos(r(a)) * Math.cos(r(c)) * Math.sin(q / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(h));
}
const readWeek = async (kv, mon) => Object.assign({}, ...(await Promise.all(SHARDS.map((h) => kv.get('roster/' + mon + '/' + h)))).filter(Boolean));
const defaultCfg = () => ({
  depts: ['Management', 'Emergency', 'ICU', 'General Ward', 'Pharmacy'],
  tpl: [
    { id: 't1', name: 'Morning', start: '07:00', end: '15:00', color: '#0369a1' },
    { id: 't2', name: 'Evening', start: '15:00', end: '23:00', color: '#b45309' },
    { id: 't3', name: 'Night', start: '23:00', end: '07:00', color: '#4338ca' },
  ],
  zone: { name: 'City General Hospital', lat: 28.6139, lng: 77.2090, radius: 200 },
});
const masterRec = (old = {}) => ({ id: MASTER_ID, name: 'Sohail Ahmad', role: 'master', designation: old.designation == null ? 'Master Admin' : old.designation, dept: old.dept || 'Management', email: old.email || '' });
async function addLog(kv, name, who, msg, tz, cap = 300) {
  const l = (await kv.get(name)) || []; l.unshift({ ts: Date.now(), t: stamp(tz), who, msg }); await kv.set(name, l.slice(0, cap));
}
async function listAtt(kv, prefix, names) {
  const keys = await kv.list(prefix);
  return keys.map((k) => { const [, date, id, hhmm, d] = k.split('/'); return { id, name: (names.get(id) || {}).name || id, date, time: hhmm.slice(0, 2) + ':' + hhmm.slice(2), d: Number(d) }; });
}
async function listOwnAtt(kv, id, names) {
  const keys = (await kv.list('attp/' + id + '/')).sort().reverse().slice(0, 30);
  return keys.map((k) => { const [, , date, hhmm, d] = k.split('/'); return { id, name: (names.get(id) || {}).name || id, date, time: hhmm.slice(0, 2) + ':' + hhmm.slice(2), d: Number(d) }; });
}

/* ---------- the server entry point used by the app ---------- */
export async function handle({ kv, env, origin, send = sendMail }, body) {
  const tz = zoneOf(env);
  try {
    const { action, payload: p = {}, token } = body || {};
    if (!env.MASTER_PASSCODE) fail(500, 'The server is missing the MASTER_PASSCODE setting.');
    let staff = await kv.get('staff'), cfg = await kv.get('cfg');
    if (!cfg) { cfg = defaultCfg(); await kv.set('cfg', cfg); }
    if (origin && !goodUrl(env.SITE_URL) && cfg.site !== origin) { cfg.site = origin; await kv.set('cfg', cfg); }
    if (!staff) { staff = [masterRec()]; await kv.set('staff', staff); }
    const mi = staff.findIndex((s) => s.id === MASTER_ID);
    if (mi < 0) { staff.unshift(masterRec()); await kv.set('staff', staff); }
    else { const m = staff[mi], fixed = masterRec(m); if (JSON.stringify(m) !== JSON.stringify(fixed)) { staff[mi] = fixed; await kv.set('staff', staff); } }
    staff.forEach((s) => { if (s.id !== MASTER_ID && s.role === 'master') s.role = 'admin'; });
    const byId = new Map(staff.map((s) => [s.id, s]));
    const log = (who, msg) => addLog(kv, 'logs', who, msg, tz);
    const ok = (b) => ({ status: 200, body: b });
    const site = () => goodUrl(env.SITE_URL) || goodUrl(origin);

    /* ---- what each person is allowed to see ---- */
    async function state(me, week, dept) {
      const mgr = me.role !== 'worker', today = todayIn(tz);
      const mon = validDate(week) ? mondayOf(week) : mondayOf(today);
      const d = mgr ? clean(dept, 60) : (cfg.depts.includes(dept) ? dept : me.dept);
      const ids = d ? new Set(staff.filter((s) => s.dept === d).map((s) => s.id)) : null;
      let roster = await readWeek(kv, mon);
      if (ids) Object.keys(roster).forEach((k) => { if (!ids.has(k.split('|')[0])) delete roster[k]; });
      Object.keys(roster).forEach((k) => { roster[k] = asList(roster[k]); });
      const cur = mondayOf(today);
      const own = await Promise.all([-7, 0, 7, 14].map((o) => kv.get('roster/' + ymd(Date.parse(cur + 'T00:00:00Z') + o * 864e5) + '/' + shardOf(me.id))));
      own.filter(Boolean).forEach((b) => Object.keys(b).forEach((k) => { if (k.startsWith(me.id + '|')) roster[k] = asList(b[k]); }));
      const list = mgr ? staff : staff.filter((s) => s.id === me.id || ids.has(s.id));
      const out = {
        me: me.id, today, week: mon, dept: d || '', depts: cfg.depts, tpl: cfg.tpl, zone: cfg.zone, roster,
        staff: list.map((s) => ({ id: s.id, name: s.name, role: s.role, designation: s.designation || '', dept: s.dept, ...(mgr ? { email: s.email || '' } : {}) })),
      };
      if (mgr) {
        out.att = (await listAtt(kv, 'att/' + today + '/', byId)).slice(0, 500);
        out.pending = (await kv.list('pend/')).map((k) => k.slice(5)).filter((id) => byId.has(id)).map((id) => ({ id, name: byId.get(id).name }));
        await Promise.all(out.pending.map(async (x) => { const a = await kv.get('acct/' + x.id); x.resetAt = a && a.resetAt; }));
      } else out.att = await listOwnAtt(kv, me.id, byId);
      if (me.role === 'master') {
        const [lg, ml] = await Promise.all([kv.get('logs'), kv.get('maillog')]);
        out.logs = [...(lg || []), ...(ml || [])].sort((a, b) => b.ts - a.ts).slice(0, 300);
        out.mailLog = (ml || []).slice(0, 5);
      }
      return out;
    }

    const newAccount = async (rec, pw) => {
      await kv.set('acct/' + rec.id, { pass: hashPass(pw), temp: pw, setup: true, reset: false });
    };
    const nextId = (role, taken) => {
      const pre = role === 'admin' ? 'A' : 'W', re = new RegExp('^EMP-2026-' + pre + '(\\d+)$'); let n = 0;
      staff.concat(taken || []).forEach((s) => { const x = re.exec(s.id); if (x) n = Math.max(n, +x[1]); });
      return 'EMP-2026-' + pre + String(n + 1).padStart(2, '0');
    };
    const checkStaffInput = (r) => {
      const name = clean(r.name, 80), email = clean(r.email, 200).toLowerCase(), role = r.role;
      if (!name) return 'Enter the full name.';
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return 'Enter a valid email address.';
      if (!['admin', 'worker'].includes(role)) return 'Choose Admin or Worker.';
      return '';
    };

    /* ---- actions that work before signing in ---- */
    if (action === 'login') {
      const id = clean(p.id, 40).toUpperCase(), pw = String(p.pass || '').slice(0, 100), s = byId.get(id);
      if (!s) fail(401, 'Invalid Staff ID or passcode.');
      const a = (await kv.get('acct/' + id)) || (s.role === 'master' ? {} : null);
      if (!a) fail(401, 'Invalid Staff ID or passcode.');
      if ((a.until || 0) > Date.now()) fail(429, 'Too many failed attempts. Please try again in 15 minutes.');
      if (a.reset) fail(403, 'Your reset request is awaiting approval. You cannot log in until a System Admin or Master Admin approves it.');
      const good = s.role === 'master' ? safeEq(pw, env.MASTER_PASSCODE) : !!a.pass && verifyPass(pw, a.pass);
      if (!good) { a.n = (a.n || 0) + 1; if (a.n >= 5) { a.until = Date.now() + 15 * 60e3; a.n = 0; } await kv.set('acct/' + id, a); fail(401, 'Invalid Staff ID or passcode.'); }
      if (a.n || a.until) { a.n = 0; a.until = 0; await kv.set('acct/' + id, a); }
      if (a.setup) return ok({ needsSetup: true, id: s.id, name: s.name });
      return ok({ token: sign(env, s.id), state: await state(s, p.week, p.dept) });
    }
    if (action === 'setup') {
      const id = clean(p.id, 40).toUpperCase(), s = byId.get(id), a = s && (await kv.get('acct/' + id));
      if (a && (a.until || 0) > Date.now()) fail(429, 'Too many failed attempts. Please try again in 15 minutes.');
      if (!a || !a.setup || !a.pass || !verifyPass(String(p.temp || ''), a.pass)) {
        if (a) { a.n = (a.n || 0) + 1; if (a.n >= 5) { a.until = Date.now() + 15 * 60e3; a.n = 0; } await kv.set('acct/' + id, a); }
        fail(401, 'Your temporary passcode is not valid. Please sign in again.');
      }
      if (!strong(p.newPass)) fail(400, 'Use at least 8 characters including letters and numbers.');
      if (verifyPass(p.newPass, a.pass)) fail(400, 'Choose a passcode different from the temporary one.');
      a.pass = hashPass(p.newPass); delete a.temp; a.setup = false; a.n = 0; a.until = 0;
      await kv.set('acct/' + id, a); await log(s.name, 'Completed account setup (new passcode set)');
      return ok({ token: sign(env, s.id), state: await state(s, p.week, p.dept) });
    }
    if (action === 'forgot') {
      const id = clean(p.id, 40).toUpperCase(), s = byId.get(id);
      if (s && s.role === 'master') return ok({ master: true });
      const a = s && (await kv.get('acct/' + id));
      if (a && !a.reset) { a.reset = true; a.resetAt = stamp(tz); await kv.set('acct/' + id, a); await kv.set('pend/' + id, { at: Date.now() }); await log(s.name, 'Passcode reset requested (' + s.id + ')'); }
      return ok({ ok: true });
    }

    /* ---- everything below needs a valid session ---- */
    const uid = token ? unsign(env, token) : null, me = uid && byId.get(uid);
    if (!me) fail(401, 'Your session expired. Please sign in again.');
    if (me.role !== 'master') { const a = await kv.get('acct/' + me.id); if (!a || a.reset || a.setup) fail(401, 'Your session expired. Please sign in again.'); }
    const isMaster = me.role === 'master', isMgr = me.role !== 'worker';
    const needMaster = () => { if (!isMaster) fail(403, 'Only the Master Admin can do that.'); };
    const needMgr = () => { if (!isMgr) fail(403, 'You do not have permission to do that.'); };
    const find = (id) => byId.get(clean(id, 40)) || fail(404, 'Staff member not found.');
    const reply = async (extra = {}) => ok({ ...extra, state: await state(me, p.week, p.dept) });
    const saveStaff = () => kv.set('staff', staff);
    const saveCfg = () => kv.set('cfg', cfg);

    switch (action) {
      case 'state': return reply();
      case 'logout': return ok({ ok: true });
      case 'assign': {
        needMgr(); const s = find(p.sid), dt = clean(p.dt, 10);
        if (!validDate(dt)) fail(400, 'Invalid date.');
        const want = [...new Set((Array.isArray(p.tids) ? p.tids : p.tid ? [p.tid] : []).map(String))].slice(0, 8);
        const chosen = cfg.tpl.filter((t) => want.includes(t.id)).sort((x, y) => x.start.localeCompare(y.start));
        if (chosen.length !== want.length) fail(400, 'Unknown shift.');
        const k = 'roster/' + mondayOf(dt) + '/' + shardOf(s.id), part = (await kv.get(k)) || {};
        if (chosen.length) part[s.id + '|' + dt] = chosen.map((t) => t.id); else delete part[s.id + '|' + dt];
        await kv.set(k, part);
        return ok({ ok: true });
      }
      case 'setDes': { needMaster(); const s = find(p.id); s.designation = clean(p.v, 60); await saveStaff(); await log(me.name, `Designation for ${s.name} set to "${s.designation || '(none)'}"`); return reply(); }
      case 'setRole': {
        needMaster(); const s = find(p.id);
        if (s.role === 'master' || !['admin', 'worker'].includes(p.r)) fail(400, 'That change is not allowed.');
        s.role = p.r; await saveStaff(); await log(me.name, `Changed ${s.name} to ${s.role}`); return reply();
      }
      case 'addStaff': {
        needMaster(); const bad = checkStaffInput(p); if (bad) fail(400, bad);
        const rec = { id: nextId(p.role), name: clean(p.name, 80), role: p.role, designation: clean(p.designation, 60), dept: cfg.depts.includes(p.dept) ? p.dept : (cfg.depts[0] || ''), email: clean(p.email, 200).toLowerCase() };
        const pw = tempPass(); staff.push(rec); await newAccount(rec, pw); await saveStaff();
        await log(me.name, `Added staff ${rec.name} (${rec.id}, ${rec.role})`);
        const r = await send(env, rec.email, 'Welcome to MediRoster', onboardText(site(), rec.id, pw));
        await addLog(kv, 'maillog', 'System', r.ok ? `📧 Automated email dispatched to: ${rec.email} for Account Onboarding.` : `⚠ Onboarding email to ${rec.email} failed (${r.status}). Share the temporary passcode manually (see Staff tab).`, tz, 100);
        return reply({ emailed: r.ok });
      }
      case 'bulkAdd': {
        needMaster(); const rows = Array.isArray(p.rows) ? p.rows.slice(0, 200) : [], added = [], skipped = [];
        for (const r of rows) {
          const bad = checkStaffInput(r); if (bad) { skipped.push(`${clean(r.name, 40) || '(blank)'}: ${bad}`); continue; }
          const rec = { id: nextId(r.role, added), name: clean(r.name, 80), role: r.role, designation: clean(r.designation, 60), dept: cfg.depts.includes(r.dept) ? r.dept : (cfg.depts[0] || ''), email: clean(r.email, 200).toLowerCase() };
          added.push(rec);
        }
        await Promise.all(added.map(async (rec) => { const pw = tempPass(); await newAccount(rec, pw); await kv.set('onb/' + rec.id, { at: Date.now() }); }));
        staff.push(...added); await saveStaff();
        await log(me.name, `Bulk-added ${added.length} staff (welcome emails queued)`);
        return reply({ added: added.length, skipped });
      }
      case 'delStaff': {
        needMaster(); const s = find(p.id);
        if (s.role === 'master') fail(400, 'The Master Admin cannot be removed.');
        staff = staff.filter((x) => x.id !== s.id); await saveStaff();
        await Promise.all([kv.del('acct/' + s.id), kv.del('pend/' + s.id), kv.del('onb/' + s.id)]);
        await log(me.name, `Removed staff ${s.name}`); return reply();
      }
      case 'addDept': { needMaster(); const n = clean(p.name, 60); if (!n || cfg.depts.includes(n)) fail(400, 'Enter a unique name.'); cfg.depts.push(n); await saveCfg(); await log(me.name, 'Created department ' + n); return reply(); }
      case 'delDept': { needMaster(); const n = clean(p.name, 60); cfg.depts = cfg.depts.filter((d) => d !== n); await saveCfg(); await log(me.name, 'Deleted department ' + n); return reply(); }
      case 'addTpl': {
        needMaster(); const name = clean(p.name, 40);
        if (!name || !/^\d{2}:\d{2}$/.test(p.start) || !/^\d{2}:\d{2}$/.test(p.end) || !/^#[0-9a-fA-F]{6}$/.test(p.color)) fail(400, 'Enter a name, start time and end time.');
        cfg.tpl.push({ id: 't' + Date.now(), name, start: p.start, end: p.end, color: p.color }); await saveCfg(); await log(me.name, 'Added shift template ' + name); return reply();
      }
      case 'delTpl': {
        needMaster(); const t = cfg.tpl.find((x) => x.id === p.id) || fail(404, 'Shift template not found.');
        cfg.tpl = cfg.tpl.filter((x) => x !== t); await saveCfg(); await log(me.name, 'Deleted shift template ' + t.name); return reply();
      }
      case 'saveZone': {
        needMaster(); const lat = Number(p.lat), lng = Number(p.lng), radius = parseInt(p.radius, 10);
        if (!(lat >= -90 && lat <= 90 && lng >= -180 && lng <= 180) || !(radius >= 10 && radius <= 5000)) fail(400, 'Enter valid coordinates and a radius of 10 to 5000 metres.');
        cfg.zone = { name: clean(p.name, 80) || 'Hospital', lat, lng, radius }; await saveCfg(); await log(me.name, 'Updated hospital zone'); return reply();
      }
      case 'approve': {
        needMgr(); const s = find(p.id), a = await kv.get('acct/' + s.id);
        if (s.role === 'master' || s.id === me.id || !a || !a.reset) fail(400, 'That request cannot be approved.');
        const pw = tempPass(); Object.assign(a, { pass: hashPass(pw), temp: pw, setup: true, reset: false, n: 0, until: 0 }); delete a.resetAt;
        await kv.set('acct/' + s.id, a); await kv.del('pend/' + s.id);
        await log(me.name, `Approved passcode reset for ${s.name} (${s.id})`); return reply({ temp: pw });
      }
      case 'staffStatus': {
        needMgr(); const ids = (Array.isArray(p.ids) ? p.ids : []).slice(0, 60).map((x) => clean(x, 40)).filter((x) => byId.has(x)), out = {};
        await Promise.all(ids.map(async (id) => { const a = (await kv.get('acct/' + id)) || {}; out[id] = { setup: !!a.setup, reset: !!a.reset, ...(isMaster && a.setup && a.temp ? { temp: a.temp } : {}) }; }));
        return ok({ status: out });
      }
      case 'attDay': {
        needMgr(); const d = clean(p.date, 10); if (!validDate(d)) fail(400, 'Invalid date.');
        return ok({ rows: (await listAtt(kv, 'att/' + d + '/', byId)).slice(0, 2000) });
      }
      case 'clockIn': {
        const lat = Number(p.lat), lng = Number(p.lng);
        if (!Number.isFinite(lat) || !Number.isFinite(lng)) fail(400, 'Your location could not be read.');
        const d = Math.round(dist(lat, lng, cfg.zone.lat, cfg.zone.lng));
        if (d > cfg.zone.radius) fail(403, `You are ${d} m from the hospital zone. Move within ${cfg.zone.radius} m to clock in.`);
        const w = wall(new Date(), tz), date = ymd(Date.UTC(w.y, w.m - 1, w.d)), hhmm = String(w.h).padStart(2, '0') + String(w.mi).padStart(2, '0');
        if ((await kv.list('attp/' + me.id + '/' + date + '/')).length) fail(409, 'You have already clocked in today.');
        await Promise.all([kv.set(`attp/${me.id}/${date}/${hhmm}/${d}`, 1), kv.set(`att/${date}/${me.id}/${hhmm}/${d}`, 1)]);
        return reply();
      }
      default: fail(400, 'Unknown request.');
    }
  } catch (e) {
    if (e instanceof HttpError) return { status: e.status, body: { error: e.message } };
    console.error('MediRoster server error:', e && e.message);
    return { status: 500, body: { error: 'Something went wrong on the server. Please try again.' } };
  }
}

/* ---------- automatic emails (called every 5 minutes) ---------- */
export async function runReminders({ kv, env, send = sendMail, at = new Date(), budgetMs = 20000 }) {
  const t0 = Date.now(), tz = zoneOf(env);
  const [staff, cfg] = await Promise.all([kv.get('staff'), kv.get('cfg')]);
  if (!staff || !cfg) return { sent: 0, due: 0, onboard: 0 };
  const w = wall(at, tz), base = Date.UTC(w.y, w.m - 1, w.d), nowWall = Date.UTC(w.y, w.m - 1, w.d, w.h, w.mi);
  const dates = [-1, 0, 1].map((o) => ymd(base + o * 864e5)), weeks = [...new Set(dates.map(mondayOf))];
  const roster = Object.assign({}, ...(await Promise.all(weeks.map((m) => readWeek(kv, m)))));
  const sentMap = {}; await Promise.all(dates.map(async (d) => { sentMap[d] = (await kv.get('sent/' + d)) || {}; }));
  const tplById = new Map(cfg.tpl.map((t) => [t.id, t])), due = [];
  for (const s of staff) for (const date of dates) for (const tid of asList(roster[s.id + '|' + date])) {
    const t = tplById.get(tid); if (!t) continue;
    const [sh, sm] = t.start.split(':').map(Number), [y, m, d] = date.split('-').map(Number), diff = nowWall - Date.UTC(y, m - 1, d, sh, sm);
    const stage = diff >= -30 * 6e4 && diff < -20 * 6e4 ? 'soon' : diff >= 0 && diff < 15 * 6e4 ? 'start' : null;
    if (!stage) continue;
    const k = `${s.id}|${date}|${t.id}|${stage}`; if (sentMap[date][k]) continue;
    due.push({ s, date, stage, k });
  }
  const logs = []; let sent = 0;
  const entry = (msg) => logs.push({ ts: Date.now(), t: stamp(tz, at), who: 'System', msg });
  for (let i = 0; i < due.length && Date.now() - t0 < budgetMs; i += 8) {
    await Promise.all(due.slice(i, i + 8).map(async ({ s, date, stage, k }) => {
      sentMap[date][k] = Date.now();
      const what = stage === 'soon' ? '30-Minute Shift Reminder' : 'Shift Start';
      if (!s.email) return entry(`⚠ ${what} email skipped for ${s.name} (no email on file).`);
      const r = await send(env, s.email, stage === 'soon' ? 'Your shift starts in about 30 minutes' : 'Your shift has started', stage === 'soon' ? SOON_TEXT : START_TEXT);
      if (r.ok) sent++;
      entry(r.ok ? `📧 Automated email dispatched to: ${s.email} for ${what}.` : `⚠ ${what} email to ${s.email} failed (${r.status}).`);
    }));
  }
  await Promise.all(dates.map((d) => kv.set('sent/' + d, sentMap[d])));
  kv.del('sent/' + ymd(base - 4 * 864e5)).catch(() => {});
  /* welcome emails queued by bulk import: 20 per run keeps Gmail within its daily limit */
  let onboard = 0; const queue = (await kv.list('onb/')).slice(0, 20), site = goodUrl(env.SITE_URL) || goodUrl(cfg.site);
  for (let i = 0; i < queue.length && Date.now() - t0 < budgetMs + 5000; i += 5) {
    await Promise.all(queue.slice(i, i + 5).map(async (qk) => {
      const id = qk.slice(4), s = staff.find((x) => x.id === id), a = s && (await kv.get('acct/' + id));
      await kv.del(qk);
      if (!s || !a || !a.setup || !a.temp) return;
      const r = await send(env, s.email, 'Welcome to MediRoster', onboardText(site, s.id, a.temp));
      if (r.ok) onboard++;
      entry(r.ok ? `📧 Automated email dispatched to: ${s.email} for Account Onboarding.` : `⚠ Onboarding email to ${s.email} failed (${r.status}). Share the temporary passcode manually (see Staff tab).`);
    }));
  }
  if (logs.length) { const ml = (await kv.get('maillog')) || []; await kv.set('maillog', [...logs.reverse(), ...ml].slice(0, 100)); }
  return { sent, due: due.length, onboard };
}
