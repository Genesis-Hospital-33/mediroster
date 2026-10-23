// The MediRoster server. Every button in the app talks to this one function.
import { handle } from '../lib/core.mjs';
import { kv } from '../lib/kv.mjs';

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });

export default async (req, context) => {
  if (req.method !== 'POST') return json({ error: 'Method not allowed' }, 405);
  const origin = new URL(req.url).origin;
  const from = req.headers.get('origin');
  if (from && from !== origin) return json({ error: 'Origin not allowed' }, 403);
  let body;
  try { body = await req.json(); } catch (e) { return json({ error: 'Invalid request' }, 400); }
  const res = await handle({ kv, env: process.env, origin }, body);
  return json(res.body, res.status);
};
