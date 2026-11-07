// Optional backup trigger: an outside free timer service can open
//   https://YOUR-SITE.netlify.app/.netlify/functions/run-reminders?key=YOUR_CRON_SECRET
// Only works if you set CRON_SECRET in Netlify.
import { runReminders } from '../lib/core.mjs';
import { kv } from '../lib/kv.mjs';

export default async (req) => {
  const secret = process.env.CRON_SECRET;
  const key = new URL(req.url).searchParams.get('key');
  if (!secret || key !== secret) return new Response('Not allowed', { status: 403 });
  const r = await runReminders({ kv, env: process.env });
  return new Response(JSON.stringify(r), { headers: { 'Content-Type': 'application/json' } });
};
