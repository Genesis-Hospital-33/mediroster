// Runs by itself every 5 minutes (no browser needed) and sends the shift emails.
import { runReminders } from '../lib/core.mjs';
import { kv } from '../lib/kv.mjs';

export default async () => {
  const r = await runReminders({ kv, env: process.env });
  console.log('shift-emails run:', JSON.stringify(r));
};

export const config = { schedule: '*/5 * * * *' };
