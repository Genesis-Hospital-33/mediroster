// Tiny wrapper around Netlify Blobs (the online storage that comes with every Netlify site).
import { getStore } from '@netlify/blobs';
const open = () => getStore({ name: 'mediroster', consistency: 'strong' });
export const kv = {
  get: (key) => open().get(key, { type: 'json' }),
  set: (key, val) => open().setJSON(key, val),
  del: (key) => open().delete(key),
  list: async (prefix) => ((await open().list({ prefix })).blobs || []).map((b) => b.key),
};
