// netlify/functions/manuals.mjs
//
// 📚 Handleidings / Manuals -- stores caravan & program manuals (PDFs,
// videos, pictures) and video links in Netlify Blobs, so they are the same
// on every phone, tablet and computer you log in on.
//
// Files are stored in 3 MB pieces ("chunks") because a Netlify function can
// only receive/send about 6 MB per request. The app uploads a file piece by
// piece and downloads it piece by piece, then glues it back together and
// keeps a copy on the device so it doesn't have to download it again.
//
// Every request needs a valid Firebase login (same check as the AI
// function), so strangers can't read, upload or delete anything.
//
// Endpoints (all at /api/manuals?op=...):
//   GET  op=list                    -> { items:[...] }
//   POST op=create  {title,cat,name,mime,size} -> { id, chunks, chunkSize }
//   PUT  op=chunk&id=..&n=..  (raw bytes)       -> { ok }
//   POST op=finish&id=..                        -> { item }
//   GET  op=chunk&id=..&n=..                    -> raw bytes
//   POST op=link    {title,cat,url}             -> { item }
//   POST op=delete&id=..                        -> { ok }

import { getStore } from '@netlify/blobs';

const FIREBASE_PROJECT_ID = 'nayela-camping';
const GOOGLE_JWKS_URL = 'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';
export const CHUNK_SIZE = 3 * 1024 * 1024;          // 3 MB
const MAX_FILE = 1024 * 1024 * 1024;                 // 1 GB per file
const CATS = ['caravan', 'program'];
const STALE_UPLOAD_MS = 24 * 60 * 60 * 1000;         // unfinished uploads older than a day are cleaned up

let jwksCache = null, jwksExpiry = 0;

function json(status, obj) {
  return new Response(JSON.stringify(obj), {
    status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }
  });
}
function b64urlToBytes(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return new Uint8Array(Buffer.from(str, 'base64'));
}
function b64urlToJson(str) { return JSON.parse(Buffer.from(b64urlToBytes(str)).toString('utf8')); }

async function getGoogleJwks() {
  const now = Date.now();
  if (jwksCache && now < jwksExpiry) return jwksCache;
  const resp = await fetch(GOOGLE_JWKS_URL);
  if (!resp.ok) throw new Error('Could not fetch Google public keys');
  const data = await resp.json();
  jwksCache = {};
  for (const k of (data.keys || [])) jwksCache[k.kid] = k;
  jwksExpiry = now + 60 * 60 * 1000;
  return jwksCache;
}

export async function verifyFirebaseIdToken(idToken) {
  const parts = String(idToken || '').split('.');
  if (parts.length !== 3) throw new Error('Malformed token');
  const header = b64urlToJson(parts[0]);
  const payload = b64urlToJson(parts[1]);
  if (header.alg !== 'RS256') throw new Error('Unexpected token algorithm');
  const jwk = (await getGoogleJwks())[header.kid];
  if (!jwk) throw new Error('Unknown signing key');
  const key = await crypto.subtle.importKey('jwk', { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: 'RS256', ext: true },
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64urlToBytes(parts[2]),
    new TextEncoder().encode(parts[0] + '.' + parts[1]));
  if (!ok) throw new Error('Invalid token signature');
  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== 'number' || payload.exp < now) throw new Error('Token expired');
  if (payload.aud !== FIREBASE_PROJECT_ID) throw new Error('Wrong audience');
  if (payload.iss !== 'https://securetoken.google.com/' + FIREBASE_PROJECT_ID) throw new Error('Wrong issuer');
  if (!payload.sub) throw new Error('No subject');
  return payload;
}

const store = () => getStore({ name: 'manuals', consistency: 'strong' });
async function readIndex(s) {
  const idx = await s.get('index', { type: 'json' });
  return (idx && Array.isArray(idx.items)) ? idx : { items: [] };
}
const writeIndex = (s, idx) => s.setJSON('index', idx);
const chunkKey = (id, n) => 'f/' + id + '/' + n;
const cleanText = (v, max) => String(v == null ? '' : v).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, max);
const newId = () => Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 10);
const publicItem = (it) => {
  const o = { ...it }; delete o.byUid; return o;
};

async function deleteChunks(s, id) {
  const { blobs } = await s.list({ prefix: 'f/' + id + '/' });
  for (const b of blobs) await s.delete(b.key);
}

export default async (req, context) => {
  const url = new URL(req.url);
  const op = url.searchParams.get('op') || '';

  const auth = req.headers.get('authorization') || '';
  if (!auth.toLowerCase().startsWith('bearer ')) return json(401, { error: 'Please log in first.' });
  let user;
  try { user = await verifyFirebaseIdToken(auth.slice(7).trim()); }
  catch (e) { return json(401, { error: 'Your login has expired. Please log in again.' }); }

  const s = store();
  try {
    if (op === 'list' && req.method === 'GET') {
      const idx = await readIndex(s);
      return json(200, { items: idx.items.filter(i => i.status === 'ready').map(publicItem), chunkSize: CHUNK_SIZE });
    }

    if (op === 'create' && req.method === 'POST') {
      const b = await req.json().catch(() => ({}));
      const size = Number(b.size);
      const title = cleanText(b.title || b.name, 120);
      const cat = CATS.includes(b.cat) ? b.cat : 'caravan';
      if (!title) return json(400, { error: 'Title is required' });
      if (!(size > 0)) return json(400, { error: 'Empty file' });
      if (size > MAX_FILE) return json(413, { error: 'File is larger than 1 GB' });
      const idx = await readIndex(s);
      // tidy up uploads that were abandoned (e.g. phone lost signal)
      const now = Date.now();
      const stale = idx.items.filter(i => i.status === 'uploading' && now - (i.added || 0) > STALE_UPLOAD_MS);
      for (const st of stale) await deleteChunks(s, st.id);
      idx.items = idx.items.filter(i => !stale.includes(i));
      const item = {
        id: newId(), kind: 'file', status: 'uploading', title, cat,
        name: cleanText(b.name, 200) || 'file', mime: cleanText(b.mime, 100) || 'application/octet-stream',
        size, chunks: Math.ceil(size / CHUNK_SIZE), chunkSize: CHUNK_SIZE,
        added: now, by: cleanText(user.email, 120), byUid: user.sub
      };
      idx.items.push(item);
      await writeIndex(s, idx);
      return json(200, { id: item.id, chunks: item.chunks, chunkSize: CHUNK_SIZE });
    }

    if (op === 'chunk') {
      const id = url.searchParams.get('id') || '';
      const n = parseInt(url.searchParams.get('n'), 10);
      const idx = await readIndex(s);
      const item = idx.items.find(i => i.id === id && i.kind === 'file');
      if (!item) return json(404, { error: 'Manual not found' });
      if (!(n >= 0 && n < item.chunks)) return json(400, { error: 'Bad chunk number' });

      if (req.method === 'PUT') {
        if (item.status !== 'uploading') return json(409, { error: 'Upload already finished' });
        const buf = await req.arrayBuffer();
        const expected = (n === item.chunks - 1) ? item.size - n * CHUNK_SIZE : CHUNK_SIZE;
        if (buf.byteLength !== expected) return json(400, { error: 'Chunk ' + n + ' has wrong size (' + buf.byteLength + ' vs ' + expected + ')' });
        await s.set(chunkKey(id, n), buf);
        return json(200, { ok: true });
      }
      if (req.method === 'GET') {
        if (item.status !== 'ready') return json(409, { error: 'Upload not finished yet' });
        const data = await s.get(chunkKey(id, n), { type: 'arrayBuffer' });
        if (!data) return json(404, { error: 'Chunk missing' });
        return new Response(data, { status: 200, headers: { 'Content-Type': 'application/octet-stream', 'Cache-Control': 'private, max-age=31536000, immutable' } });
      }
    }

    if (op === 'finish' && req.method === 'POST') {
      const id = url.searchParams.get('id') || '';
      const idx = await readIndex(s);
      const item = idx.items.find(i => i.id === id && i.kind === 'file');
      if (!item) return json(404, { error: 'Manual not found' });
      const { blobs } = await s.list({ prefix: 'f/' + id + '/' });
      if (blobs.length !== item.chunks) return json(409, { error: 'Only ' + blobs.length + ' of ' + item.chunks + ' pieces arrived - please try the upload again' });
      item.status = 'ready';
      await writeIndex(s, idx);
      return json(200, { item: publicItem(item) });
    }

    if (op === 'link' && req.method === 'POST') {
      const b = await req.json().catch(() => ({}));
      const link = cleanText(b.url, 1000);
      if (!/^https?:\/\//i.test(link)) return json(400, { error: 'The link must start with https://' });
      const title = cleanText(b.title, 120) || link;
      const idx = await readIndex(s);
      const item = { id: newId(), kind: 'link', status: 'ready', title, cat: CATS.includes(b.cat) ? b.cat : 'caravan',
        url: link, added: Date.now(), by: cleanText(user.email, 120), byUid: user.sub };
      idx.items.push(item);
      await writeIndex(s, idx);
      return json(200, { item: publicItem(item) });
    }

    if (op === 'delete' && req.method === 'POST') {
      const id = url.searchParams.get('id') || '';
      const idx = await readIndex(s);
      const item = idx.items.find(i => i.id === id);
      if (!item) return json(404, { error: 'Manual not found' });
      if (item.kind === 'file') await deleteChunks(s, id);
      idx.items = idx.items.filter(i => i.id !== id);
      await writeIndex(s, idx);
      return json(200, { ok: true });
    }

    return json(400, { error: 'Unknown request' });
  } catch (e) {
    return json(500, { error: (e && e.message) || String(e) });
  }
};

export const config = { path: '/api/manuals' };
