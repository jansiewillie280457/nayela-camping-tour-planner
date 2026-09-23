// netlify/edge-functions/campsite-info.js
//
// AI campsite info (Tour Planner "Genereer met AI" / "AI Vul Alles In",
// and the Wysig modal's facilities search) -- EDGE FUNCTION version.
//
// WHY THIS REPLACES netlify/functions/campsite-info.js:
// The old version was a normal Netlify Function, which Netlify kills after
// 10 SECONDS on the free plan. Once web search was switched on, Claude has
// to run 1-3 internet searches before answering, which regularly takes
// 12-25 seconds -- so Netlify cut it off ("Task timed out") and the app just
// showed "Kon nie AI-inligting genereer nie". Edge Functions only have to
// start answering within 40 seconds, and time spent WAITING on Claude does
// not count against their limits, so the search has room to finish.
//
// Also fixed here:
//  - With web search on, Claude usually says "Ek sal eers soek..." BEFORE
//    searching. The old code glued that onto the answer, so the
//    HOOGTEPUNT line was never found and the notes started with chatter.
//    Now only the text written AFTER the last search is used, and the
//    HOOGTEPUNT/HIGHLIGHT line is found anywhere (with or without **bold**).
//  - "pause_turn" (Claude's search loop pausing mid-way) is continued
//    instead of returning a half answer.
//  - Every failure returns a clear JSON error the app can show on screen.
//
// Security is unchanged: requires a valid Firebase login, and the
// Anthropic key stays in Netlify's environment variables.

const FIREBASE_PROJECT_ID = 'nayela-camping';
const GOOGLE_JWKS_URL = 'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';

let jwksCache = null;
let jwksCacheExpiry = 0;

function json(status, obj) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }
  });
}

function b64urlToBytes(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function b64urlToJson(str) {
  return JSON.parse(new TextDecoder().decode(b64urlToBytes(str)));
}

async function getGoogleJwks() {
  const now = Date.now();
  if (jwksCache && now < jwksCacheExpiry) return jwksCache;
  const resp = await fetch(GOOGLE_JWKS_URL);
  if (!resp.ok) throw new Error('Could not fetch Google public keys');
  const data = await resp.json();
  jwksCache = {};
  for (const k of (data.keys || [])) jwksCache[k.kid] = k;
  jwksCacheExpiry = now + 60 * 60 * 1000;
  return jwksCache;
}

// Same checks as firebase-admin's verifyIdToken(): RS256 signature against
// Google's current keys, then expiry / issuer / audience / subject.
async function verifyFirebaseIdToken(idToken) {
  const parts = idToken.split('.');
  if (parts.length !== 3) throw new Error('Malformed token');
  const header = b64urlToJson(parts[0]);
  const payload = b64urlToJson(parts[1]);
  if (header.alg !== 'RS256') throw new Error('Unexpected token algorithm');

  const keys = await getGoogleJwks();
  const jwk = keys[header.kid];
  if (!jwk) throw new Error('Unknown signing key');
  const key = await crypto.subtle.importKey(
    'jwk', { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: 'RS256', ext: true },
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']
  );
  const ok = await crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5', key, b64urlToBytes(parts[2]),
    new TextEncoder().encode(parts[0] + '.' + parts[1])
  );
  if (!ok) throw new Error('Invalid token signature');

  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== 'number' || payload.exp < now) throw new Error('Token expired');
  if (typeof payload.iat !== 'number' || payload.iat > now + 300) throw new Error('Token issued in the future');
  if (payload.aud !== FIREBASE_PROJECT_ID) throw new Error('Token was not issued for this app');
  if (payload.iss !== 'https://securetoken.google.com/' + FIREBASE_PROJECT_ID) throw new Error('Unexpected token issuer');
  if (!payload.sub) throw new Error('Token missing subject');
  return payload;
}

function getApiKey() {
  try { if (typeof Netlify !== 'undefined' && Netlify.env) return Netlify.env.get('ANTHROPIC_API_KEY'); } catch (e) {}
  try { if (typeof Deno !== 'undefined') return Deno.env.get('ANTHROPIC_API_KEY'); } catch (e) {}
  return undefined;
}

// Pull the final answer out of Claude's content blocks: only the text that
// comes AFTER the last web-search result (drops "I'll search for..." lines).
export function extractAnswer(content, lang) {
  content = content || [];
  let lastSearchIdx = -1;
  let searches = 0;
  let searchError = '';
  content.forEach((b, i) => {
    if (b.type === 'web_search_tool_result') {
      lastSearchIdx = i;
      searches++;
      if (b.content && !Array.isArray(b.content) && b.content.error_code) searchError = b.content.error_code;
    }
  });
  let textBlocks = content.slice(lastSearchIdx + 1).filter(b => b.type === 'text');
  if (!textBlocks.map(b => b.text || '').join('').trim()) textBlocks = content.filter(b => b.type === 'text');
  let raw = textBlocks.map(b => b.text || '').join('').trim();

  let highlight = '';
  let text = raw;
  const re = /(?:^|\n)[ \t>#*_]*(HOOGTEPUNT|HIGHLIGHT)[ \t*_]*:[ \t*_]*([^\n]*)/i;
  const m = raw.match(re);
  if (m) {
    highlight = m[2].replace(/[*_]+/g, '').replace(/^[<"'\s]+|[>"'\s]+$/g, '').trim();
    text = raw.slice(m.index + m[0].length).trim();
    if (!text) text = raw.slice(0, m.index).trim(); // answer written before the line
  }
  text = text.replace(/^\*+|\*+$/g, '').replace(/^<|>$/g, '').trim();
  return { text, highlight, searches, searchError };
}

export default async (request, context) => {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204 });

  // ── Require a valid, current Firebase login ──────────────────────
  const authHeader = request.headers.get('authorization') || '';
  if (!authHeader.toLowerCase().startsWith('bearer ')) {
    return json(401, { error: 'Please log in to use AI generation.' });
  }
  try {
    await verifyFirebaseIdToken(authHeader.slice(7).trim());
  } catch (e) {
    return json(401, { error: 'Your login has expired. Please log in again.' });
  }

  const apiKey = getApiKey();
  if (!apiKey) {
    return json(500, { error: 'ANTHROPIC_API_KEY is not set on this Netlify site (Project configuration → Environment variables — scope must include Functions).' });
  }

  let body;
  try { body = await request.json(); } catch (e) { return json(400, { error: 'Invalid request body' }); }
  body = body || {};

  var name = (body.name || '').trim();
  var town = (body.town || '').trim();
  var province = (body.province || '').trim();
  var gps = (body.gps || '').trim();
  var lang = body.lang === 'en' ? 'en' : 'af'; // default Afrikaans, matches the app
  var mode = body.mode === 'facilities' ? 'facilities' : 'area'; // 'area' = surrounding-area info (Tour Planner), 'facilities' = the stand/site itself (Wysig campsite)

  if (!name) {
    return { statusCode: 400, body: JSON.stringify({ error: 'Missing campsite name' }) };
  }

  var whereBits = [town, province].filter(Boolean).join(', ');
  var whereForSearch = whereBits || name;
  var searchQuery = whereBits ? (name + ', ' + whereBits) : name;
  var gpsSearchQuery = gps ? (gps + ' South Africa') : '';
  var locationGuard =
    (gps ? (lang === 'en'
      ? 'IMPORTANT: the GPS coordinates ' + gps + ' are the most reliable indicator of exactly where this place is -- also run a separate search for "' + gpsSearchQuery + '" to confirm the nearest town/landmark from these coordinates, and use THAT (not just the name or town alone) as the final word on which place this is. If the name or town conflicts with the coordinates, trust the coordinates. '
      : 'BELANGRIK: die GPS-koördinate ' + gps + ' is die mees betroubare aanduiding van presies waar hierdie plek is -- doen ook \'n aparte soektog vir "' + gpsSearchQuery + '" om die naaste dorp/landmerk vanaf hierdie koördinate te bevestig, en gebruik DIT (nie net die naam of dorp alleen nie) as die finale beslissing oor watter plek dit is. As die naam of dorp met die koördinate bots, vertrou die koördinate. ') : '') +
    (whereBits ? (lang === 'en'
      ? 'IMPORTANT: search for this specific place IN ' + whereBits + ' -- there may be other places with a similar name elsewhere in the country, do not confuse them. '
      : 'BELANGRIK: soek na hierdie spesifieke plek IN ' + whereBits + ' -- daar mag dalk ander plekke met \'n soortgelyke naam elders in die land wees, moenie dié verwar nie. ') : '');

  var prompt;

  if (mode === 'facilities') {
    // Wysig / edit-campsite modal: what the STAND/SITE itself is like,
    // not the surrounding tourist area -- no highlight line needed here,
    // this just goes straight into the plain Aantekeninge notes box.
    var promptFacAf =
      'Doen \'n vinnige internetsoektog vir "' + searchQuery + '" om inligting te vind oor die kampeerterrein "' + name + '"' +
      (whereBits ? ' naby ' + whereBits : '') + (gps ? ' (GPS-koördinate: ' + gps + ')' : '') +
      ' in Suid-Afrika (of die omliggende streek/land) se GERIEWE EN STANDPLEKKE self -- nie die omliggende toeriste-omgewing nie. ' +
      locationGuard +
      'Soek spesifiek na (indien beskikbaar): tipe standplekke (gras/sand/teer/gruis), elektrisiteitspunte by die stand, waterpunte, ablusie-geriewe (skoon/warm water), skaduwee (bome/oop), braai-geriewe, of troeteldiere toegelaat word, WiFi, aanlyn winkel of restaurant op die perseel, sekuriteit (omheining/wag), en of dit rystoel-toeganklik is. ' +
      'Skryf ongeveer 120-150 woorde praktiese, feitelike inligting oor hierdie geriewe, in vloeiende paragraaf-teks (geen opskrifte of kolpunte nie). Moenie \'n opsomming van die omliggende toerisme-area gee nie -- fokus op die kampeerterrein se eie fasiliteite. ' +
      'As die internetsoektog geen betroubare, spesifieke inligting oor hierdie presiese plek se geriewe oplewer nie, sê eerlik dat spesifieke geriewe-inligting nie beskikbaar was nie, eerder as om besonderhede te verzin.';

    var promptFacEn =
      'Do a quick web search for "' + searchQuery + '" to find information about the campsite "' + name + '"' +
      (whereBits ? ' near ' + whereBits : '') + (gps ? ' (GPS coordinates: ' + gps + ')' : '') +
      ' in South Africa (or the surrounding region/country)\'s OWN FACILITIES AND STANDS -- not the surrounding tourist area. ' +
      locationGuard +
      'Search specifically for (where available): type of stands (grass/sand/tar/gravel), power points at the stand, water points, ablution facilities (clean/hot water), shade (trees/open), braai facilities, whether pets are allowed, WiFi, an on-site shop or restaurant, security (fencing/guard), and wheelchair accessibility. ' +
      'Write about 120-150 words of practical, factual information about these facilities, in flowing paragraph text (no headings or bullet points). Do not summarise the surrounding tourist area -- focus on the campsite\'s own facilities. ' +
      'If the web search turns up no reliable, specific information about this exact place\'s facilities, say honestly that specific facilities information wasn\'t available, rather than inventing details.';

    prompt = lang === 'en' ? promptFacEn : promptFacAf;
  } else {

  var promptAf =
    'Doen \'n vinnige internetsoektog vir "' + searchQuery + '" om te bevestig wat die kampeerterrein "' + name + '"' +
    (whereBits ? ' naby ' + whereBits : '') + (gps ? ' (GPS-koördinate: ' + gps + ')' : '') +
    ' in Suid-Afrika (of die omliggende streek/land) se omgewing werklik bekend maak. ' +
    (gps ? 'BELANGRIK: die GPS-koördinate ' + gps + ' is die mees betroubare aanduiding van presies waar hierdie plek is -- doen ook \'n aparte soektog vir "' + gpsSearchQuery + '" om die naaste dorp/landmerk vanaf hierdie koördinate te bevestig, en gebruik DIT (nie net die naam of dorp alleen nie) as die finale beslissing oor watter omgewing beskryf moet word. As die naam of dorp met die koördinate bots, vertrou die koördinate. ' : '') +
    (whereBits ? 'BELANGRIK: soek na hierdie spesifieke plek IN ' + whereBits + ' -- daar mag dalk ander plekke met \'n soortgelyke naam elders in die land wees, moenie dié verwar nie. ' : '') +
    'Soek spesifiek na bekende natuurlike kenmerke, besienswaardighede of aktiwiteite in of naby ' + whereForSearch + '. ' +
    'Antwoord dan in PRESIES hierdie formaat, niks anders nie:\n\n' +
    'HOOGTEPUNT: <2-6 woorde wat die EEN mees bekende, spesifieke besienswaardigheid of natuurlike kenmerk in die omgewing noem -- bv. \'Kwerboomwoud\', \'Tsitsikamma-brugpad\', \'Oranjerivier-varswaterstrand\'. Wees so spesifiek en akkuraat as moontlik; gebruik nie vae terme soos \'natuurskoon\' of \'pragtige uitsigte\' nie.>\n\n' +
    '<Daarna, op \'n nuwe paragraaf: ongeveer 150 woorde praktiese, feitelike inligting oor die omgewing -- natuurlike kenmerke, aktiwiteite of besienswaardighede naby, en enige nuttige praktiese of veiligheidsnotas vir kampeerders. Vloeiende paragraaf-teks, geen opskrifte of kolpunte nie.>\n\n' +
    'As die internetsoektog geen betroubare, spesifieke inligting oor hierdie presiese plek oplewer nie, gebruik dan die bekendste kenmerk van die breër streek/dorp in plaas daarvan, en praat in algemene terme eerder as om besonderhede te verzin.';

  var promptEn =
    'Do a quick web search for "' + searchQuery + '" to confirm what the campsite "' + name + '"' +
    (whereBits ? ' near ' + whereBits : '') + (gps ? ' (GPS coordinates: ' + gps + ')' : '') +
    ' in South Africa (or the surrounding region/country) is actually known for. ' +
    (gps ? 'IMPORTANT: the GPS coordinates ' + gps + ' are the most reliable indicator of exactly where this place is -- also run a separate search for "' + gpsSearchQuery + '" to confirm the nearest town/landmark from these coordinates, and use THAT (not just the name or town alone) as the final word on which area to describe. If the name or town conflicts with the coordinates, trust the coordinates. ' : '') +
    (whereBits ? 'IMPORTANT: search for this specific place IN ' + whereBits + ' -- there may be other places with a similar name elsewhere in the country, do not confuse them. ' : '') +
    'Search specifically for well-known natural features, attractions, or activities in or near ' + whereForSearch + '. ' +
    'Then answer in EXACTLY this format, nothing else:\n\n' +
    'HIGHLIGHT: <2-6 words naming the ONE most famous, specific attraction or natural feature in the area -- e.g. \'Quiver Tree Forest\', \'Tsitsikamma suspension bridge\', \'Orange River freshwater beach\'. Be as specific and accurate as possible; avoid vague terms like \'scenic views\' or \'beautiful nature\'.>\n\n' +
    '<Then, as a new paragraph: about 150 words of practical, factual information about the area -- natural features, nearby activities or points of interest, and any useful practical or safety notes for campers. Flowing paragraph text, no headings or bullet points.>\n\n' +
    'If the web search turns up no reliable, specific information about this exact place, use the best-known feature of the broader region/town instead, and speak in general terms rather than inventing details.';

    prompt = lang === 'en' ? promptEn : promptAf;
  }


  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 36000); // finish before Netlify's 40s
  try {
    const messages = [{ role: 'user', content: prompt }];
    let data = null;
    // Up to 2 continuations if Claude's search loop pauses (stop_reason "pause_turn").
    for (let attempt = 0; attempt < 3; attempt++) {
      const resp = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        signal: controller.signal,
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01'
        },
        body: JSON.stringify({
          model: 'claude-haiku-4-5-20251001',
          max_tokens: 1200,
          tools: [{ type: 'web_search_20250305', name: 'web_search', max_uses: 3, user_location: { type: 'approximate', country: 'ZA' } }],
          messages
        })
      });
      if (!resp.ok) {
        const errText = await resp.text();
        let msg = errText;
        try { msg = (JSON.parse(errText).error || {}).message || errText; } catch (e) {}
        return json(resp.status, { error: 'Claude API error (' + resp.status + '): ' + String(msg).slice(0, 300) });
      }
      const part = await resp.json();
      data = data ? { ...part, content: data.content.concat(part.content || []) } : part;
      if (part.stop_reason !== 'pause_turn') break;
      messages.push({ role: 'assistant', content: part.content });
    }

    const out = extractAnswer(data.content, lang);
    if (!out.text) {
      return json(502, { error: 'Claude returned no text (stop_reason: ' + (data.stop_reason || '?') + ')' });
    }
    return json(200, { text: out.text, highlight: out.highlight, searches: out.searches, searchError: out.searchError || undefined });
  } catch (e) {
    if (e && e.name === 'AbortError') return json(504, { error: 'The web search took too long (over 36s). Please try again.' });
    return json(500, { error: (e && e.message) || String(e) });
  } finally {
    clearTimeout(timer);
  }
};

export const config = { path: '/api/campsite-info' };
