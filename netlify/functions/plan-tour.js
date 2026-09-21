// netlify/functions/plan-tour.js
//
// Serverless proxy for the "AI Toer Beplanner" tab. Given a list of towns
// or areas the traveller wants to visit, plus a shortlist of candidate
// campsites (already filtered from the app's own database client-side --
// see runAiTourPlanner() in index.html), this asks Claude to choose ONE
// sensible visiting order through those campsites.
//
// Two things this function deliberately does NOT do, both on purpose:
//   1. It never proposes a campsite outside the candidate list it's given.
//      The prompt below is built to make that structurally hard to get
//      wrong (it only ever hands back names from the list), which is what
//      keeps this from ever hallucinating a place that doesn't exist in
//      the app's data.
//   2. It doesn't do any distance/km-per-day math. Real driving distances
//      (via OSRM) and the traveller's chosen daily-km cap are enforced
//      entirely client-side, in code, after this returns an order --
//      exact km limits are not something to trust an LLM to get right,
//      only real routing data.
//
// Same Firebase-login gate as campsite-info.js, and for the same reason:
// without it, anyone who found this URL could call it directly and rack
// up Claude API charges on your key.
//
// SETUP: identical to campsite-info.js -- needs ANTHROPIC_API_KEY set as
// a Netlify environment variable. No other configuration.

var crypto = require('crypto');

var FIREBASE_PROJECT_ID = 'nayela-camping';
var GOOGLE_CERTS_URL = 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';

var certsCache = null;
var certsCacheExpiry = 0;

async function getGoogleCerts() {
  var now = Date.now();
  if (certsCache && now < certsCacheExpiry) return certsCache;
  var resp = await fetch(GOOGLE_CERTS_URL);
  if (!resp.ok) throw new Error('Could not fetch Google public certs');
  certsCache = await resp.json();
  certsCacheExpiry = now + 60 * 60 * 1000;
  return certsCache;
}

function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64');
}

async function verifyFirebaseIdToken(idToken) {
  var parts = idToken.split('.');
  if (parts.length !== 3) throw new Error('Malformed token');
  var headerB64 = parts[0], payloadB64 = parts[1], signatureB64 = parts[2];

  var header = JSON.parse(base64UrlDecode(headerB64).toString('utf8'));
  var payload = JSON.parse(base64UrlDecode(payloadB64).toString('utf8'));

  if (header.alg !== 'RS256') throw new Error('Unexpected token algorithm');

  var certs = await getGoogleCerts();
  var cert = certs[header.kid];
  if (!cert) throw new Error('Unknown signing key (token may be forged or expired keys were used)');

  var verifier = crypto.createVerify('RSA-SHA256');
  verifier.update(headerB64 + '.' + payloadB64);
  var signatureValid = verifier.verify(cert, base64UrlDecode(signatureB64));
  if (!signatureValid) throw new Error('Invalid token signature');

  var now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== 'number' || payload.exp < now) throw new Error('Token expired');
  if (typeof payload.iat !== 'number' || payload.iat > now + 300) throw new Error('Token issued in the future');
  if (payload.aud !== FIREBASE_PROJECT_ID) throw new Error('Token was not issued for this app');
  if (payload.iss !== 'https://securetoken.google.com/' + FIREBASE_PROJECT_ID) throw new Error('Unexpected token issuer');
  if (!payload.sub) throw new Error('Token missing subject');

  return payload;
}

exports.handler = async function (event) {
  var authHeader = (event.headers && (event.headers.authorization || event.headers.Authorization)) || '';
  if (!authHeader.toLowerCase().startsWith('bearer ')) {
    return { statusCode: 401, body: JSON.stringify({ error: 'Please log in to use the AI tour planner.' }) };
  }
  var idToken = authHeader.slice(7).trim();
  try {
    await verifyFirebaseIdToken(idToken);
  } catch (e) {
    return { statusCode: 401, body: JSON.stringify({ error: 'Your login has expired. Please log in again.' }) };
  }

  var apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'ANTHROPIC_API_KEY is not set on this Netlify site (Site settings → Environment variables).' })
    };
  }

  var body;
  try {
    body = JSON.parse(event.body || '{}');
  } catch (e) {
    return { statusCode: 400, body: JSON.stringify({ error: 'Invalid request body' }) };
  }

  var towns = Array.isArray(body.towns) ? body.towns.filter(Boolean).slice(0, 30) : [];
  var candidates = Array.isArray(body.candidates) ? body.candidates.slice(0, 200) : [];
  var lang = body.lang === 'en' ? 'en' : 'af';

  if (!towns.length) return { statusCode: 400, body: JSON.stringify({ error: 'No towns/areas given' }) };
  if (!candidates.length) return { statusCode: 400, body: JSON.stringify({ error: 'No candidate campsites given' }) };

  // Build a plain numbered list Claude can only ever pick FROM -- this is
  // what makes hallucinating a nonexistent campsite structurally hard: it
  // only ever has these exact names, with their real town/province, to
  // choose between and hand back verbatim.
  var listText = candidates.map(function (c, i) {
    return (i + 1) + '. ' + c.naam + (c.dorp ? ' (' + c.dorp + (c.provinsie ? ', ' + c.provinsie : '') + ')' : '');
  }).join('\n');

  var townsText = towns.join(lang === 'en' ? ', ' : ', ');

  var promptAf =
    'Jy help \'n Suid-Afrikaanse kampeerder \'n roete beplan wat hierdie dorpe/areas besoek, in hierdie volgorde of \'n logieser volgorde as jy een kan sien: ' + townsText + '.\n\n' +
    'Hier is \'n lys kampeerterreine wat reeds in die program se databasis is, elkeen met sy dorp/provinsie:\n' + listText + '\n\n' +
    'Kies VIR ELKE dorp/area hierbo, EEN kampeerterrein uit die lys wat die beste daarby pas (naaste geleë of duidelik bedoel vir daardie area). ' +
    'As twee dorpe albei die naaste aan dieselfde kampeerterrein is, kies dit net EENMAAL en los die ander dorp uit. ' +
    'As werklik GEEN kampeerterrein in die lys enigsins by \'n spesifieke dorp pas nie, los daardie dorp eenvoudig uit -- moenie \'n kampeerterrein kies wat nie eintlik daar naby is nie. ' +
    'Rangskik jou finale keuses in \'n sinvolle reisvolgorde (nie te veel heen-en-weer ry nie).\n\n' +
    'Antwoord met NIKS ANDERS as \'n geldige JSON-array van die presiese name (soos hierbo gelys) in reisvolgorde nie. Voorbeeld: ["Naam Een","Naam Twee","Naam Drie"]. Geen ander teks, geen verduideliking, net die JSON-array.';

  var promptEn =
    'You are helping a South African camper plan a route visiting these towns/areas, in this order or a more logical order if you can see one: ' + townsText + '.\n\n' +
    'Here is a list of campsites already in the app\'s database, each with its town/province:\n' + listText + '\n\n' +
    'For EACH town/area above, choose ONE campsite from the list that fits it best (closest located, or clearly intended for that area). ' +
    'If two towns are both closest to the same campsite, pick it only ONCE and skip the other town. ' +
    'If genuinely NO campsite in the list fits a particular town at all, simply skip that town -- do not pick a campsite that isn\'t actually near it. ' +
    'Order your final picks into a sensible travel sequence (not excessive backtracking).\n\n' +
    'Reply with NOTHING ELSE but a valid JSON array of the exact names (as listed above) in travel order. Example: ["Name One","Name Two","Name Three"]. No other text, no explanation, just the JSON array.';

  var prompt = lang === 'en' ? promptEn : promptAf;

  try {
    var resp = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 1000,
        messages: [{ role: 'user', content: prompt }]
      })
    });

    if (!resp.ok) {
      var errText = await resp.text();
      return { statusCode: resp.status, body: JSON.stringify({ error: 'Claude API error', detail: errText }) };
    }

    var data = await resp.json();
    var rawText = (data.content || [])
      .filter(function (block) { return block.type === 'text'; })
      .map(function (block) { return block.text || ''; })
      .join('')
      .trim();

    // Be tolerant of Claude wrapping the array in a ```json fence or a
    // sentence despite the instruction -- pull out the first [...] block.
    var match = rawText.match(/\[[\s\S]*\]/);
    if (!match) {
      return { statusCode: 502, body: JSON.stringify({ error: 'AI did not return a usable list', raw: rawText.slice(0, 300) }) };
    }
    var order;
    try {
      order = JSON.parse(match[0]);
    } catch (e) {
      return { statusCode: 502, body: JSON.stringify({ error: 'AI returned malformed JSON', raw: rawText.slice(0, 300) }) };
    }
    if (!Array.isArray(order)) {
      return { statusCode: 502, body: JSON.stringify({ error: 'AI response was not a list' }) };
    }

    // Defensive filter: only keep names that actually exist in the
    // candidate list handed in -- belt-and-braces against the (rare)
    // case Claude paraphrases a name slightly instead of copying it
    // exactly. Anything that doesn't match verbatim is silently dropped
    // rather than passed through as an unverified/possibly-fake stop.
    var validNames = {};
    candidates.forEach(function (c) { validNames[c.naam] = true; });
    var cleanOrder = order.filter(function (n) { return typeof n === 'string' && validNames[n]; });

    // De-duplicate while preserving order, in case the same name got
    // picked for two different towns despite the prompt's instruction.
    var seen = {};
    cleanOrder = cleanOrder.filter(function (n) {
      if (seen[n]) return false;
      seen[n] = true;
      return true;
    });

    return { statusCode: 200, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ order: cleanOrder }) };
  } catch (e) {
    return { statusCode: 500, body: JSON.stringify({ error: e.message }) };
  }
};
