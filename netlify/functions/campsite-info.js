// netlify/functions/campsite-info.js
//
// Serverless proxy for the "AI campsite info" feature in the Tour Planner.
// The browser NEVER sees the Anthropic API key -- it lives only in this
// function's environment (Netlify Site settings -> Environment variables).
//
// This endpoint is also gated behind your existing Firebase login: every
// request must carry a valid Firebase ID token (as an "Authorization:
// Bearer <token>" header, which the front-end already attaches). Without
// this check, anyone who found this URL could call it directly -- with
// curl, a script, whatever -- completely bypassing the app's UI, and
// generate Claude API charges on your key for free. Verifying the token
// here (not just checking login state in the browser) is what actually
// closes that hole.
//
// No npm packages are used (just Node's built-in `crypto` + `fetch`), so
// this deploys as-is via Netlify's drag-and-drop -- no build step, no
// node_modules to bundle.

var crypto = require('crypto');

// Your Firebase project ID (from firebaseConfig in the app). This isn't a
// secret -- it's already public in the HTML -- it's just used here to
// confirm the token was actually issued for THIS app, not some other
// Firebase project.
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
  // These certs rotate periodically; Google's response headers say how
  // long to cache them for, but re-fetching at most once an hour (well
  // under Firebase ID tokens' own 1-hour lifetime) is a safe, simple
  // default without needing to parse Cache-Control ourselves.
  certsCacheExpiry = now + 60 * 60 * 1000;
  return certsCache;
}

function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64');
}

// Verifies a Firebase Auth ID token: checks the RS256 signature against
// Google's current public keys, then checks expiry/issuer/audience. This
// is the same set of checks firebase-admin's verifyIdToken() does under
// the hood -- reimplemented by hand here purely so this function has zero
// npm dependencies and stays deployable via plain drag-and-drop.
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

  return payload; // includes payload.email, payload.sub (Firebase uid), etc.
}

exports.handler = async function (event) {
  console.log('campsite-info invoked, method:', event && event.httpMethod, 'hasBody:', !!(event && event.body));

  // (No HTTP-method check here -- it isn't needed for security, since the
  // Firebase login check right below is what actually gates this
  // endpoint, and different Netlify function runtimes/formats have
  // reported the incoming method inconsistently in the past. Body
  // parsing below will naturally fail for a request with no JSON body
  // anyway.)

  // ── Require a valid, current Firebase login ──────────────────────
  var authHeader = (event.headers && (event.headers.authorization || event.headers.Authorization)) || '';
  if (!authHeader.toLowerCase().startsWith('bearer ')) {
    return { statusCode: 401, body: JSON.stringify({ error: 'Please log in to use AI generation.' }) };
  }
  var idToken = authHeader.slice(7).trim();
  try {
    await verifyFirebaseIdToken(idToken);
  } catch (e) {
    return { statusCode: 401, body: JSON.stringify({ error: 'Your login has expired. Please log in again.' }) };
  }
  // Note: this confirms the request comes from someone genuinely signed
  // in via Firebase Auth for this app -- it does NOT re-check the
  // `members/{email}.active` Firestore flag the rest of the app uses to
  // gate access (that would need firebase-admin + a service account
  // credential, which is more setup than this feature needs). In
  // practice this matches the app's own login gate closely enough: an
  // admin revoking someone's `active` flag mid-session won't cut off
  // their AI access until their existing token naturally expires
  // (tokens last up to 1 hour), same as it wouldn't instantly kick them
  // out of the rest of the app either.

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

  var name = (body.name || '').trim();
  var town = (body.town || '').trim();
  var province = (body.province || '').trim();
  var gps = (body.gps || '').trim();
  var lang = body.lang === 'en' ? 'en' : 'af'; // default Afrikaans, matches the app

  if (!name) {
    return { statusCode: 400, body: JSON.stringify({ error: 'Missing campsite name' }) };
  }

  var whereBits = [town, province].filter(Boolean).join(', ');

  var promptAf =
    'Skryf ongeveer 150 woorde praktiese, feitelike inligting oor die kampeerterrein "' + name + '"' +
    (whereBits ? ' naby ' + whereBits : '') + (gps ? ' (GPS: ' + gps + ')' : '') + ' in Suid-Afrika of die omliggende streek. ' +
    'Dek dinge soos: waarvoor die omgewing bekend is, natuurlike kenmerke (berge, riviere, kus, wildlewe), aktiwiteite of besienswaardighede in die omgewing, en enige nuttige praktiese of veiligheidsnotas vir kampeerders. ' +
    'Skryf in vloeiende, natuurlike paragraaf-teks (geen opskrifte of kolpunte nie). ' +
    'As jy nie seker is van spesifieke feite oor hierdie presiese plek nie, praat eerder in algemene terme oor die streek as om spesifieke besonderhede te verzin.';

  var promptEn =
    'Write about 150 words of practical, factual information about the campsite "' + name + '"' +
    (whereBits ? ' near ' + whereBits : '') + (gps ? ' (GPS: ' + gps + ')' : '') + ' in South Africa or the surrounding region. ' +
    'Cover things like: what the surrounding area is known for, natural features (mountains, rivers, coast, wildlife), nearby activities or points of interest, and any useful practical or safety notes for campers. ' +
    'Write in flowing, natural paragraph text (no headings or bullet points). ' +
    'If you are not confident about specific facts for this exact location, speak in more general terms about the region rather than inventing specific details.';

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
        max_tokens: 400,
        messages: [{ role: 'user', content: prompt }]
      })
    });

    if (!resp.ok) {
      var errText = await resp.text();
      return {
        statusCode: resp.status,
        body: JSON.stringify({ error: 'Claude API error', detail: errText })
      };
    }

    var data = await resp.json();
    var text = (data.content || [])
      .map(function (block) { return block.text || ''; })
      .join('')
      .trim();

    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: text })
    };
  } catch (e) {
    return { statusCode: 500, body: JSON.stringify({ error: e.message }) };
  }
};
