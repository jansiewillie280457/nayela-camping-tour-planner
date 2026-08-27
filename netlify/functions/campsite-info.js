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
  console.log('campsite-info invoked, method:', event && event.httpMethod, 'hasBody:', !!(event && event.body));

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
  var lang = body.lang === 'en' ? 'en' : 'af';

  if (!name) {
    return { statusCode: 400, body: JSON.stringify({ error: 'Missing campsite name' }) };
  }

  var whereBits = [town, province].filter(Boolean).join(', ');
  var whereForSearch = whereBits || name;

  var promptAf =
    'Doen \'n vinnige internetsoektog om te bevestig wat die kampeerterrein "' + name + '"' +
    (whereBits ? ' naby ' + whereBits : '') + (gps ? ' (GPS: ' + gps + ')' : '') +
    ' in Suid-Afrika (of die omliggende streek/land) se omgewing werklik bekend maak -- soek spesifiek na bekende natuurlike kenmerke, besienswaardighede of aktiwiteite in of naby ' + whereForSearch + '. ' +
    'Antwoord dan in PRESIES hierdie formaat, niks anders nie:\n\n' +
    'HOOGTEPUNT: <2-6 woorde wat die EEN mees bekende, spesifieke besienswaardigheid of natuurlike kenmerk in die omgewing noem -- bv. \'Kwerboomwoud\', \'Tsitsikamma-brugpad\', \'Oranjerivier-varswaterstrand\'. Wees so spesifiek en akkuraat as moontlik; gebruik nie vae terme soos \'natuurskoon\' of \'pragtige uitsigte\' nie.>\n\n' +
    '<Daarna, op \'n nuwe paragraaf: ongeveer 150 woorde praktiese, feitelike inligting oor die omgewing -- natuurlike kenmerke, aktiwiteite of besienswaardighede naby, en enige nuttige praktiese of veiligheidsnotas vir kampeerders. Vloeiende paragraaf-teks, geen opskrifte of kolpunte nie.>\n\n' +
    'As die internetsoektog geen betroubare, spesifieke inligting oor hierdie presiese plek oplewer nie, gebruik dan die bekendste kenmerk van die breër streek/dorp in plaas daarvan, en praat in algemene terme eerder as om besonderhede te verzin.';

  var promptEn =
    'Do a quick web search to confirm what the campsite "' + name + '"' +
    (whereBits ? ' near ' + whereBits : '') + (gps ? ' (GPS: ' + gps + ')' : '') +
    ' in South Africa (or the surrounding region/country) is actually known for -- search specifically for well-known natural features, attractions, or activities in or near ' + whereForSearch + '. ' +
    'Then answer in EXACTLY this format, nothing else:\n\n' +
    'HIGHLIGHT: <2-6 words naming the ONE most famous, specific attraction or natural feature in the area -- e.g. \'Quiver Tree Forest\', \'Tsitsikamma suspension bridge\', \'Orange River freshwater beach\'. Be as specific and accurate as possible; avoid vague terms like \'scenic views\' or \'beautiful nature\'.>\n\n' +
    '<Then, as a new paragraph: about 150 words of practical, factual information about the area -- natural features, nearby activities or points of interest, and any useful practical or safety notes for campers. Flowing paragraph text, no headings or bullet points.>\n\n' +
    'If the web search turns up no reliable, specific information about this exact place, use the best-known feature of the broader region/town instead, and speak in general terms rather than inventing details.';

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
        max_tokens: 800,
        tools: [{ type: 'web_search_20250305', name: 'web_search', max_uses: 3 }],
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
    var rawText = (data.content || [])
      .filter(function (block) { return block.type === 'text'; })
      .map(function (block) { return block.text || ''; })
      .join('')
      .trim();

    var highlightPrefix = lang === 'en' ? 'HIGHLIGHT:' : 'HOOGTEPUNT:';
    var highlight = '';
    var text = rawText;
    if (rawText.indexOf(highlightPrefix) === 0) {
      var afterPrefix = rawText.slice(highlightPrefix.length);
      var newlineIdx = afterPrefix.indexOf('\n');
      if (newlineIdx === -1) {
        highlight = afterPrefix.trim();
        text = '';
      } else {
        highlight = afterPrefix.slice(0, newlineIdx).trim();
        text = afterPrefix.slice(newlineIdx).trim();
      }
    }

    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: text, highlight: highlight })
    };
  } catch (e) {
    return { statusCode: 500, body: JSON.stringify({ error: e.message }) };
  }
};
