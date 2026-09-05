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
    // With the web_search tool enabled, data.content can also include
    // server_tool_use / web_search_tool_result blocks alongside the
    // final text -- only the text blocks make up Claude's actual answer.
    var rawText = (data.content || [])
      .filter(function (block) { return block.type === 'text'; })
      .map(function (block) { return block.text || ''; })
      .join('')
      .trim();

    // Pull the "HOOGTEPUNT:"/"HIGHLIGHT:" line out as its own field so
    // the front-end can show it as a prominent badge, separate from the
    // paragraph text that goes in the editable notes box.
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
