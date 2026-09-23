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
