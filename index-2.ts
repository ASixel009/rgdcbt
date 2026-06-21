// ============================================================
// Supabase Edge Function: admin-login
// Deploy with: supabase functions deploy admin-login
//
// This is the ONLY place the two secret codes are checked.
// They live as Edge Function secrets (set via CLI/dashboard),
// never inside any HTML/JS file the browser can read.
// ============================================================

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

// These are read from Edge Function environment secrets — set them with:
//   supabase secrets set ADMIN_CODE_DEVELOPER=rdg-cloud-developer
//   supabase secrets set ADMIN_CODE_ADMIN=rdg-cloud-admin
const ADMIN_CODE_DEVELOPER = Deno.env.get('ADMIN_CODE_DEVELOPER') ?? '';
const ADMIN_CODE_ADMIN = Deno.env.get('ADMIN_CODE_ADMIN') ?? '';
const SESSION_SECRET = Deno.env.get('SESSION_SECRET') ?? 'change-me-too';

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

// Simple signed-token session (good enough for a small admin panel;
// not a full JWT library, but unforgeable without SESSION_SECRET)
async function makeSessionToken(role) {
  const payload = JSON.stringify({ role, exp: Date.now() + 1000 * 60 * 60 * 12 }); // 12h
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(SESSION_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(payload));
  const sigHex = [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
  const payloadB64 = btoa(payload);
  return `${payloadB64}.${sigHex}`;
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: CORS_HEADERS });
  }

  try {
    const { code } = await req.json();

    if (!code || typeof code !== 'string') {
      return new Response(JSON.stringify({ error: 'Code is required' }), {
        status: 400, headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
      });
    }

    let role = null;
    let welcomeName = null;

    if (code === ADMIN_CODE_DEVELOPER) {
      role = 'developer';
      welcomeName = 'ABDUL-SALAM'; // display-only, not used for auth
    } else if (code === ADMIN_CODE_ADMIN) {
      role = 'admin';
      welcomeName = 'Ashad';
    }

    if (!role) {
      // Deliberately vague — don't reveal whether code was "close"
      return new Response(JSON.stringify({ error: 'Invalid code' }), {
        status: 401, headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
      });
    }

    const token = await makeSessionToken(role);

    return new Response(JSON.stringify({ token, role, welcomeName }), {
      status: 200, headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: 'Bad request' }), {
      status: 400, headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
    });
  }
});
