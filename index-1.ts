// ============================================================
// Supabase Edge Function: admin-get-suggestions
// Deploy with: supabase functions deploy admin-get-suggestions
//
// Validates the session token issued by admin-login, then returns
// suggestions using the service_role key (bypassing RLS) — this is
// the only path that can read the suggestions table.
// ============================================================

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const SESSION_SECRET = Deno.env.get('SESSION_SECRET') ?? 'change-me-too';
const SUPABASE_URL = Deno.env.get('SUPABASE_URL') ?? '';
const SUPABASE_SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? '';

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

async function verifySessionToken(token) {
  try {
    const [payloadB64, sigHex] = token.split('.');
    const payload = atob(payloadB64);
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw', enc.encode(SESSION_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
    );
    const sigBytes = new Uint8Array(sigHex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, enc.encode(payload));
    if (!valid) return null;

    const parsed = JSON.parse(payload);
    if (parsed.exp < Date.now()) return null; // expired
    return parsed; // { role, exp }
  } catch {
    return null;
  }
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: CORS_HEADERS });
  }

  try {
    const { token, action, id, status } = await req.json();
    const session = await verifySessionToken(token);

    if (!session) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401, headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
      });
    }

    const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

    if (action === 'update_status') {
      const { error } = await supabase
        .from('suggestions')
        .update({ status })
        .eq('id', id);
      if (error) throw error;
      return new Response(JSON.stringify({ ok: true }), {
        status: 200, headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
      });
    }

    // default action: list suggestions
    const { data, error } = await supabase
      .from('suggestions')
      .select('*')
      .order('submitted_at', { ascending: false });

    if (error) throw error;

    return new Response(JSON.stringify({ suggestions: data }), {
      status: 200, headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: String(err) }), {
      status: 500, headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
    });
  }
});
