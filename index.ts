// ============================================================
// Supabase Edge Function: admin-upload-pdf
// Deploy with: supabase functions deploy admin-upload-pdf
//
// Receives a PDF + metadata from admin.html, validates the session
// token, extracts text for search, uploads the file to Backblaze B2
// (S3-compatible API), then inserts a row into `documents`.
//
// B2 credentials live ONLY here, as Edge Function secrets — never
// in any HTML/JS file.
// ============================================================

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import { S3Client, PutObjectCommand } from 'https://esm.sh/@aws-sdk/client-s3@3';

const SESSION_SECRET = Deno.env.get('SESSION_SECRET') ?? '';
const SUPABASE_URL = Deno.env.get('SUPABASE_URL') ?? '';
const SUPABASE_SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? '';

const B2_KEY_ID = Deno.env.get('B2_KEY_ID') ?? '';
const B2_APPLICATION_KEY = Deno.env.get('B2_APPLICATION_KEY') ?? '';
const B2_BUCKET_NAME = Deno.env.get('B2_BUCKET_NAME') ?? '';
const B2_ENDPOINT = Deno.env.get('B2_ENDPOINT') ?? ''; // e.g. s3.us-east-005.backblazeb2.com
const B2_REGION = (Deno.env.get('B2_ENDPOINT') ?? '').split('.')[1] ?? 'us-east-005';

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
    if (parsed.exp < Date.now()) return null;
    return parsed;
  } catch {
    return null;
  }
}

const r2 = new S3Client({
  region: B2_REGION,
  endpoint: `https://${B2_ENDPOINT}`,
  credentials: { accessKeyId: B2_KEY_ID, secretAccessKey: B2_APPLICATION_KEY },
});

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: CORS_HEADERS });
  }

  try {
    const formData = await req.formData();
    const token = formData.get('token');
    const session = await verifySessionToken(token);

    if (!session) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401, headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
      });
    }

    const file = formData.get('file');
    const title = formData.get('title');
    const moduleNumber = parseInt(formData.get('module_number') || '0', 10);
    const topic = formData.get('topic') || '';

    if (!file || !title) {
      return new Response(JSON.stringify({ error: 'Missing file or title' }), {
        status: 400, headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
      });
    }

    const arrayBuffer = await file.arrayBuffer();
    const buffer = new Uint8Array(arrayBuffer);

    // Extract text for search (lightweight regex-based extraction;
    // good enough for typical lecture-note PDFs)
    let contentText = '';
    try {
      contentText = extractTextFromPdf(buffer);
    } catch {
      contentText = ''; // non-fatal — file still uploads, just not full-text searchable
    }

    const safeFileName = file.name.replace(/[^a-zA-Z0-9.\-_]/g, '_');
    const fileKey = `module-${moduleNumber}/${Date.now()}-${safeFileName}`;

    await r2.send(new PutObjectCommand({
      Bucket: B2_BUCKET_NAME,
      Key: fileKey,
      Body: buffer,
      ContentType: 'application/pdf',
    }));

    const publicUrl = `https://${B2_ENDPOINT}/${B2_BUCKET_NAME}/${fileKey}`;

    const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);
    const { error } = await supabase.from('documents').insert({
      title,
      course_code: 'RDG205',
      module_number: moduleNumber,
      topic,
      file_key: fileKey,
      file_size_bytes: buffer.length,
      content_text: contentText,
      public_url: publicUrl,
    });

    if (error) throw error;

    return new Response(JSON.stringify({ ok: true, fileKey, publicUrl }), {
      status: 200, headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
    });
  } catch (err) {
    console.error(err);
    return new Response(JSON.stringify({ error: String(err) }), {
      status: 500, headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
    });
  }
});

// Minimal PDF text extraction — pulls text between BT/ET markers.
// Works for most standard-export PDFs; scanned/image-only PDFs will
// just get an empty content_text (file still uploads fine).
function extractTextFromPdf(bytes) {
  const text = new TextDecoder('latin1').decode(bytes);
  const matches = text.match(/\(((?:[^()\\]|\\.)*)\)\s*Tj/g) || [];
  return matches
    .map(m => m.replace(/^\(|\)\s*Tj$/g, '').replace(/\\(.)/g, '$1'))
    .join(' ')
    .slice(0, 50000); // cap stored text length
}
