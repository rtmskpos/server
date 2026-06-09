// KPOS WINV10 — Activation Server
// Copyright © 2025 @RT3M1S. All Rights Reserved.
// [KPOS WINV10 P3] — Core activation endpoints
// [KPOS WINV10 P6] — Analytics route mount
// [KPOS WINV10 P6B] — Admin panel route mount + app.locals.supabase + flag checks
// [KPOS WINV10 P6B-FIX] — Multi-month license type support in DAYS_MAP
// ════════════════════════════════════════════════════════════════════

'use strict';

require('dotenv').config();

const express    = require('express');
const crypto     = require('crypto');
const rateLimit  = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─── Supabase ─────────────────────────────────────────────────────────────────
const supabase = (process.env.SUPABASE_URL && process.env.SUPABASE_KEY)
  ? createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY)
  : null;

// Expose to routes via app.locals (admin.js + patchnotes.js read from here)
app.locals.supabase = supabase;

// ─── Logging ──────────────────────────────────────────────────────────────────
function slog(level, event, detail = {}) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), level, event, ...detail }));
}

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(express.json());

// Rate limiting — general API
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// ─── License Days Map ─────────────────────────────────────────────────────────
// [KPOS WINV10 P6B-FIX] Added multi-month types (2month through 6month)
const DAYS_MAP = {
  'monthly':   30,
  '2month':    60,
  '3month':    90,
  '4month':   120,
  '5month':   150,
  '6month':   180,
  'yearly':   365,
  'perpetual': null,  // null = no expiry
};

// ─── Helpers ──────────────────────────────────────────────────────────────────
const SERVER_SECRET = process.env.SERVER_SECRET || 'fallback-dev-secret';
const ADMIN_SECRET  = process.env.ADMIN_SECRET  || '';

function signToken(payload) {
  const data = JSON.stringify(payload);
  const sig  = crypto.createHmac('sha256', SERVER_SECRET).update(data).digest('hex');
  return Buffer.from(JSON.stringify({ data, sig })).toString('base64');
}

function verifyToken(tokenB64) {
  try {
    const { data, sig } = JSON.parse(Buffer.from(tokenB64, 'base64').toString());
    const expected = crypto.createHmac('sha256', SERVER_SECRET).update(data).digest('hex');
    if (sig !== expected) return null;
    return JSON.parse(data);
  } catch { return null; }
}

async function getConfig(key) {
  if (!supabase) return 'true';
  try {
    const { data } = await supabase.from('server_config').select('value').eq('key', key).single();
    return data ? data.value : 'true';
  } catch { return 'true'; }
}

// ─── Health Check ─────────────────────────────────────────────────────────────
app.get('/health', async (req, res) => {
  const dbOk = supabase ? await supabase.from('license_keys').select('id').limit(1)
    .then(() => true).catch(() => false) : false;
  return res.json({ status: 'ok', db: dbOk, ts: new Date().toISOString() });
});

// ════════════════════════════════════════════════════════════════════
// [KPOS WINV10 P3] — POST /v1/activate
// ════════════════════════════════════════════════════════════════════
app.post('/v1/activate', async (req, res) => {
  const { key, deviceId } = req.body || {};

  // Check activations_enabled flag
  const activationsEnabled = await getConfig('activations_enabled');
  if (activationsEnabled === 'false') {
    return res.status(503).json({ success: false, error: 'Activations are currently disabled for maintenance. Please try again later.' });
  }

  if (!key || !deviceId) {
    return res.status(400).json({ success: false, error: 'Missing key or deviceId.' });
  }

  const cleanKey = key.trim().toUpperCase();
  if (!supabase) {
    return res.status(503).json({ success: false, error: 'Server not configured.' });
  }

  try {
    const { data: row, error } = await supabase
      .from('license_keys')
      .select('*')
      .eq('key', cleanKey)
      .single();

    if (error || !row) {
      slog('WARN', 'ACTIVATE_KEY_NOT_FOUND', { key: cleanKey.slice(0, 9) });
      return res.json({ success: false, error: 'License key not found.' });
    }

    if (row.revoked) {
      slog('WARN', 'ACTIVATE_REVOKED', { key: cleanKey.slice(0, 9) });
      return res.json({ success: false, error: 'This license has been suspended or revoked.' });
    }

    if (!row.active) {
      return res.json({ success: false, error: 'This license is not active.' });
    }

    // Device binding — if already bound to a different device, reject
    if (row.device_id && row.device_id !== deviceId) {
      slog('WARN', 'ACTIVATE_DEVICE_MISMATCH', { key: cleanKey.slice(0, 9) });
      return res.json({ success: false, error: 'This license is already activated on another device. Contact support.' });
    }

    // Calculate expiry
    const days = DAYS_MAP[row.type];
    const now  = new Date();
    const expiryDate = days !== null
      ? new Date(now.getTime() + days * 86400000).toISOString()
      : null;

    const daysRemaining = days !== null ? days : 99999;
    const licenseId = 'LIC-' + crypto.randomBytes(5).toString('hex').toUpperCase();

    // Bind device if not already bound
    if (!row.device_id) {
      await supabase.from('license_keys').update({
        device_id: deviceId,
        activated_at: now.toISOString(),
        active: true,
      }).eq('key', cleanKey);
    }

    // Issue HMAC token
    const tokenPayload = { key: cleanKey, deviceId, licenseId, issuedAt: now.toISOString() };
    const token = signToken(tokenPayload);

    slog('INFO', 'ACTIVATE_OK', { key: cleanKey.slice(0, 9), type: row.type, device: deviceId.slice(0, 8) });

    return res.json({
      success: true,
      licenseType: row.type,
      licenseId,
      expiryDate,
      daysRemaining,
      token,
      serverTimestamp: now.toISOString(),
    });

  } catch (err) {
    slog('ERROR', 'ACTIVATE_ERROR', { err: err.message });
    return res.status(500).json({ success: false, error: 'Server error.' });
  }
});

// ════════════════════════════════════════════════════════════════════
// [KPOS WINV10 P3] — POST /v1/validate
// ════════════════════════════════════════════════════════════════════
app.post('/v1/validate', async (req, res) => {
  const { token, deviceId } = req.body || {};

  if (!token || !deviceId) {
    return res.status(400).json({ valid: false, error: 'Missing token or deviceId.' });
  }

  const payload = verifyToken(token);
  if (!payload) {
    return res.json({ valid: false, error: 'Invalid token signature.' });
  }

  if (payload.deviceId !== deviceId) {
    return res.json({ valid: false, error: 'Device mismatch.' });
  }

  if (!supabase) {
    return res.json({ valid: true, daysRemaining: 30, expiryDate: null, serverTimestamp: new Date().toISOString() });
  }

  try {
    const { data: row, error } = await supabase
      .from('license_keys')
      .select('*')
      .eq('key', payload.key)
      .single();

    if (error || !row) {
      return res.json({ valid: false, revoked: true, error: 'License not found.' });
    }

    if (row.revoked || !row.active) {
      slog('INFO', 'VALIDATE_REVOKED', { key: payload.key.slice(0, 9) });
      return res.json({ valid: false, revoked: true, error: 'License suspended or revoked.' });
    }

    // Recalculate expiry from activation date
    const days = DAYS_MAP[row.type];
    let expiryDate = null;
    let daysRemaining = 99999;

    if (days !== null && row.activated_at) {
      const expiry = new Date(new Date(row.activated_at).getTime() + days * 86400000);
      expiryDate = expiry.toISOString();
      daysRemaining = Math.max(0, Math.ceil((expiry.getTime() - Date.now()) / 86400000));
    }

    const serverTimestamp = new Date().toISOString();
    slog('INFO', 'VALIDATE_OK', { key: payload.key.slice(0, 9), type: row.type, daysRemaining });

    return res.json({ valid: true, daysRemaining, expiryDate, serverTimestamp });

  } catch (err) {
    slog('ERROR', 'VALIDATE_ERROR', { err: err.message });
    return res.status(500).json({ valid: false, error: 'Server error.' });
  }
});

// ════════════════════════════════════════════════════════════════════
// [KPOS WINV10 P3] — POST /v1/revoke (legacy endpoint, keep for compat)
// ════════════════════════════════════════════════════════════════════
app.post('/v1/revoke', async (req, res) => {
  const { key, secret } = req.body || {};
  if (!ADMIN_SECRET || secret !== ADMIN_SECRET) {
    return res.status(401).json({ success: false, error: 'Unauthorized.' });
  }
  if (!key || !supabase) return res.status(400).json({ success: false });
  try {
    await supabase.from('license_keys')
      .update({ revoked: true, active: false })
      .eq('key', key.trim().toUpperCase());
    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

// ─── Route Mounts ─────────────────────────────────────────────────────────────
// [KPOS WINV10 P6] — Analytics
app.use('/v1/analytics', require('./routes/analytics'));

// [KPOS WINV10 P6B] — Admin panel
app.use('/admin', require('./routes/admin'));

// [KPOS WINV10 P6B] — Patch notes (public)
app.use('/v1/patch-notes', require('./routes/patchnotes'));

// ─── 404 ──────────────────────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: 'Not found.' }));

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  slog('INFO', 'SERVER_STARTED', { port: String(PORT), db: supabase ? 'supabase' : 'none' });
});