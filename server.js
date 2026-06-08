// KPOS WINV10 — Activation Server
// Copyright © 2025 @RT3M1S. All Rights Reserved.
// [KPOS WINV10 P3] — Phase 3: Online License Activation Server
// [KPOS WINV10 P6B] — Phase 6B: Admin panel + patch notes routes mounted
// ════════════════════════════════════════════════════════════════════

'use strict';

require('dotenv').config();

const express    = require('express');
const crypto     = require('crypto');
const rateLimit  = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');

const app  = express();
app.use(express.json());

// ─── [KPOS WINV10 P3] — Config ───────────────────────────────────────────────
const PORT           = process.env.PORT           || 3000;
const SERVER_SECRET  = process.env.SERVER_SECRET  || 'KPOS-WINV10-SERVER-SECRET-CHANGE-ME-IN-PROD';
const SUPABASE_URL   = process.env.SUPABASE_URL;
const SUPABASE_KEY   = process.env.SUPABASE_KEY;   // service_role key

const supabase = (SUPABASE_URL && SUPABASE_KEY)
  ? createClient(SUPABASE_URL, SUPABASE_KEY)
  : null;

// ─── [KPOS WINV10 P6B] — Expose supabase to all routes via app.locals ────────
// admin.js and patchnotes.js access it via req.app.locals.supabase
app.locals.supabase = supabase;

// ─── [KPOS WINV10 P3] — License Constants (must match main.js) ───────────────
const TRIAL_DAYS  = 30;
const MONTHLY_DAYS = 30;
const YEARLY_DAYS  = 365;

const LICENSE_TYPES = {
  M: { type: 'monthly',   days: MONTHLY_DAYS },
  Y: { type: 'yearly',    days: YEARLY_DAYS  },
  P: { type: 'perpetual', days: null         },
};

// ─── [KPOS WINV10 P3] — Rate Limiting ────────────────────────────────────────
const activateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 10,
  message: { success: false, error: 'Too many activation attempts. Try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const validateLimiter = rateLimit({
  windowMs: 60 * 1000,   // 1 minute
  max: 30,
  message: { success: false, error: 'Validation rate limit exceeded.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// ─── [KPOS WINV10 P3] — Helpers ──────────────────────────────────────────────

/** Validate KPOS-XXXX-XXXX-XXXX-XXXX format */
function validateKeyFormat(key) {
  return /^KPOS-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(
    key.trim().toUpperCase()
  );
}

/** Infer license type from key prefix segment */
function inferKeyType(cleanKey) {
  const seg = cleanKey.split('-')[1]; // segment after "KPOS-"
  const firstChar = seg ? seg[0] : 'M';
  return LICENSE_TYPES[firstChar] || LICENSE_TYPES['M'];
}

/** SHA-256 hex digest */
function sha256(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

/**
 * Sign a license payload with HMAC-SHA256 using SERVER_SECRET.
 * This token is stored on the client and re-sent for periodic validation.
 */
function signToken(payload) {
  const data = JSON.stringify(payload);
  const sig  = crypto.createHmac('sha256', SERVER_SECRET).update(data).digest('hex');
  return Buffer.from(JSON.stringify({ payload, sig })).toString('base64');
}

/** Verify a signed token. Returns payload or null. */
function verifyToken(tokenB64) {
  try {
    const { payload, sig } = JSON.parse(Buffer.from(tokenB64, 'base64').toString('utf8'));
    const expected = crypto.createHmac('sha256', SERVER_SECRET)
      .update(JSON.stringify(payload)).digest('hex');
    if (!crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'))) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}

/** Structured server log */
function slog(level, event, detail = {}) {
  console.log(JSON.stringify({
    ts: new Date().toISOString(), level, event, ...detail
  }));
}

// ─── [KPOS WINV10 P6B] — server_config helper ────────────────────────────────
/** Read a boolean flag from server_config. Returns true if value is 'true' or DB unavailable. */
async function configFlag(key) {
  if (!supabase) return true; // default open in dev mode
  try {
    const { data } = await supabase.from('server_config').select('value').eq('key', key).single();
    if (!data) return true; // missing row = default enabled
    return data.value !== 'false';
  } catch (e) {
    return true; // DB error = default open (don't block customers)
  }
}

// ─── [KPOS WINV10 P3] — Supabase Key Lookup ──────────────────────────────────
// Expected table: license_keys
// Columns: key TEXT PK, type TEXT, active BOOL, device_id TEXT, activated_at TIMESTAMPTZ,
//          created_at TIMESTAMPTZ, revoked BOOL, notes TEXT

async function dbGetKey(cleanKey) {
  if (!supabase) {
    // Dev mode: no DB — accept any valid-format key, device bind allowed once
    return { key: cleanKey, type: inferKeyType(cleanKey).type, active: true,
             device_id: null, revoked: false, activated_at: null };
  }
  const { data, error } = await supabase
    .from('license_keys')
    .select('*')
    .eq('key', cleanKey)
    .single();
  if (error || !data) return null;
  return data;
}

async function dbBindDevice(cleanKey, deviceId) {
  if (!supabase) return true;
  const { error } = await supabase
    .from('license_keys')
    .update({ device_id: deviceId, activated_at: new Date().toISOString() })
    .eq('key', cleanKey);
  return !error;
}

async function dbIsRevoked(cleanKey) {
  if (!supabase) return false;
  const { data } = await supabase
    .from('license_keys')
    .select('revoked')
    .eq('key', cleanKey)
    .single();
  return data ? !!data.revoked : false;
}

// ─── [KPOS WINV10 P3] — Health ───────────────────────────────────────────────
app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'KPOS WINV10 License Server', version: '3.0.0' });
});

// ─── [KPOS WINV10 P3] — Analytics route ──────────────────────────────────────
app.use('/v1/analytics', require('./routes/analytics'));

// ─── [KPOS WINV10 P6B] — Admin + Patch Notes routes ─────────────────────────
app.use('/admin',          require('./routes/admin'));
app.use('/v1/patch-notes', require('./routes/patchnotes'));

// ════════════════════════════════════════════════════════════════════
// [KPOS WINV10 P3] — POST /v1/activate
// Called by main.js ipcMain.handle('license:activate') once on first use.
// Body: { key: string, deviceId: string }
// Returns: { success, licenseId, licenseType, expiryDate, token, serverTimestamp, error? }
// ════════════════════════════════════════════════════════════════════
app.post('/v1/activate', activateLimiter, async (req, res) => {
  const { key, deviceId } = req.body || {};

  // [KPOS WINV10 P6B] — Check server_config: activations_enabled
  const activationsEnabled = await configFlag('activations_enabled');
  if (!activationsEnabled) {
    return res.status(503).json({ success: false, error: 'License activations are temporarily disabled. Contact your seller.' });
  }

  // 1. Input validation
  if (!key || !deviceId) {
    return res.status(400).json({ success: false, error: 'Missing key or deviceId.' });
  }
  const cleanKey = key.trim().toUpperCase();
  if (!validateKeyFormat(cleanKey)) {
    return res.status(400).json({
      success: false,
      error: 'Invalid license key format. Expected: KPOS-XXXX-XXXX-XXXX-XXXX'
    });
  }
  if (typeof deviceId !== 'string' || deviceId.length !== 64) {
    return res.status(400).json({ success: false, error: 'Invalid device fingerprint.' });
  }

  try {
    // 2. Fetch key record
    const record = await dbGetKey(cleanKey);
    if (!record) {
      slog('WARN', 'ACTIVATE_NOT_FOUND', { key: cleanKey.slice(0,9) });
      return res.status(404).json({ success: false, error: 'License key not found.' });
    }

    // 3. Revocation check
    if (record.revoked) {
      slog('WARN', 'ACTIVATE_REVOKED', { key: cleanKey.slice(0,9), deviceId: deviceId.slice(0,8) });
      return res.status(403).json({ success: false, error: 'This license key has been revoked.' });
    }

    // 4. Active check
    if (!record.active) {
      return res.status(403).json({ success: false, error: 'This license key is inactive.' });
    }

    // 5. Device binding — enforce single-device
    if (record.device_id && record.device_id !== deviceId) {
      slog('WARN', 'ACTIVATE_DEVICE_CONFLICT', {
        key: cleanKey.slice(0,9),
        existing: record.device_id.slice(0,8),
        attempted: deviceId.slice(0,8)
      });
      return res.status(409).json({
        success: false,
        error: 'This key is already activated on another device. Contact support to transfer.'
      });
    }

    // 6. Bind device if not yet bound
    if (!record.device_id) {
      const ok = await dbBindDevice(cleanKey, deviceId);
      if (!ok) {
        return res.status(500).json({ success: false, error: 'Failed to bind device. Try again.' });
      }
    }

    // 7. Compute license dates
    const { type: licenseType, days } = inferKeyType(cleanKey);
    const now        = new Date();
    const expiryDate = days ? new Date(now.getTime() + days * 86400000).toISOString() : null;
    const licenseId  = 'LIC-' + sha256(cleanKey + deviceId).slice(0,12).toUpperCase();

    // 8. Sign a server token (stored on client for periodic re-validation)
    const tokenPayload = {
      licenseId,
      licenseKey: cleanKey,
      deviceId,
      licenseType,
      expiryDate,
      issuedAt: now.toISOString(),
    };
    const token = signToken(tokenPayload);

    slog('INFO', 'ACTIVATE_OK', {
      key: cleanKey.slice(0,9), type: licenseType, device: deviceId.slice(0,8)
    });

    return res.json({
      success:         true,
      licenseId,
      licenseType,
      expiryDate,
      token,
      serverTimestamp: now.toISOString(),
    });

  } catch (err) {
    slog('ERROR', 'ACTIVATE_ERROR', { err: err.message });
    return res.status(500).json({ success: false, error: 'Server error. Try again.' });
  }
});

// ════════════════════════════════════════════════════════════════════
// [KPOS WINV10 P3] — POST /v1/validate
// Called by main.js periodically (every launch / every 24h).
// Body: { token: string, deviceId: string }
// Returns: { valid, licenseType, expiryDate, daysRemaining, revoked?, serverTimestamp }
// ════════════════════════════════════════════════════════════════════
app.post('/v1/validate', validateLimiter, async (req, res) => {
  const { token, deviceId } = req.body || {};

  if (!token || !deviceId) {
    return res.status(400).json({ valid: false, error: 'Missing token or deviceId.' });
  }

  // 1. Verify HMAC signature
  const payload = verifyToken(token);
  if (!payload) {
    slog('WARN', 'VALIDATE_BAD_TOKEN', { device: deviceId.slice(0,8) });
    return res.json({ valid: false, error: 'Token signature invalid. Re-activate your license.' });
  }

  // 2. Device binding check
  if (payload.deviceId !== deviceId) {
    slog('WARN', 'VALIDATE_DEVICE_MISMATCH', {
      tokenDevice: payload.deviceId.slice(0,8), reqDevice: deviceId.slice(0,8)
    });
    return res.json({ valid: false, error: 'Token was issued for a different device.' });
  }

  // 3. Live revocation check against DB
  try {
    const revoked = await dbIsRevoked(payload.licenseKey);
    if (revoked) {
      slog('WARN', 'VALIDATE_REVOKED', { key: payload.licenseKey.slice(0,9) });
      return res.json({ valid: false, revoked: true, error: 'License has been revoked.' });
    }
  } catch (err) {
    // DB unavailable — allow offline grace (don't invalidate)
    slog('WARN', 'VALIDATE_DB_UNAVAILABLE', { err: err.message });
  }

  // 4. Expiry check (perpetual = never expires)
  const now = new Date();
  let daysRemaining = null;
  if (payload.expiryDate) {
    daysRemaining = Math.max(0, Math.ceil(
      (new Date(payload.expiryDate).getTime() - now.getTime()) / 86400000
    ));
  }

  slog('INFO', 'VALIDATE_OK', {
    key: payload.licenseKey.slice(0,9), daysRemaining, device: deviceId.slice(0,8)
  });

  return res.json({
    valid:           true,
    licenseId:       payload.licenseId,
    licenseType:     payload.licenseType,
    expiryDate:      payload.expiryDate,
    daysRemaining,
    serverTimestamp: now.toISOString(),
  });
});

// ════════════════════════════════════════════════════════════════════
// [KPOS WINV10 P3] — POST /v1/revoke  (Admin endpoint)
// Body: { adminSecret: string, key: string }
// ════════════════════════════════════════════════════════════════════
app.post('/v1/revoke', async (req, res) => {
  const { adminSecret, key } = req.body || {};
  if (!adminSecret || adminSecret !== process.env.ADMIN_SECRET) {
    return res.status(401).json({ success: false, error: 'Unauthorized.' });
  }
  const cleanKey = (key || '').trim().toUpperCase();
  if (!validateKeyFormat(cleanKey)) {
    return res.status(400).json({ success: false, error: 'Invalid key format.' });
  }
  if (!supabase) {
    return res.status(503).json({ success: false, error: 'No DB connected (dev mode).' });
  }
  const { error } = await supabase
    .from('license_keys')
    .update({ revoked: true })
    .eq('key', cleanKey);
  if (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
  slog('INFO', 'KEY_REVOKED', { key: cleanKey.slice(0,9) });
  return res.json({ success: true, key: cleanKey });
});

// ─── Start ───────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  slog('INFO', 'SERVER_STARTED', { port: PORT, db: supabase ? 'supabase' : 'dev-mode (no DB)' });
});
