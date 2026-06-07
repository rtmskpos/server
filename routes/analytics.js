// KPOS WINV10 — Analytics Route
// Copyright © 2025 @RT3M1S. All Rights Reserved.
// [KPOS WINV10 P6] — Phase 6: Opt-in Analytics Endpoint
// ════════════════════════════════════════════════════════════════════
// ADD THIS TO server.js (one line):
//   app.use('/v1/analytics', require('./routes/analytics'));
//
// PLACE THIS FILE AT:
//   /home/junne/kpos-server/routes/analytics.js
//
// SUPABASE TABLE (run once in Supabase SQL editor):
//   CREATE TABLE analytics_events (
//     id           BIGSERIAL PRIMARY KEY,
//     device_id    TEXT NOT NULL,
//     app_version  TEXT NOT NULL,
//     date         DATE NOT NULL,
//     tx_count     INTEGER DEFAULT 0,
//     session_mins INTEGER DEFAULT 0,
//     features     JSONB DEFAULT '{}',
//     created_at   TIMESTAMPTZ DEFAULT NOW()
//   );
//   CREATE INDEX ON analytics_events (device_id, date);
// ════════════════════════════════════════════════════════════════════

'use strict';

const express   = require('express');
const router    = express.Router();
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');

// Re-use Supabase from env (same as server.js)
const supabase = (process.env.SUPABASE_URL && process.env.SUPABASE_KEY)
  ? createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY)
  : null;

// ─── Rate Limiting ────────────────────────────────────────────────────────────
// Max 10 analytics pings per device per hour
const analyticsLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  keyGenerator: (req) => req.body?.deviceId || req.ip,
  message: { success: false, error: 'Analytics rate limit exceeded.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// ─── Helpers ─────────────────────────────────────────────────────────────────
function slog(level, event, detail = {}) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), level, event, ...detail }));
}

function isValidDeviceId(id) {
  return typeof id === 'string' && /^[a-f0-9]{64}$/.test(id);
}

function isValidVersion(v) {
  return typeof v === 'string' && /^\d+\.\d+\.\d+$/.test(v);
}

function sanitizeFeatures(raw) {
  // Allow only boolean flags — no strings, no nested objects, no PII
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
  const clean = {};
  const ALLOWED_FEATURES = [
    'used_pos', 'used_inventory', 'used_reports', 'used_customers',
    'used_gcash', 'used_expenses', 'used_ai', 'used_barcode',
    'used_credits', 'used_shifts', 'used_backup'
  ];
  for (const key of ALLOWED_FEATURES) {
    if (key in raw) clean[key] = !!raw[key];
  }
  return clean;
}

// ════════════════════════════════════════════════════════════════════
// [KPOS WINV10 P6] — POST /v1/analytics/ping
// Called by main.js once per day (batched). Never called in real-time.
// Body: {
//   deviceId:    string (64-char hex, anon — NOT linked to license DB),
//   appVersion:  string (semver, e.g. "10.1.0"),
//   date:        string (YYYY-MM-DD, local date of the session),
//   txCount:     integer (daily transaction count, no amounts/items),
//   sessionMins: integer (total session minutes that day),
//   features:    object (boolean flags only — see sanitizeFeatures),
// }
// Returns: { success: boolean }
// ════════════════════════════════════════════════════════════════════
router.post('/ping', analyticsLimiter, async (req, res) => {
  const { deviceId, appVersion, date, txCount, sessionMins, features } = req.body || {};

  // ── Input validation ────────────────────────────────────────────────
  if (!isValidDeviceId(deviceId)) {
    return res.status(400).json({ success: false, error: 'Invalid deviceId.' });
  }
  if (!isValidVersion(appVersion)) {
    return res.status(400).json({ success: false, error: 'Invalid appVersion.' });
  }
  // Validate date: YYYY-MM-DD
  if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    return res.status(400).json({ success: false, error: 'Invalid date.' });
  }
  const txInt   = Math.max(0, Math.min(99999, parseInt(txCount,  10) || 0));
  const sesInt  = Math.max(0, Math.min(1440,  parseInt(sessionMins, 10) || 0));
  const feats   = sanitizeFeatures(features);

  // ── Upsert (one row per device per day) ────────────────────────────
  if (!supabase) {
    // Dev mode — just acknowledge
    slog('INFO', 'ANALYTICS_PING_DEVMODE', { device: deviceId.slice(0,8), date });
    return res.json({ success: true });
  }

  try {
    const { error } = await supabase
      .from('analytics_events')
      .upsert(
        {
          device_id:    deviceId,
          app_version:  appVersion,
          date:         date,
          tx_count:     txInt,
          session_mins: sesInt,
          features:     feats,
        },
        { onConflict: 'device_id,date', ignoreDuplicates: false }
      );

    if (error) {
      slog('ERROR', 'ANALYTICS_PING_DB_ERROR', { err: error.message });
      // Never fail the client — return success regardless
      return res.json({ success: true });
    }

    slog('INFO', 'ANALYTICS_PING_OK', {
      device: deviceId.slice(0,8), date, txInt, sesInt, version: appVersion
    });
    return res.json({ success: true });

  } catch (err) {
    slog('ERROR', 'ANALYTICS_PING_EXCEPTION', { err: err.message });
    // Never fail the client
    return res.json({ success: true });
  }
});

module.exports = router;
