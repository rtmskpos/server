// KPOS WINV10 — Patch Notes Route
// Copyright © 2025 @RT3M1S. All Rights Reserved.
// [KPOS WINV10 P6B] — Public endpoint: GET /v1/patch-notes/latest
// Called by KPOS app on every boot. No auth required.
// ════════════════════════════════════════════════════════════════════

'use strict';

const express  = require('express');
const router   = express.Router();

// supabase is attached to app.locals by server.js
function getSupabase(req) {
  return req.app.locals.supabase || null;
}

// ─── GET /v1/patch-notes/latest ──────────────────────────────────────────────
// Returns the latest patch note if its version > current app version.
// The version comparison is semver-aware using integer tuple comparison.
// Response shape:
//   { hasUpdate: false }
//   { hasUpdate: true, version, title, body, download_url, is_critical }
// ─────────────────────────────────────────────────────────────────────────────
router.get('/latest', async (req, res) => {
  const supabase = getSupabase(req);

  // If no DB connected (dev mode with no Supabase), return no-update
  if (!supabase) {
    return res.json({ hasUpdate: false });
  }

  try {
    // Check server_config: updates_enabled flag
    const { data: cfg } = await supabase
      .from('server_config')
      .select('value')
      .eq('key', 'updates_enabled')
      .single();

    if (cfg && cfg.value === 'false') {
      return res.json({ hasUpdate: false });
    }

    // Fetch the most recent patch note
    const { data: note, error } = await supabase
      .from('patch_notes')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(1)
      .single();

    if (error || !note) {
      return res.json({ hasUpdate: false });
    }

    // App version is sent as query param: ?appVersion=10.1.0
    // If not provided, always return hasUpdate: false to be safe
    const appVersion = (req.query.appVersion || '').trim();
    if (!appVersion) {
      return res.json({ hasUpdate: false });
    }

    // Compare versions: parse as integer tuples [major, minor, patch]
    const parse = (v) => v.split('.').map(n => parseInt(n, 10) || 0);
    const appTuple   = parse(appVersion);
    const noteTuple  = parse(note.version);

    // noteTuple > appTuple → update available
    let isNewer = false;
    for (let i = 0; i < 3; i++) {
      const a = appTuple[i]  || 0;
      const b = noteTuple[i] || 0;
      if (b > a) { isNewer = true; break; }
      if (b < a) { isNewer = false; break; }
    }

    if (!isNewer) {
      return res.json({ hasUpdate: false });
    }

    return res.json({
      hasUpdate:    true,
      version:      note.version,
      title:        note.title,
      body:         note.body,
      download_url: note.download_url || null,
      is_critical:  !!note.is_critical,
    });

  } catch (err) {
    // Never let this crash the app — just return no-update
    console.error('[P6B] patch-notes/latest error:', err.message);
    return res.json({ hasUpdate: false });
  }
});

module.exports = router;
