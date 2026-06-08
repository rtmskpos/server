// KPOS WINV10 — Admin Panel Route
// Copyright © 2025 @RT3M1S. All Rights Reserved.
// [KPOS WINV10 P6B] — GET /admin (dashboard HTML) + all /admin/api/* endpoints
// Single-owner vendor control room. Secured by X-Admin-Token header.
// ════════════════════════════════════════════════════════════════════

'use strict';

const express = require('express');
const crypto  = require('crypto');
const router  = express.Router();

// ─── In-memory log ring buffer (100 entries) ──────────────────────────────────
// [KPOS WINV10 P6B] Wraps console.log so all slog() calls are captured here.
const LOG_RING = [];
const LOG_MAX  = 100;
const _origLog = console.log;
console.log = function (...args) {
  _origLog.apply(console, args);
  try {
    const line = args.map(a => (typeof a === 'string' ? a : JSON.stringify(a))).join(' ');
    LOG_RING.push({ ts: new Date().toISOString(), line });
    if (LOG_RING.length > LOG_MAX) LOG_RING.shift();
  } catch (e) {}
};

// ─── Helpers ─────────────────────────────────────────────────────────────────
function getSupabase(req) { return req.app.locals.supabase || null; }
function getAdminToken()  { return process.env.ADMIN_TOKEN || ''; }

/** Validate KPOS-XXXX-XXXX-XXXX-XXXX format */
function validateKeyFormat(key) {
  return /^KPOS-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(
    (key || '').trim().toUpperCase()
  );
}

/** Generate a random segment of N uppercase alphanumeric chars */
function randSeg(n) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let out = '';
  const buf = crypto.randomBytes(n * 2);
  for (let i = 0; i < n; i++) out += chars[buf[i] % chars.length];
  return out;
}

/** Generate a valid KPOS license key: KPOS-{T}XXX-XXXX-XXXX-XXXX */
function generateKey(type) {
  const prefix = type === 'yearly' ? 'Y' : type === 'perpetual' ? 'P' : 'M';
  const seg1 = prefix + randSeg(3);
  return `KPOS-${seg1}-${randSeg(4)}-${randSeg(4)}-${randSeg(4)}`;
}

// ─── Auth middleware ──────────────────────────────────────────────────────────
// [KPOS WINV10 P6B] All /admin/api/* routes require X-Admin-Token header.
function requireAuth(req, res, next) {
  const token     = req.headers['x-admin-token'] || '';
  const expected  = getAdminToken();
  if (!expected) return res.status(503).json({ error: 'ADMIN_TOKEN not configured on server.' });
  if (!token || token !== expected) {
    return res.status(401).json({ error: 'Unauthorized. Invalid admin token.' });
  }
  next();
}

// ════════════════════════════════════════════════════════════════════
// [KPOS WINV10 P6B] — GET /admin
// Serves the full single-page admin dashboard HTML
// ════════════════════════════════════════════════════════════════════
router.get('/', (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(ADMIN_HTML);
});

// ════════════════════════════════════════════════════════════════════
// [KPOS WINV10 P6B] — License Manager API
// ════════════════════════════════════════════════════════════════════

// GET /admin/api/licenses
router.get('/api/licenses', requireAuth, async (req, res) => {
  const sb = getSupabase(req);
  if (!sb) return res.json({ licenses: [] });
  try {
    const { data, error } = await sb.from('license_keys').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    return res.json({ licenses: data || [] });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// POST /admin/api/licenses/create
router.post('/api/licenses/create', requireAuth, async (req, res) => {
  const { type } = req.body || {};
  const validTypes = ['monthly', 'yearly', 'perpetual'];
  if (!validTypes.includes(type)) return res.status(400).json({ error: 'Invalid type.' });

  const sb  = getSupabase(req);
  if (!sb) return res.status(503).json({ error: 'No DB in dev mode.' });

  const key = generateKey(type);
  try {
    const { error } = await sb.from('license_keys').insert({
      key, type, active: true, revoked: false, device_id: null,
      activated_at: null, created_at: new Date().toISOString(), notes: null,
    });
    if (error) throw error;
    return res.json({ success: true, key });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// POST /admin/api/licenses/revoke
router.post('/api/licenses/revoke', requireAuth, async (req, res) => {
  const { key } = req.body || {};
  if (!validateKeyFormat(key)) return res.status(400).json({ error: 'Invalid key format.' });
  const sb = getSupabase(req);
  if (!sb) return res.status(503).json({ error: 'No DB.' });
  try {
    const { error } = await sb.from('license_keys')
      .update({ revoked: true, active: false })
      .eq('key', key.trim().toUpperCase());
    if (error) throw error;
    return res.json({ success: true });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// POST /admin/api/licenses/restore
router.post('/api/licenses/restore', requireAuth, async (req, res) => {
  const { key } = req.body || {};
  if (!validateKeyFormat(key)) return res.status(400).json({ error: 'Invalid key format.' });
  const sb = getSupabase(req);
  if (!sb) return res.status(503).json({ error: 'No DB.' });
  try {
    const { error } = await sb.from('license_keys')
      .update({ revoked: false, active: true })
      .eq('key', key.trim().toUpperCase());
    if (error) throw error;
    return res.json({ success: true });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// POST /admin/api/licenses/extend
router.post('/api/licenses/extend', requireAuth, async (req, res) => {
  const { key, newExpiry } = req.body || {};
  if (!validateKeyFormat(key)) return res.status(400).json({ error: 'Invalid key format.' });
  if (!newExpiry || isNaN(Date.parse(newExpiry))) return res.status(400).json({ error: 'Invalid date.' });
  const sb = getSupabase(req);
  if (!sb) return res.status(503).json({ error: 'No DB.' });
  // NOTE: server token expiry is authoritative — extending here marks it in notes.
  // Full expiry push requires re-validate from client. We update notes with new date as memo.
  try {
    const { error } = await sb.from('license_keys')
      .update({ notes: `Extended to ${newExpiry}` })
      .eq('key', key.trim().toUpperCase());
    if (error) throw error;
    return res.json({ success: true, note: 'Expiry memo saved. Customer must re-activate or re-validate to pull new dates.' });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// POST /admin/api/licenses/note
router.post('/api/licenses/note', requireAuth, async (req, res) => {
  const { key, notes } = req.body || {};
  if (!validateKeyFormat(key)) return res.status(400).json({ error: 'Invalid key format.' });
  const sb = getSupabase(req);
  if (!sb) return res.status(503).json({ error: 'No DB.' });
  try {
    const { error } = await sb.from('license_keys')
      .update({ notes: (notes || '').slice(0, 500) })
      .eq('key', key.trim().toUpperCase());
    if (error) throw error;
    return res.json({ success: true });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// ════════════════════════════════════════════════════════════════════
// [KPOS WINV10 P6B] — Analytics Dashboard API
// ════════════════════════════════════════════════════════════════════

// GET /admin/api/analytics/summary
router.get('/api/analytics/summary', requireAuth, async (req, res) => {
  const sb = getSupabase(req);
  if (!sb) return res.json({ activeInstalls: 0, totalTx: 0, avgSessionMins: 0, totalDevices: 0 });
  try {
    const cutoff = new Date(Date.now() - 30 * 86400000).toISOString().slice(0, 10);
    const { data } = await sb.from('analytics_events').select('device_id, tx_count, session_mins').gte('date', cutoff);
    const rows = data || [];
    const devices = new Set(rows.map(r => r.device_id)).size;
    const totalTx = rows.reduce((s, r) => s + (r.tx_count || 0), 0);
    const totalMins = rows.reduce((s, r) => s + (r.session_mins || 0), 0);
    return res.json({ activeInstalls: devices, totalTx, avgSessionMins: rows.length ? Math.round(totalMins / rows.length) : 0, totalDevices: devices });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// GET /admin/api/analytics/dau
router.get('/api/analytics/dau', requireAuth, async (req, res) => {
  const sb = getSupabase(req);
  if (!sb) return res.json({ dau: [] });
  try {
    const cutoff = new Date(Date.now() - 30 * 86400000).toISOString().slice(0, 10);
    const { data } = await sb.from('analytics_events').select('date, device_id').gte('date', cutoff);
    const rows = data || [];
    const byDate = {};
    for (const r of rows) {
      if (!byDate[r.date]) byDate[r.date] = new Set();
      byDate[r.date].add(r.device_id);
    }
    const dau = Object.entries(byDate).sort(([a], [b]) => a.localeCompare(b))
      .map(([date, s]) => ({ date, count: s.size }));
    return res.json({ dau });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// GET /admin/api/analytics/features
router.get('/api/analytics/features', requireAuth, async (req, res) => {
  const sb = getSupabase(req);
  if (!sb) return res.json({ features: [] });
  try {
    const cutoff = new Date(Date.now() - 30 * 86400000).toISOString().slice(0, 10);
    const { data } = await sb.from('analytics_events').select('device_id, features').gte('date', cutoff);
    const rows = data || [];
    const deviceSet = new Set(rows.map(r => r.device_id));
    const total = deviceSet.size || 1;
    const featureKeys = ['used_pos','used_inventory','used_reports','used_customers','used_gcash','used_expenses','used_ai','used_barcode','used_credits','used_shifts','used_backup'];
    // Count unique devices that used each feature
    const deviceFeature = {}; // key → Set of device_ids
    for (const r of rows) {
      if (!r.features) continue;
      for (const fk of featureKeys) {
        if (r.features[fk]) {
          if (!deviceFeature[fk]) deviceFeature[fk] = new Set();
          deviceFeature[fk].add(r.device_id);
        }
      }
    }
    const features = featureKeys.map(k => ({
      key: k,
      label: k.replace('used_', '').replace('_', ' ').replace(/\b\w/g, c => c.toUpperCase()),
      pct: Math.round(((deviceFeature[k] ? deviceFeature[k].size : 0) / total) * 100),
    }));
    return res.json({ features });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// GET /admin/api/analytics/versions
router.get('/api/analytics/versions', requireAuth, async (req, res) => {
  const sb = getSupabase(req);
  if (!sb) return res.json({ versions: [] });
  try {
    const cutoff = new Date(Date.now() - 30 * 86400000).toISOString().slice(0, 10);
    const { data } = await sb.from('analytics_events').select('device_id, app_version').gte('date', cutoff);
    const rows = data || [];
    // Latest version per device
    const devVer = {};
    for (const r of rows) devVer[r.device_id] = r.app_version;
    const counts = {};
    for (const v of Object.values(devVer)) counts[v] = (counts[v] || 0) + 1;
    const versions = Object.entries(counts).map(([v, c]) => ({ version: v, count: c }))
      .sort((a, b) => b.count - a.count);
    return res.json({ versions });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// GET /admin/api/analytics/topdevices
router.get('/api/analytics/topdevices', requireAuth, async (req, res) => {
  const sb = getSupabase(req);
  if (!sb) return res.json({ devices: [] });
  try {
    const cutoff = new Date(Date.now() - 30 * 86400000).toISOString().slice(0, 10);
    const { data } = await sb.from('analytics_events').select('device_id, tx_count, app_version').gte('date', cutoff);
    const rows = data || [];
    const byDevice = {};
    for (const r of rows) {
      if (!byDevice[r.device_id]) byDevice[r.device_id] = { device_id: r.device_id, tx_count: 0, app_version: r.app_version };
      byDevice[r.device_id].tx_count += (r.tx_count || 0);
      byDevice[r.device_id].app_version = r.app_version;
    }
    const devices = Object.values(byDevice).sort((a, b) => b.tx_count - a.tx_count).slice(0, 10);
    return res.json({ devices });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// ════════════════════════════════════════════════════════════════════
// [KPOS WINV10 P6B] — Patch Notes API
// ════════════════════════════════════════════════════════════════════

// GET /admin/api/patches
router.get('/api/patches', requireAuth, async (req, res) => {
  const sb = getSupabase(req);
  if (!sb) return res.json({ patches: [] });
  try {
    const { data, error } = await sb.from('patch_notes').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    return res.json({ patches: data || [] });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// POST /admin/api/patches/create
router.post('/api/patches/create', requireAuth, async (req, res) => {
  const { version, title, body, download_url, is_critical } = req.body || {};
  if (!version || !title || !body) return res.status(400).json({ error: 'version, title, body are required.' });
  const sb = getSupabase(req);
  if (!sb) return res.status(503).json({ error: 'No DB.' });
  try {
    const { error } = await sb.from('patch_notes').insert({
      version: version.trim(), title: title.trim().slice(0, 200),
      body: body.trim().slice(0, 2000), download_url: (download_url || '').trim() || null,
      is_critical: !!is_critical, created_at: new Date().toISOString(),
    });
    if (error) throw error;
    return res.json({ success: true });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// DELETE /admin/api/patches/:id
router.delete('/api/patches/:id', requireAuth, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'Invalid id.' });
  const sb = getSupabase(req);
  if (!sb) return res.status(503).json({ error: 'No DB.' });
  try {
    const { error } = await sb.from('patch_notes').delete().eq('id', id);
    if (error) throw error;
    return res.json({ success: true });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// ════════════════════════════════════════════════════════════════════
// [KPOS WINV10 P6B] — Server Health API
// ════════════════════════════════════════════════════════════════════

// GET /admin/api/health
router.get('/api/health', requireAuth, async (req, res) => {
  const sb = getSupabase(req);
  let dbOk = false;
  if (sb) {
    try {
      const { error } = await sb.from('server_config').select('key').limit(1);
      dbOk = !error;
    } catch (e) {}
  }
  const uptime = Math.floor(process.uptime());
  const mem    = process.memoryUsage();
  return res.json({
    server: true,
    db: dbOk,
    uptime,
    memMB: Math.round(mem.rss / 1024 / 1024),
    logs: LOG_RING.slice(-100).reverse(),
  });
});

// GET /admin/api/license-counts
router.get('/api/license-counts', requireAuth, async (req, res) => {
  const sb = getSupabase(req);
  if (!sb) return res.json({ total: 0, active: 0, suspended: 0, unused: 0 });
  try {
    const { data } = await sb.from('license_keys').select('active, revoked, device_id');
    const rows = data || [];
    const total     = rows.length;
    const suspended = rows.filter(r => r.revoked).length;
    const active    = rows.filter(r => !r.revoked && r.active && r.device_id).length;
    const unused    = rows.filter(r => !r.revoked && r.active && !r.device_id).length;
    return res.json({ total, active, suspended, unused });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// ════════════════════════════════════════════════════════════════════
// [KPOS WINV10 P6B] — Quick Controls API (server_config)
// ════════════════════════════════════════════════════════════════════

// GET /admin/api/config
router.get('/api/config', requireAuth, async (req, res) => {
  const sb = getSupabase(req);
  if (!sb) return res.json({ config: {} });
  try {
    const { data } = await sb.from('server_config').select('*');
    const config = {};
    for (const row of (data || [])) config[row.key] = row.value;
    return res.json({ config });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// POST /admin/api/config
router.post('/api/config', requireAuth, async (req, res) => {
  const { key, value } = req.body || {};
  const allowed = ['activations_enabled', 'analytics_enabled', 'trials_allowed', 'updates_enabled'];
  if (!allowed.includes(key)) return res.status(400).json({ error: 'Invalid config key.' });
  if (value !== 'true' && value !== 'false') return res.status(400).json({ error: 'Value must be "true" or "false".' });
  const sb = getSupabase(req);
  if (!sb) return res.status(503).json({ error: 'No DB.' });
  try {
    const { error } = await sb.from('server_config').upsert({ key, value, updated_at: new Date().toISOString() });
    if (error) throw error;
    return res.json({ success: true });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// ════════════════════════════════════════════════════════════════════
// [KPOS WINV10 P6B] — ADMIN DASHBOARD HTML
// Full single-page dark dashboard. Sidebar nav. Chart.js via CDN.
// ════════════════════════════════════════════════════════════════════
const ADMIN_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>KPOS WINV10 — Admin</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0d0d0f;--sf:#16181d;--bd:#1f2128;--accent:#7c5cfc;--danger:#ef4444;
  --success:#22c55e;--warn:#f59e0b;--tx:#f1f1f3;--muted:#6b7280;
  --row1:#0d0d0f;--row2:#13151a;
}
body{font-family:system-ui,-apple-system,'Inter',sans-serif;background:var(--bg);color:var(--tx);display:flex;height:100vh;overflow:hidden;font-size:14px}
a{color:var(--accent);text-decoration:none}

/* ── Sidebar ── */
#sidebar{width:220px;min-width:220px;background:var(--sf);border-right:1px solid var(--bd);display:flex;flex-direction:column;padding:0;z-index:10}
.sb-logo{padding:20px 18px 14px;border-bottom:1px solid var(--bd)}
.sb-logo .badge{display:inline-block;background:linear-gradient(135deg,#7c5cfc,#3ecfcf);color:#fff;font-size:10px;font-weight:700;letter-spacing:2px;padding:3px 8px;border-radius:20px;margin-bottom:6px}
.sb-logo h2{font-size:15px;font-weight:700;color:var(--tx)}
.sb-logo p{font-size:11px;color:var(--muted);margin-top:2px}
.sb-nav{flex:1;padding:12px 0;overflow-y:auto}
.nav-item{display:flex;align-items:center;gap:10px;padding:10px 18px;cursor:pointer;color:var(--muted);font-size:13px;font-weight:500;transition:all .15s;border-left:2px solid transparent}
.nav-item:hover{color:var(--tx);background:rgba(124,92,252,.07)}
.nav-item.active{color:var(--accent);background:rgba(124,92,252,.1);border-left-color:var(--accent);font-weight:600}
.nav-item .ic{font-size:16px;width:20px;text-align:center}
.sb-footer{padding:14px 18px;border-top:1px solid var(--bd);font-size:11px;color:var(--muted)}

/* ── Main area ── */
#main{flex:1;display:flex;flex-direction:column;overflow:hidden}
#topbar{background:var(--sf);border-bottom:1px solid var(--bd);padding:0 24px;height:52px;display:flex;align-items:center;justify-content:space-between;flex-shrink:0}
#topbar h1{font-size:15px;font-weight:600;color:var(--tx)}
.tb-right{display:flex;align-items:center;gap:10px}
.status-dot{width:8px;height:8px;border-radius:50%;background:var(--success);display:inline-block;margin-right:4px}
.status-dot.red{background:var(--danger)}
#content{flex:1;overflow-y:auto;padding:24px}

/* ── Section ── */
.section{display:none}.section.active{display:block}
.section-title{font-size:18px;font-weight:700;color:var(--tx);margin-bottom:4px}
.section-sub{font-size:13px;color:var(--muted);margin-bottom:20px}

/* ── Stat cards ── */
.stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}
.stat-card{background:var(--sf);border:1px solid var(--bd);border-radius:8px;padding:16px}
.stat-label{font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px}
.stat-val{font-size:26px;font-weight:700;line-height:1}
.stat-sub{font-size:11px;color:var(--muted);margin-top:4px}
.val-accent{color:var(--accent)}.val-green{color:var(--success)}.val-red{color:var(--danger)}.val-warn{color:var(--warn)}

/* ── Cards ── */
.card{background:var(--sf);border:1px solid var(--bd);border-radius:8px;padding:18px;margin-bottom:16px}
.card-title{font-size:12px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:14px}

/* ── Tables ── */
.tbl-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;padding:10px 12px;font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;border-bottom:1px solid var(--bd)}
tr:nth-child(odd) td{background:var(--row1)}
tr:nth-child(even) td{background:var(--row2)}
td{padding:10px 12px;border-bottom:1px solid var(--bd);color:var(--tx);vertical-align:middle}
tr:hover td{filter:brightness(1.07)}

/* ── Badges ── */
.badge{display:inline-block;padding:2px 8px;border-radius:20px;font-size:11px;font-weight:600}
.badge-green{background:rgba(34,197,94,.15);color:var(--success)}
.badge-red{background:rgba(239,68,68,.15);color:var(--danger)}
.badge-warn{background:rgba(245,158,11,.15);color:var(--warn)}
.badge-muted{background:rgba(107,114,128,.15);color:var(--muted)}
.badge-accent{background:rgba(124,92,252,.15);color:var(--accent)}

/* ── Buttons ── */
.btn{padding:7px 14px;border-radius:6px;border:1px solid var(--bd);background:var(--sf);color:var(--tx);cursor:pointer;font-size:13px;font-weight:500;font-family:inherit;transition:all .15s;display:inline-flex;align-items:center;gap:5px}
.btn:hover{border-color:var(--accent);color:var(--accent)}
.btn-accent{background:var(--accent);border-color:var(--accent);color:#fff}.btn-accent:hover{opacity:.88;color:#fff}
.btn-danger{background:var(--danger);border-color:var(--danger);color:#fff}.btn-danger:hover{opacity:.88;color:#fff}
.btn-success{background:var(--success);border-color:var(--success);color:#fff}.btn-success:hover{opacity:.88;color:#fff}
.btn-sm{padding:4px 10px;font-size:12px}
.btn-copy{background:transparent;border:1px solid var(--bd);color:var(--muted);padding:3px 8px;border-radius:4px;cursor:pointer;font-size:11px;font-family:inherit;transition:all .15s}
.btn-copy:hover{border-color:var(--accent);color:var(--accent)}

/* ── Forms ── */
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px}
.form-group{display:flex;flex-direction:column;gap:4px}
label.fl{font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
input,select,textarea{background:var(--bg);border:1px solid var(--bd);border-radius:6px;padding:9px 12px;color:var(--tx);font-size:13px;font-family:inherit;outline:none;transition:border-color .15s;width:100%}
input:focus,select:focus,textarea:focus{border-color:var(--accent)}
textarea{resize:vertical;min-height:80px}

/* ── Toggle switch ── */
.toggle-wrap{display:flex;align-items:center;justify-content:space-between;padding:14px 0;border-bottom:1px solid var(--bd)}
.toggle-wrap:last-child{border-bottom:none}
.toggle-info h4{font-size:14px;font-weight:500;color:var(--tx);margin-bottom:2px}
.toggle-info p{font-size:12px;color:var(--muted)}
.toggle{position:relative;width:44px;height:24px;flex-shrink:0}
.toggle input{opacity:0;width:0;height:0;position:absolute}
.slider{position:absolute;inset:0;background:#374151;border-radius:24px;cursor:pointer;transition:background .15s}
.slider:before{content:'';position:absolute;width:18px;height:18px;left:3px;top:3px;background:#fff;border-radius:50%;transition:transform .15s}
.toggle input:checked + .slider{background:var(--accent)}
.toggle input:checked + .slider:before{transform:translateX(20px)}

/* ── Modal ── */
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.7);display:flex;align-items:center;justify-content:center;z-index:9999;display:none}
.modal-overlay.open{display:flex}
.modal{background:var(--sf);border:1px solid var(--bd);border-radius:12px;padding:28px;width:100%;max-width:480px;position:relative}
.modal h3{font-size:17px;font-weight:700;margin-bottom:8px}
.modal p{font-size:13px;color:var(--muted);margin-bottom:16px;line-height:1.5}
.modal-danger{border-top:3px solid var(--danger)}
.modal-footer{display:flex;justify-content:flex-end;gap:10px;margin-top:20px}

/* ── Charts ── */
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}
.chart-box{background:var(--sf);border:1px solid var(--bd);border-radius:8px;padding:18px}
.chart-box canvas{max-height:220px}

/* ── Login screen ── */
#login-screen{position:fixed;inset:0;background:var(--bg);display:flex;align-items:center;justify-content:center;z-index:9999}
.login-card{background:var(--sf);border:1px solid var(--bd);border-radius:16px;padding:40px;width:100%;max-width:400px}
.login-badge{display:inline-block;background:linear-gradient(135deg,#7c5cfc,#3ecfcf);color:#fff;font-size:11px;font-weight:700;letter-spacing:2px;padding:4px 12px;border-radius:20px;margin-bottom:14px}
.login-card h1{font-size:24px;font-weight:800;margin-bottom:4px}
.login-card p{font-size:13px;color:var(--muted);margin-bottom:24px}
.login-err{color:var(--danger);font-size:12px;margin-top:8px;display:none}

/* ── Misc ── */
.empty-state{text-align:center;padding:40px;color:var(--muted);font-size:13px}
.key-mono{font-family:'Courier New',monospace;font-size:12px;color:var(--accent)}
.truncate{max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.log-feed{background:var(--bg);border:1px solid var(--bd);border-radius:6px;padding:12px;font-family:'Courier New',monospace;font-size:11px;color:#9ca3af;max-height:260px;overflow-y:auto;line-height:1.6}
.log-line{padding:1px 0;border-bottom:1px solid rgba(255,255,255,.03)}
.log-line:last-child{border:none}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.filter-bar{display:flex;gap:10px;margin-bottom:14px;flex-wrap:wrap;align-items:center}
.filter-bar select,.filter-bar input{width:auto;flex:none}
.new-key-box{background:rgba(124,92,252,.1);border:1px solid var(--accent);border-radius:8px;padding:14px;display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px;display:none}
.new-key-box .key-text{font-family:monospace;font-size:15px;color:var(--accent);font-weight:700;letter-spacing:1px}
.critical-badge{background:rgba(239,68,68,.2);color:var(--danger);font-size:10px;padding:2px 6px;border-radius:4px;font-weight:700}
</style>
</head>
<body>

<!-- ── Login Screen ── -->
<div id="login-screen">
  <div class="login-card">
    <div class="login-badge">ADMIN</div>
    <h1>KPOS WINV10</h1>
    <p>Vendor Control Room · @RT3M1S</p>
    <label class="fl" style="margin-bottom:6px">Admin Token</label>
    <input type="password" id="token-input" placeholder="Enter your ADMIN_TOKEN" autocomplete="off"/>
    <div class="login-err" id="login-err">❌ Invalid token. Try again.</div>
    <button class="btn btn-accent" style="width:100%;margin-top:14px;padding:12px;font-size:15px" onclick="doLogin()">Enter Dashboard</button>
  </div>
</div>

<!-- ── Sidebar ── -->
<div id="sidebar">
  <div class="sb-logo">
    <div class="badge">KPOS WINV10</div>
    <h2>Admin Panel</h2>
    <p>Vendor Control Room</p>
  </div>
  <nav class="sb-nav">
    <div class="nav-item active" data-section="licenses" onclick="nav(this,'licenses')">
      <span class="ic">🔑</span> License Manager
    </div>
    <div class="nav-item" data-section="analytics" onclick="nav(this,'analytics')">
      <span class="ic">📊</span> Analytics
    </div>
    <div class="nav-item" data-section="patches" onclick="nav(this,'patches')">
      <span class="ic">📦</span> Patch Notes
    </div>
    <div class="nav-item" data-section="health" onclick="nav(this,'health')">
      <span class="ic">💚</span> Server Health
    </div>
    <div class="nav-item" data-section="controls" onclick="nav(this,'controls')">
      <span class="ic">⚙️</span> Quick Controls
    </div>
  </nav>
  <div class="sb-footer">© 2025 @RT3M1S · KPOS WINV10</div>
</div>

<!-- ── Main ── -->
<div id="main">
  <div id="topbar">
    <h1 id="section-heading">License Manager</h1>
    <div class="tb-right">
      <span><span class="status-dot" id="srv-dot"></span><span id="srv-label" style="font-size:12px;color:var(--muted)">Connecting...</span></span>
      <button class="btn btn-sm" onclick="logout()">Logout</button>
    </div>
  </div>
  <div id="content">

    <!-- ════ LICENSES ════ -->
    <div class="section active" id="section-licenses">
      <div class="section-title">License Manager</div>
      <div class="section-sub">Issue, revoke, extend, and annotate customer licenses.</div>
      <div class="stat-grid" id="lic-stats"></div>

      <!-- Generate key -->
      <div class="card">
        <div class="card-title">Generate New Key</div>
        <div style="display:flex;gap:10px;align-items:flex-end">
          <div class="form-group" style="flex:1">
            <label class="fl">License Type</label>
            <select id="gen-type">
              <option value="monthly">Monthly (30 days)</option>
              <option value="yearly">Yearly (365 days)</option>
              <option value="perpetual">Perpetual (lifetime)</option>
            </select>
          </div>
          <button class="btn btn-accent" onclick="generateKey()">⚡ Generate Key</button>
        </div>
        <div class="new-key-box" id="new-key-box">
          <span class="key-text" id="new-key-text"></span>
          <button class="btn-copy" onclick="copyNewKey()">Copy</button>
        </div>
      </div>

      <!-- Filter bar -->
      <div class="filter-bar">
        <select id="f-status" onchange="applyFilter()">
          <option value="">All Statuses</option>
          <option value="active">Active</option>
          <option value="unused">Unused</option>
          <option value="suspended">Suspended</option>
        </select>
        <select id="f-type" onchange="applyFilter()">
          <option value="">All Types</option>
          <option value="monthly">Monthly</option>
          <option value="yearly">Yearly</option>
          <option value="perpetual">Perpetual</option>
        </select>
        <input id="f-search" placeholder="Search key or notes…" oninput="applyFilter()" style="width:220px"/>
        <span id="lic-count" style="font-size:12px;color:var(--muted);margin-left:auto"></span>
      </div>

      <div class="tbl-wrap">
        <table>
          <thead><tr>
            <th>Key</th><th>Type</th><th>Status</th><th>Device Bound</th>
            <th>Activated</th><th>Notes</th><th>Actions</th>
          </tr></thead>
          <tbody id="lic-tbody"></tbody>
        </table>
      </div>
    </div>

    <!-- ════ ANALYTICS ════ -->
    <div class="section" id="section-analytics">
      <div class="section-title">Analytics Dashboard</div>
      <div class="section-sub">Anonymous usage data from opted-in stores. Last 30 days.</div>
      <div class="stat-grid" id="ana-stats"></div>
      <div class="chart-grid">
        <div class="chart-box"><div class="card-title">Daily Active Stores</div><canvas id="dauChart"></canvas></div>
        <div class="chart-box"><div class="card-title">Feature Adoption</div><canvas id="featChart"></canvas></div>
      </div>
      <div class="two-col">
        <div class="card"><div class="card-title">Version Distribution</div><canvas id="verChart" style="max-height:180px"></canvas></div>
        <div class="card">
          <div class="card-title">Top 10 Stores by Transactions</div>
          <table><thead><tr><th>#</th><th>Device ID</th><th>Transactions</th><th>Version</th></tr></thead>
          <tbody id="top-tbody"></tbody></table>
        </div>
      </div>
    </div>

    <!-- ════ PATCH NOTES ════ -->
    <div class="section" id="section-patches">
      <div class="section-title">Patch Notes & Update Push</div>
      <div class="section-sub">Post updates. Customers see a banner or modal on next boot.</div>
      <div class="card">
        <div class="card-title">Post New Patch Note</div>
        <div class="form-row">
          <div class="form-group">
            <label class="fl">Version (e.g. 10.2.0)</label>
            <input id="p-version" placeholder="10.2.0"/>
          </div>
          <div class="form-group">
            <label class="fl">Title</label>
            <input id="p-title" placeholder="Version 10.2.0 Available"/>
          </div>
        </div>
        <div class="form-group" style="margin-bottom:12px">
          <label class="fl">Body (what changed)</label>
          <textarea id="p-body" placeholder="Bug fixes and performance improvements…"></textarea>
        </div>
        <div class="form-group" style="margin-bottom:12px">
          <label class="fl">Download URL (Google Drive direct link, optional)</label>
          <input id="p-url" placeholder="https://drive.google.com/uc?export=download&id=…"/>
        </div>
        <div style="display:flex;align-items:center;gap:12px;margin-bottom:14px">
          <label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:13px">
            <input type="checkbox" id="p-critical" style="width:auto"/>
            <span>Mark as <strong style="color:var(--danger)">Critical</strong> (popup every boot until updated)</span>
          </label>
        </div>
        <button class="btn btn-accent" onclick="postPatch()">📢 Post Patch Note</button>
      </div>
      <div class="card">
        <div class="card-title">Patch History</div>
        <div class="tbl-wrap">
          <table><thead><tr><th>Version</th><th>Title</th><th>Critical</th><th>Posted</th><th>Download</th><th>Actions</th></tr></thead>
          <tbody id="patch-tbody"></tbody></table>
        </div>
      </div>
    </div>

    <!-- ════ HEALTH ════ -->
    <div class="section" id="section-health">
      <div class="section-title">Server Health</div>
      <div class="section-sub">Live server status, memory, and log feed.</div>
      <div class="stat-grid" id="health-stats"></div>
      <div class="card">
        <div class="card-title">Live Log Feed (last 100 entries)</div>
        <div class="log-feed" id="log-feed"><div style="color:var(--muted)">Loading logs…</div></div>
      </div>
    </div>

    <!-- ════ CONTROLS ════ -->
    <div class="section" id="section-controls">
      <div class="section-title">Quick Controls</div>
      <div class="section-sub">Toggle server-wide flags instantly. Changes take effect immediately — no redeploy.</div>
      <div class="card">
        <div class="card-title">Server Switches</div>
        <div id="toggle-container"></div>
      </div>
    </div>

  </div><!-- /content -->
</div><!-- /main -->

<!-- ── Modals ── -->

<!-- Suspend (kill switch) modal -->
<div class="modal-overlay" id="modal-suspend">
  <div class="modal modal-danger">
    <h3>🚨 Suspend License for Non-Payment</h3>
    <p>This will immediately revoke the license. The customer's KPOS will lock on next boot (max 24h delay).</p>
    <p style="margin-bottom:4px">Key: <span class="key-mono" id="suspend-key-label"></span></p>
    <p style="color:var(--warn);margin-bottom:14px">Type <strong>CONFIRM</strong> below to proceed:</p>
    <input id="suspend-confirm-input" placeholder="Type CONFIRM here" style="margin-bottom:0"/>
    <div class="modal-footer">
      <button class="btn" onclick="closeModal('modal-suspend')">Cancel</button>
      <button class="btn btn-danger" onclick="confirmSuspend()">Suspend Now</button>
    </div>
  </div>
</div>

<!-- Revoke modal (immediate revoke, different label) -->
<div class="modal-overlay" id="modal-revoke">
  <div class="modal modal-danger">
    <h3>🔴 Revoke License</h3>
    <p>This will permanently revoke the license. The customer will be locked out on next validation.</p>
    <p style="margin-bottom:4px">Key: <span class="key-mono" id="revoke-key-label"></span></p>
    <p style="color:var(--warn);margin-bottom:14px">Type <strong>CONFIRM</strong> to proceed:</p>
    <input id="revoke-confirm-input" placeholder="Type CONFIRM here" style="margin-bottom:0"/>
    <div class="modal-footer">
      <button class="btn" onclick="closeModal('modal-revoke')">Cancel</button>
      <button class="btn btn-danger" onclick="confirmRevoke()">Revoke License</button>
    </div>
  </div>
</div>

<!-- Notes modal -->
<div class="modal-overlay" id="modal-notes">
  <div class="modal">
    <h3>📝 Edit Notes</h3>
    <p>Internal memo for this license (customer name, payment info, etc).</p>
    <input id="note-key-hidden" type="hidden"/>
    <textarea id="note-text" placeholder="e.g. Juan dela Cruz, GCash May 2026, ₱499" style="margin-bottom:0"></textarea>
    <div class="modal-footer">
      <button class="btn" onclick="closeModal('modal-notes')">Cancel</button>
      <button class="btn btn-accent" onclick="saveNote()">Save Note</button>
    </div>
  </div>
</div>

<script>
// ── [KPOS WINV10 P6B] Admin Panel JS ────────────────────────────────────────

let ADMIN_TOKEN = '';
let _licData    = [];
let _suspendKey = '';
let _revokeKey  = '';
let _charts     = {};

// ── Auth ─────────────────────────────────────────────────────────────────────
function doLogin() {
  const t = document.getElementById('token-input').value.trim();
  if (!t) return;
  ADMIN_TOKEN = t;
  api('GET', '/admin/api/health').then(data => {
    document.getElementById('login-screen').style.display = 'none';
    initDashboard();
  }).catch(() => {
    document.getElementById('login-err').style.display = 'block';
    ADMIN_TOKEN = '';
  });
}
document.getElementById('token-input').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });

function logout() {
  ADMIN_TOKEN = '';
  location.reload();
}

// ── API helper ────────────────────────────────────────────────────────────────
async function api(method, path, body) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json', 'X-Admin-Token': ADMIN_TOKEN },
  };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(path, opts);
  if (!res.ok && res.status === 401) { logout(); throw new Error('Unauthorized'); }
  return res.json();
}

// ── Navigation ────────────────────────────────────────────────────────────────
const SECTION_TITLES = {
  licenses: 'License Manager', analytics: 'Analytics',
  patches: 'Patch Notes', health: 'Server Health', controls: 'Quick Controls'
};
function nav(el, section) {
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  el.classList.add('active');
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.getElementById('section-' + section).classList.add('active');
  document.getElementById('section-heading').textContent = SECTION_TITLES[section] || section;
  if (section === 'licenses')  loadLicenses();
  if (section === 'analytics') loadAnalytics();
  if (section === 'patches')   loadPatches();
  if (section === 'health')    loadHealth();
  if (section === 'controls')  loadControls();
}

// ── Init ──────────────────────────────────────────────────────────────────────
function initDashboard() {
  loadLicenses();
  pingHealth();
}

// ── Health ping (topbar) ──────────────────────────────────────────────────────
async function pingHealth() {
  try {
    const d = await api('GET', '/admin/api/health');
    document.getElementById('srv-dot').className   = 'status-dot' + (d.server ? '' : ' red');
    document.getElementById('srv-label').textContent = d.server ? 'Server Online' : 'Server Error';
  } catch(e) {
    document.getElementById('srv-dot').className   = 'status-dot red';
    document.getElementById('srv-label').textContent = 'Offline';
  }
  setTimeout(pingHealth, 30000);
}

// ════════════════════════════════════════════════════════════════════
// LICENSES
// ════════════════════════════════════════════════════════════════════
async function loadLicenses() {
  try {
    const [lic, counts] = await Promise.all([
      api('GET', '/admin/api/licenses'),
      api('GET', '/admin/api/license-counts'),
    ]);
    _licData = lic.licenses || [];
    renderLicStats(counts);
    renderLicTable(_licData);
  } catch(e) {
    document.getElementById('lic-tbody').innerHTML = '<tr><td colspan="7" class="empty-state">Error loading licenses.</td></tr>';
  }
}

function renderLicStats(c) {
  document.getElementById('lic-stats').innerHTML = \`
    <div class="stat-card"><div class="stat-label">Total Keys</div><div class="stat-val val-accent">\${c.total||0}</div></div>
    <div class="stat-card"><div class="stat-label">Active</div><div class="stat-val val-green">\${c.active||0}</div></div>
    <div class="stat-card"><div class="stat-label">Unused</div><div class="stat-val val-warn">\${c.unused||0}</div></div>
    <div class="stat-card"><div class="stat-label">Suspended</div><div class="stat-val val-red">\${c.suspended||0}</div></div>
  \`;
}

function applyFilter() {
  const fStatus = document.getElementById('f-status').value;
  const fType   = document.getElementById('f-type').value;
  const fSearch = document.getElementById('f-search').value.toLowerCase();
  const filtered = _licData.filter(r => {
    const status = licStatus(r);
    if (fStatus && status !== fStatus) return false;
    if (fType && r.type !== fType) return false;
    if (fSearch && !(r.key.toLowerCase().includes(fSearch) || (r.notes||'').toLowerCase().includes(fSearch))) return false;
    return true;
  });
  renderLicTable(filtered);
}

function licStatus(r) {
  if (r.revoked) return 'suspended';
  if (!r.device_id) return 'unused';
  return 'active';
}

function renderLicTable(data) {
  document.getElementById('lic-count').textContent = data.length + ' license' + (data.length !== 1 ? 's' : '');
  if (!data.length) {
    document.getElementById('lic-tbody').innerHTML = '<tr><td colspan="7" class="empty-state">No licenses found.</td></tr>';
    return;
  }
  document.getElementById('lic-tbody').innerHTML = data.map(r => {
    const status = licStatus(r);
    const badges = { suspended: 'badge-red', active: 'badge-green', unused: 'badge-muted' };
    const badge  = \`<span class="badge \${badges[status]}">\${status}</span>\`;
    const typeBadge = \`<span class="badge badge-accent">\${r.type}</span>\`;
    const devId  = r.device_id ? \`<span class="truncate" title="\${r.device_id}">\${r.device_id.slice(0,12)}…</span>\` : '<span style="color:var(--muted)">—</span>';
    const actDate = r.activated_at ? new Date(r.activated_at).toLocaleDateString() : '—';
    const notes  = (r.notes||'').slice(0,50) || '<span style="color:var(--muted)">—</span>';
    const actions = \`
      <div style="display:flex;gap:4px;flex-wrap:wrap">
        <button class="btn btn-sm" onclick="copyText('\${r.key}')">Copy</button>
        \${!r.revoked ? \`<button class="btn btn-sm btn-danger" onclick="openSuspend('\${r.key}')">Suspend</button>\` : \`<button class="btn btn-sm btn-success" onclick="restoreKey('\${r.key}')">Restore</button>\`}
        <button class="btn btn-sm" onclick="openNotes('\${r.key}',\${JSON.stringify(r.notes||'').replace(/'/g,"&#39;")})">Notes</button>
      </div>\`;
    return \`<tr>
      <td><span class="key-mono">\${r.key}</span></td>
      <td>\${typeBadge}</td>
      <td>\${badge}</td>
      <td>\${devId}</td>
      <td>\${actDate}</td>
      <td style="max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">\${notes}</td>
      <td>\${actions}</td>
    </tr>\`;
  }).join('');
}

async function generateKey() {
  const type = document.getElementById('gen-type').value;
  try {
    const d = await api('POST', '/admin/api/licenses/create', { type });
    if (d.key) {
      document.getElementById('new-key-text').textContent = d.key;
      document.getElementById('new-key-box').style.display = 'flex';
      await loadLicenses();
    }
  } catch(e) { alert('Error: ' + e.message); }
}

function copyNewKey() {
  const k = document.getElementById('new-key-text').textContent;
  copyText(k);
  document.querySelector('#new-key-box .btn-copy').textContent = '✓ Copied!';
  setTimeout(() => { document.querySelector('#new-key-box .btn-copy').textContent = 'Copy'; }, 2000);
}

function openSuspend(key) {
  _suspendKey = key;
  document.getElementById('suspend-key-label').textContent = key;
  document.getElementById('suspend-confirm-input').value = '';
  openModal('modal-suspend');
}

async function confirmSuspend() {
  if (document.getElementById('suspend-confirm-input').value.trim() !== 'CONFIRM') {
    alert('Type CONFIRM exactly to proceed.');
    return;
  }
  try {
    await api('POST', '/admin/api/licenses/revoke', { key: _suspendKey });
    closeModal('modal-suspend');
    await loadLicenses();
  } catch(e) { alert('Error: ' + e.message); }
}

async function restoreKey(key) {
  if (!confirm('Restore access for key: ' + key + '?')) return;
  try {
    await api('POST', '/admin/api/licenses/restore', { key });
    await loadLicenses();
  } catch(e) { alert('Error: ' + e.message); }
}

function openNotes(key, notes) {
  document.getElementById('note-key-hidden').value = key;
  document.getElementById('note-text').value = typeof notes === 'string' ? notes : '';
  openModal('modal-notes');
}

async function saveNote() {
  const key   = document.getElementById('note-key-hidden').value;
  const notes = document.getElementById('note-text').value;
  try {
    await api('POST', '/admin/api/licenses/note', { key, notes });
    closeModal('modal-notes');
    await loadLicenses();
  } catch(e) { alert('Error: ' + e.message); }
}

// (unused but kept for completeness — revoke modal accessible via openRevoke)
function openRevoke(key) {
  _revokeKey = key;
  document.getElementById('revoke-key-label').textContent = key;
  document.getElementById('revoke-confirm-input').value = '';
  openModal('modal-revoke');
}
async function confirmRevoke() {
  if (document.getElementById('revoke-confirm-input').value.trim() !== 'CONFIRM') {
    alert('Type CONFIRM exactly to proceed.'); return;
  }
  try {
    await api('POST', '/admin/api/licenses/revoke', { key: _revokeKey });
    closeModal('modal-revoke');
    await loadLicenses();
  } catch(e) { alert('Error: ' + e.message); }
}

// ════════════════════════════════════════════════════════════════════
// ANALYTICS
// ════════════════════════════════════════════════════════════════════
async function loadAnalytics() {
  try {
    const [summary, dau, features, versions, topdevices] = await Promise.all([
      api('GET', '/admin/api/analytics/summary'),
      api('GET', '/admin/api/analytics/dau'),
      api('GET', '/admin/api/analytics/features'),
      api('GET', '/admin/api/analytics/versions'),
      api('GET', '/admin/api/analytics/topdevices'),
    ]);
    renderAnaStats(summary);
    renderDAU(dau.dau || []);
    renderFeatures(features.features || []);
    renderVersions(versions.versions || []);
    renderTopDevices(topdevices.devices || []);
  } catch(e) {
    document.getElementById('ana-stats').innerHTML = '<div class="empty-state">Error loading analytics.</div>';
  }
}

function renderAnaStats(s) {
  document.getElementById('ana-stats').innerHTML = \`
    <div class="stat-card"><div class="stat-label">Active Installs (30d)</div><div class="stat-val val-accent">\${s.activeInstalls||0}</div></div>
    <div class="stat-card"><div class="stat-label">Total Transactions</div><div class="stat-val val-green">\${(s.totalTx||0).toLocaleString()}</div></div>
    <div class="stat-card"><div class="stat-label">Avg Session (mins)</div><div class="stat-val val-warn">\${s.avgSessionMins||0}</div></div>
    <div class="stat-card"><div class="stat-label">Total Devices Seen</div><div class="stat-val">\${s.totalDevices||0}</div></div>
  \`;
}

function destroyChart(id) {
  if (_charts[id]) { _charts[id].destroy(); delete _charts[id]; }
}

function renderDAU(data) {
  destroyChart('dau');
  const ctx = document.getElementById('dauChart').getContext('2d');
  _charts['dau'] = new Chart(ctx, {
    type: 'line',
    data: { labels: data.map(d => d.date.slice(5)), datasets: [{ label: 'Active Stores', data: data.map(d => d.count), borderColor: '#7c5cfc', backgroundColor: 'rgba(124,92,252,.1)', fill: true, tension: .3, pointRadius: 2 }] },
    options: { plugins: { legend: { display: false } }, scales: { x: { grid: { color: '#1f2128' }, ticks: { color: '#6b7280', maxTicksLimit: 7 } }, y: { grid: { color: '#1f2128' }, ticks: { color: '#6b7280', precision: 0 }, beginAtZero: true } } }
  });
}

function renderFeatures(data) {
  destroyChart('feat');
  const ctx = document.getElementById('featChart').getContext('2d');
  _charts['feat'] = new Chart(ctx, {
    type: 'bar',
    data: { labels: data.map(d => d.label), datasets: [{ data: data.map(d => d.pct), backgroundColor: '#7c5cfc', borderRadius: 4 }] },
    options: { indexAxis: 'y', plugins: { legend: { display: false } }, scales: { x: { grid: { color: '#1f2128' }, ticks: { color: '#6b7280', callback: v => v + '%' }, max: 100 }, y: { grid: { display: false }, ticks: { color: '#6b7280', font: { size: 11 } } } } }
  });
}

function renderVersions(data) {
  destroyChart('ver');
  const ctx = document.getElementById('verChart').getContext('2d');
  const colors = ['#7c5cfc','#22c55e','#f59e0b','#ef4444','#3ecfcf','#a78bfa'];
  _charts['ver'] = new Chart(ctx, {
    type: 'doughnut',
    data: { labels: data.map(d => 'v' + d.version), datasets: [{ data: data.map(d => d.count), backgroundColor: colors, borderWidth: 0 }] },
    options: { plugins: { legend: { position: 'bottom', labels: { color: '#6b7280', font: { size: 11 } } } } }
  });
}

function renderTopDevices(data) {
  document.getElementById('top-tbody').innerHTML = data.length
    ? data.map((d, i) => \`<tr><td>\${i+1}</td><td><span class="key-mono">\${d.device_id.slice(0,12)}…</span></td><td>\${(d.tx_count||0).toLocaleString()}</td><td>\${d.app_version||'—'}</td></tr>\`).join('')
    : '<tr><td colspan="4" class="empty-state">No data yet.</td></tr>';
}

// ════════════════════════════════════════════════════════════════════
// PATCH NOTES
// ════════════════════════════════════════════════════════════════════
async function loadPatches() {
  try {
    const d = await api('GET', '/admin/api/patches');
    renderPatches(d.patches || []);
  } catch(e) { document.getElementById('patch-tbody').innerHTML = '<tr><td colspan="6" class="empty-state">Error loading patches.</td></tr>'; }
}

function renderPatches(data) {
  document.getElementById('patch-tbody').innerHTML = data.length
    ? data.map(p => \`<tr>
        <td><span class="badge badge-accent">v\${p.version}</span></td>
        <td>\${escHtml(p.title)}</td>
        <td>\${p.is_critical ? '<span class="critical-badge">CRITICAL</span>' : '—'}</td>
        <td>\${new Date(p.created_at).toLocaleString()}</td>
        <td>\${p.download_url ? \`<a href="\${p.download_url}" target="_blank">Link</a>\` : '—'}</td>
        <td><button class="btn btn-sm btn-danger" onclick="deletePatch(\${p.id})">Delete</button></td>
      </tr>\`).join('')
    : '<tr><td colspan="6" class="empty-state">No patch notes yet.</td></tr>';
}

async function postPatch() {
  const version     = document.getElementById('p-version').value.trim();
  const title       = document.getElementById('p-title').value.trim();
  const body        = document.getElementById('p-body').value.trim();
  const download_url = document.getElementById('p-url').value.trim();
  const is_critical = document.getElementById('p-critical').checked;
  if (!version || !title || !body) { alert('Version, title and body are required.'); return; }
  try {
    await api('POST', '/admin/api/patches/create', { version, title, body, download_url, is_critical });
    document.getElementById('p-version').value = '';
    document.getElementById('p-title').value = '';
    document.getElementById('p-body').value = '';
    document.getElementById('p-url').value = '';
    document.getElementById('p-critical').checked = false;
    await loadPatches();
  } catch(e) { alert('Error: ' + e.message); }
}

async function deletePatch(id) {
  if (!confirm('Delete this patch note?')) return;
  try {
    await api('DELETE', '/admin/api/patches/' + id);
    await loadPatches();
  } catch(e) { alert('Error: ' + e.message); }
}

// ════════════════════════════════════════════════════════════════════
// SERVER HEALTH
// ════════════════════════════════════════════════════════════════════
async function loadHealth() {
  try {
    const [health, counts] = await Promise.all([
      api('GET', '/admin/api/health'),
      api('GET', '/admin/api/license-counts'),
    ]);
    const upMin = Math.floor(health.uptime / 60);
    document.getElementById('health-stats').innerHTML = \`
      <div class="stat-card"><div class="stat-label">Server</div><div class="stat-val" style="font-size:28px">\${health.server ? '🟢' : '🔴'}</div><div class="stat-sub">\${health.server ? 'Online' : 'Error'}</div></div>
      <div class="stat-card"><div class="stat-label">Database</div><div class="stat-val" style="font-size:28px">\${health.db ? '🟢' : '🔴'}</div><div class="stat-sub">\${health.db ? 'Connected' : 'Disconnected'}</div></div>
      <div class="stat-card"><div class="stat-label">Uptime</div><div class="stat-val val-accent">\${upMin}m</div><div class="stat-sub">\${health.memMB}MB RAM</div></div>
      <div class="stat-card"><div class="stat-label">Total Licenses</div><div class="stat-val">\${counts.total||0}</div><div class="stat-sub">\${counts.active||0} active</div></div>
    \`;
    renderLogs(health.logs || []);
  } catch(e) {
    document.getElementById('health-stats').innerHTML = '<div class="empty-state">Error loading health data.</div>';
  }
}

function renderLogs(logs) {
  const feed = document.getElementById('log-feed');
  if (!logs.length) { feed.innerHTML = '<div style="color:var(--muted)">No logs yet.</div>'; return; }
  feed.innerHTML = logs.map(l => {
    const ts = new Date(l.ts).toLocaleTimeString();
    const line = escHtml(l.line);
    return \`<div class="log-line"><span style="color:var(--muted);margin-right:8px">\${ts}</span>\${line}</div>\`;
  }).join('');
}

// ════════════════════════════════════════════════════════════════════
// QUICK CONTROLS
// ════════════════════════════════════════════════════════════════════
const CONFIG_META = {
  activations_enabled: { label: 'License Activations', desc: 'If OFF, no new licenses can be activated (maintenance mode).' },
  analytics_enabled:   { label: 'Analytics Ingestion', desc: 'If OFF, server rejects all analytics pings.' },
  trials_allowed:      { label: 'Trial Mode',          desc: 'If OFF, new devices cannot start a trial period (paid-only mode).' },
  updates_enabled:     { label: 'Update Banner',       desc: 'If OFF, patch note popups are suppressed on all client boots.' },
};

async function loadControls() {
  try {
    const d = await api('GET', '/admin/api/config');
    const config = d.config || {};
    document.getElementById('toggle-container').innerHTML = Object.entries(CONFIG_META).map(([key, meta]) => {
      const isOn = config[key] !== 'false';
      return \`<div class="toggle-wrap">
        <div class="toggle-info">
          <h4>\${meta.label}</h4>
          <p>\${meta.desc}</p>
        </div>
        <label class="toggle">
          <input type="checkbox" \${isOn ? 'checked' : ''} onchange="toggleConfig('\${key}', this.checked)"/>
          <span class="slider"></span>
        </label>
      </div>\`;
    }).join('');
  } catch(e) {
    document.getElementById('toggle-container').innerHTML = '<div class="empty-state">Error loading config.</div>';
  }
}

async function toggleConfig(key, value) {
  try {
    await api('POST', '/admin/api/config', { key, value: String(value) });
  } catch(e) {
    alert('Error saving config: ' + e.message);
    await loadControls(); // revert UI
  }
}

// ── Modals ────────────────────────────────────────────────────────────────────
function openModal(id)  { document.getElementById(id).classList.add('open'); }
function closeModal(id) { document.getElementById(id).classList.remove('open'); }
document.querySelectorAll('.modal-overlay').forEach(el => {
  el.addEventListener('click', e => { if (e.target === el) el.classList.remove('open'); });
});

// ── Utils ─────────────────────────────────────────────────────────────────────
function copyText(text) {
  navigator.clipboard.writeText(text).catch(() => {
    const ta = document.createElement('textarea');
    ta.value = text; document.body.appendChild(ta); ta.select();
    document.execCommand('copy'); document.body.removeChild(ta);
  });
}
function escHtml(str) {
  return String(str||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
</script>
</body>
</html>`;

module.exports = router;
