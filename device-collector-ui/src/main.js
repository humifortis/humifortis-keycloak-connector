/**
 * Humifortis Device Collector — main entry point  v2.2
 *
 * v2.2 additions (free hardening, no FingerprintJS Pro required):
 *  1. WebGL canvas dedup — single GL context for vendor+renderer, prevents inconsistency.
 *  2. device_touch_points — actual maxTouchPoints count (0/1/5/10), not just boolean.
 *  3. device_orientation — screen.orientation.type ("portrait-primary" etc).
 *  4. device_hash_perf_ms — SubtleCrypto SHA-256 CPU benchmark.
 *       Real browser on real hardware: 1-15ms. Slow VM/bot farm: 50-200ms. Blocked: absent.
 *
 * v2.1 (in place):
 *  - Truncation fix: sha256hex(full JSON) + buildSignalsSubset (always valid JSON)
 *  - Anti-replay nonce: binding = SHA-256(nonce:timestamp:visitorId)
 *  - Platform: UACH → UA parse → navigator.platform (3-tier degradation)
 */
import FingerprintJS from '@fingerprintjs/fingerprintjs'

const MAX_WAIT_MS  = 3000
const PAGE_LOAD_AT = Date.now()

async function collect() {
  const form = document.getElementById('kc-device-collector')
  if (!form) return

  let submitted = false

  const safetyTimer = setTimeout(() => {
    if (!submitted) {
      submitted = true
      console.debug('[Humifortis] Safety timer: submitting without full device data')
      form.submit()
    }
  }, MAX_WAIT_MS)

  try {
    const fp     = await FingerprintJS.load()
    const result = await fp.get()

    // ── STABLE ────────────────────────────────────────────────────────────────
    setField('device_id', result.visitorId)

    // FP signals: SHA-256 hash of FULL components + structured high-entropy subset.
    // device_fp_hash → stable reference for cross-login drift detection (two-signal matrix)
    // device_signals → always-valid JSON subset (canvas, audio, counts) under 2 KB
    const signalsJson = JSON.stringify(result.components)
    const fpHash = await sha256hex(signalsJson)
    if (fpHash) setField('device_fp_hash', fpHash)
    setField('device_signals', JSON.stringify(buildSignalsSubset(result.components)))

    // ── ANTI-REPLAY BINDING ───────────────────────────────────────────────────
    const serverNonce  = safeGet(() => document.getElementById('device_nonce')?.value) || ''
    const collectionTs = Date.now()
    setField('device_timestamp', String(collectionTs))
    if (serverNonce && result.visitorId) {
      const binding = await sha256hex(`${serverNonce}:${collectionTs}:${result.visitorId}`)
      if (binding) setField('device_binding', binding)
    }

    // ── CONTEXTUAL ────────────────────────────────────────────────────────────
    setField('device_tz',          safeGet(() => Intl.DateTimeFormat().resolvedOptions().timeZone))
    setField('device_screen',      safeGet(() => `${screen.width}x${screen.height}`))
    setField('device_lang',        safeGet(() => navigator.language))
    setField('device_color_depth', safeGet(() => String(screen.colorDepth)))

    // ── HARDWARE ──────────────────────────────────────────────────────────────
    setField('device_cpu_cores',  safeGet(() => String(navigator.hardwareConcurrency)))
    setField('device_memory_gb',  safeGet(() => String(navigator.deviceMemory)))
    setField('device_touch',      safeGet(() => String(navigator.maxTouchPoints > 0)))

    // Platform: UACH → UA parse → navigator.platform (last resort)
    setField('device_platform', safeGet(() => {
      if (navigator.userAgentData?.platform) return navigator.userAgentData.platform
      const ua = navigator.userAgent
      if (/iP(hone|od)/.test(ua))        return 'iOS'
      if (/iPad/.test(ua))               return 'iPadOS'
      if (/Android/.test(ua))            return 'Android'
      if (/Win/.test(ua))                return 'Windows'
      if (/Mac OS X|Macintosh/.test(ua)) return 'macOS'
      if (/Linux/.test(ua))              return 'Linux'
      if (/CrOS/.test(ua))               return 'ChromeOS'
      // eslint-disable-next-line no-restricted-globals
      return navigator.platform || null
    }))

    setField('device_connection', safeGet(() => {
      const c = navigator.connection || navigator.mozConnection || navigator.webkitConnection
      return c ? (c.effectiveType || c.type || 'unknown') : null
    }))

    // ── GPU — single canvas context (v2.2: dedup prevents inconsistency) ──────
    const glInfo = safeGet(() => {
      const canvas = document.createElement('canvas')
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl')
      if (!gl) return null
      const ext = gl.getExtension('WEBGL_debug_renderer_info')
      if (!ext) return null
      return {
        vendor:   gl.getParameter(ext.UNMASKED_VENDOR_WEBGL),
        renderer: gl.getParameter(ext.UNMASKED_RENDERER_WEBGL),
      }
    })
    if (glInfo) {
      setField('device_webgl_vendor',   safeGet(() => glInfo.vendor))
      setField('device_webgl_renderer', safeGet(() => glInfo.renderer))
    }

    // ── PASSIVE DISCRIMINATORS (v2.2) ─────────────────────────────────────────

    // Actual touch point count: 0=desktop, 1=pen tablet, 5=phone, 10=high-end tablet.
    // More discriminant than boolean. Used in server-side two-signal drift matrix.
    setField('device_touch_points', safeGet(() => String(navigator.maxTouchPoints)))

    // Screen orientation: "portrait-primary"|"landscape-primary"|"landscape-secondary".
    // Mobile defaults to portrait-primary; desktops typically landscape-primary or absent.
    setField('device_orientation', safeGet(() => screen.orientation?.type || null))

    // SubtleCrypto SHA-256 benchmark (ms) — lightweight CPU speed signal.
    //   Real browser/hardware: 1-15ms  (native crypto acceleration)
    //   Slow VM / bot farm:    50-200ms (software fallback, shared CPU)
    //   SubtleCrypto blocked:  field absent (itself a signal)
    // Must run AFTER fp.get() so it does not distort device_load_ms.
    const hashBenchStart = performance.now()
    await sha256hex('humifortis-benchmark-probe')
    setField('device_hash_perf_ms', String(Math.round(performance.now() - hashBenchStart)))

    // ── BEHAVIORAL ────────────────────────────────────────────────────────────
    // DetectBotLoadTime: <50ms=headless, 200-1500ms=human, >8000ms=safety timer
    setField('device_load_ms', safeGet(() => String(Date.now() - PAGE_LOAD_AT)))

  } catch (err) {
    console.debug('[Humifortis] FingerprintJS error (non-blocking):', err)
  } finally {
    clearTimeout(safetyTimer)
    if (!submitted) {
      submitted = true
      form.submit()
    }
  }
}

/**
 * sha256hex — SHA-256 via SubtleCrypto (W3C standard, non-deprecated, all modern browsers).
 * Returns lowercase hex string, or null on any error (fail-open — never blocks login).
 */
async function sha256hex(data) {
  try {
    const buf    = new TextEncoder().encode(data)
    const digest = await crypto.subtle.digest('SHA-256', buf)
    return Array.from(new Uint8Array(digest))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
  } catch (_) {
    return null
  }
}

/**
 * buildSignalsSubset — highest-entropy FP components, always valid JSON, always < 2 KB.
 * canvas + audio: highest entropy (rendered hashes, very stable between logins).
 * fonts/plugins: summarised as counts to avoid list bloat.
 * Full JSON SHA-256 sent separately as device_fp_hash.
 */
function buildSignalsSubset(components) {
  const c = components || {}
  return {
    canvas:        safeGet(() => c.canvas?.value         ?? null),
    audio:         safeGet(() => c.audio?.value          ?? null),
    fonts_count:   safeGet(() => Array.isArray(c.fonts?.value)   ? c.fonts.value.length   : null),
    plugins_count: safeGet(() => Array.isArray(c.plugins?.value) ? c.plugins.value.length : null),
    webgl:         safeGet(() => c.webgl?.value          ?? null),
    color_gamut:   safeGet(() => c.colorGamut?.value     ?? null),
  }
}

function setField(id, value) {
  const el = document.getElementById(id)
  if (el && value != null && value !== 'undefined' && value !== 'null') {
    el.value = value
  }
}

function safeGet(fn) {
  try {
    const v = fn()
    return (v === undefined || v === null) ? null : v
  } catch (_) {
    return null
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', collect)
} else {
  collect()
}
