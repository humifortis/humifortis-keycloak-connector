/**
 * Humifortis Device Collector — main entry point  v2.5
 *
 * v2.5 — Removed localStorage UUID (spoofable). Device identity strategy:
 *
 *   device_id  = FingerprintJS free visitorId (hardware-derived, hard to fake at scale).
 *                NOT a security secret — used only for device recognition heuristics.
 *
 *   TRUST is established exclusively via the HttpOnly cookie "hf_trust":
 *     - Generated server-side (Java/Keycloak) after explicit MFA + "Trust this device"
 *     - Never readable by JS (HttpOnly) — impossible to spoof from the browser
 *     - SHA-256(cookie) matched server-side → browser_token_valid = true → ALLOW
 *
 *   Why NOT localStorage UUID (v2.4 approach):
 *     - Trivially spoofable: localStorage.setItem('hf_device_id', victimUUID)
 *     - Adds no security — the cookie already handles trusted-device bypass
 *     - FingerprintJS visitorId requires matching real hardware signals to spoof
 *
 * v2.3 additions — Math/FPU fingerprint (anti-VM, anti-spoof):
 *  1. device_math_hash     — SHA-256 of stableStringify(Math results).
 *  2. device_fpu_class     — "arm64"|"x86_64"|"unknown".
 *  3. device_math_anomaly  — "1" if NaN/Infinity detected.
 *  4. device_math_exec_ms  — Math.sin(1) timing in µs.
 *  5. device_math_consistency — abs(sin²+cos²−1) deviation.
 *
 * v2.2: WebGL dedup, touch_points, orientation, hash_perf_ms.
 * v2.1: sha256hex full JSON, anti-replay nonce, platform 3-tier degradation.
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

    // ── STABLE DEVICE IDENTITY ────────────────────────────────────────────────
    // device_id = FingerprintJS visitorId: hardware-derived, not a security secret.
    // Trusted-device bypass is handled exclusively by the server-issued HttpOnly
    // "hf_trust" cookie (browser_token_valid signal in the risk pipeline).
    setField('device_id', result.visitorId)

    // FP signals: SHA-256 of full components JSON + high-entropy structured subset.
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
    setField('device_memory_gb',  safeGet(() => {
      const m = navigator.deviceMemory
      return m !== undefined ? String(m) : 'unknown'
    }))
    setField('device_touch',      safeGet(() => String(navigator.maxTouchPoints > 0)))

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
      return c ? (c.effectiveType || c.type || 'unknown') : 'unknown'
    }))

    // ── GPU (v2.2 dedup: single context) ─────────────────────────────────────
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
    setField('device_touch_points', safeGet(() => String(navigator.maxTouchPoints)))
    setField('device_orientation',  safeGet(() => screen.orientation?.type || null))

    const hashBenchStart = performance.now()
    await sha256hex('humifortis-benchmark-probe')
    setField('device_hash_perf_ms', String(Math.round(performance.now() - hashBenchStart)))

    // ── MATH / FPU FINGERPRINT (v2.3) ─────────────────────────────────────────
    const mathRaw = safeGet(() => {
      const r = {}
      r.sin    = Math.sin(-1e300)
      r.cos    = Math.cos(10.000000000123)
      r.tan    = Math.tan(10.000000000123)
      r.asin   = Math.asin(0.123124234234234242)
      r.acos   = Math.acos(0.123124234234234242)
      r.atan   = Math.atan(0.5)
      r.atan2  = Math.atan2(1e-310, 1e-310)
      r.sinh   = Math.sinh(1)
      r.cosh   = Math.cosh(10)
      r.tanh   = Math.tanh(-2)
      r.log    = Math.log(1e-310)
      r.log1p  = Math.log1p(-9.881312916824931e-324)
      r.log2   = Math.log2(1e-310)
      r.exp    = Math.exp(1)
      r.expm1  = Math.expm1(1)
      r.pow    = Math.pow(-1e300, -1)
      r.sqrt   = Math.sqrt(1e-310)
      r.cbrt   = Math.cbrt(100)
      r.hypot  = Math.hypot(1, 2)
      r.clz32  = Math.clz32(1)
      r.imul   = Math.imul(Math.pow(2, 53), 5)
      r.fround = Math.fround(5.5)
      r.sign   = Math.sign(-0)
      r.trunc  = Math.trunc(-0.5)
      r.round  = Math.round(-0.5)
      r.ceil   = Math.ceil(-1e-10)
      r._neg_zero = (1 / Math.sign(-0)) === -Infinity ? '-0' : '0'
      return r
    })

    if (mathRaw) {
      const anomaly = Object.values(mathRaw).some(v =>
        typeof v === 'number' && (Number.isNaN(v) || !Number.isFinite(v)))
      setField('device_math_anomaly', anomaly ? '1' : '0')

      const armHints = [
        mathRaw.fround !== 5.5,
        mathRaw.atan2  !== 0.7853981633974483,
        mathRaw.log1p  !== -Infinity,
      ]
      const armScore = armHints.filter(Boolean).length
      setField('device_fpu_class', armScore >= 2 ? 'arm64' : armScore === 0 ? 'x86_64' : 'unknown')

      const mathHash = await sha256hex(stableStringify(mathRaw))
      if (mathHash) setField('device_math_hash', mathHash)

      const consVal = safeGet(() => {
        const x = 10.000000000123
        return Math.abs(Math.sin(x) * Math.sin(x) + Math.cos(x) * Math.cos(x) - 1.0)
      })
      if (consVal !== null) setField('device_math_consistency', consVal.toFixed(6))

      const mt0 = performance.now()
      Math.sin(1)
      setField('device_math_exec_ms', ((performance.now() - mt0) * 1000).toFixed(3))
    }

    // ── BEHAVIORAL ────────────────────────────────────────────────────────────
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
 * stableStringify — canonical JSON for Math objects (order-independent, IEEE-normalised).
 */
function stableStringify(obj) {
  return JSON.stringify(
    Object.keys(obj).sort().reduce((acc, key) => {
      let v = obj[key]
      if (typeof v === 'number') {
        if      (Number.isNaN(v))  v = 'NaN'
        else if (v === Infinity)   v = '+Infinity'
        else if (v === -Infinity)  v = '-Infinity'
        else                       v = Number(v.toPrecision(15))
      }
      acc[key] = v
      return acc
    }, {})
  )
}

/**
 * sha256hex — SHA-256 via SubtleCrypto. Returns hex string or null (fail-open).
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
    math_hash:     safeGet(() => document.getElementById('device_math_hash')?.value  || null),
    fpu_class:     safeGet(() => document.getElementById('device_fpu_class')?.value  || null),
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
