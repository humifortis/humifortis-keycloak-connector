<#-- ============================================================
     Humifortis Device Collector — transparent collection page

     This page is served by HumifortisDeviceCollectorAuthenticator
     immediately after the username/password form.

     The user sees nothing — the bundle runs, collects signals,
     and auto-submits the form within ~1-3 seconds.

     The <noscript> block provides a manual fallback for browsers
     with JavaScript disabled.

     DEPLOYMENT (JAR mode — recommended):
       This file lives in theme-resources/templates/ inside the JAR.
       It is accessible to ANY login theme automatically.
       The JS bundle must be in:
         themes/<your-theme>/login/resources/js/humifortis-device.bundle.js
       Referenced via ${url.resourcesPath}/js/humifortis-device.bundle.js.

     STANDALONE (copy mode — alternative):
       Copy this file to your Keycloak theme:
         themes/<your-theme>/login/humifortis-device-collector.ftl
       Copy the JS bundle to:
         themes/<your-theme>/login/resources/js/humifortis-device.bundle.js
     ============================================================ -->
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${kcSanitize(msg("loginTitle", realm.name))?no_esc}</title>
  <style>
    /*
     * Invisible page — user sees nothing while device signals are collected.
     * The body background matches the Keycloak login page so there is no
     * visible flash between the password form and the next step.
     * The spinner div is hidden by default; reveal it via JS if you want
     * to show a "Securing…" indicator for slow connections.
     */
    html, body {
      margin: 0;
      padding: 0;
      width: 100%;
      height: 100%;
      /* Inherit the Keycloak theme background so the transition is seamless */
      background: var(--kc-background, #f0f0f0);
      overflow: hidden;
    }
    #collecting-indicator {
      display: flex;
      flex-direction: column;
      align-items: center; /* visible — shows "Securing your session…" spinner during collection */
      position: fixed;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      text-align: center;
      font-family: sans-serif;
      font-size: 14px;
      color: #555;
      opacity: 0.7;
    }
    .spinner {
      width: 24px;
      height: 24px;
      border: 3px solid #ddd;
      border-top-color: #555;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
      margin: 0 auto 8px;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    /* noscript fallback — only shown when JS is disabled */
    .noscript-box {
      position: fixed;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      padding: 24px 32px;
      border: 1px solid #ccc;
      border-radius: 8px;
      background: #fff;
      font-family: sans-serif;
      text-align: center;
    }
    .noscript-box button {
      margin-top: 12px;
      padding: 8px 20px;
      border: none;
      border-radius: 4px;
      background: #0066cc;
      color: #fff;
      font-size: 14px;
      cursor: pointer;
    }
  </style>
</head>
<body>

  <!-- Hidden form — auto-submitted by the JS bundle (user never sees this) -->
  <form id="kc-device-collector"
        method="post"
        action="${url.loginAction}">

    <!-- ANTI-REPLAY BINDING (v2.1)
         device_nonce     : server-generated UUID, embedded by authenticate() via FTL attribute.
                            JS reads it to compute binding = SHA-256(nonce:timestamp:visitorId).
         device_timestamp : Unix ms when JS collection ran (stale check server-side).
         device_binding   : SHA-256(nonce:timestamp:visitorId) — computed by JS, validated by Java.
    -->
    <input type="hidden" id="device_nonce"     name="device_nonce"     value="${deviceNonce!''}" />
    <input type="hidden" id="device_timestamp" name="device_timestamp" value="" />
    <input type="hidden" id="device_binding"   name="device_binding"   value="" />

    <!-- STABLE signals -->
    <input type="hidden" id="device_id"       name="device_id"       value="" />
    <!-- device_fp_hash: SHA-256 of full FP components JSON (replaces truncated blob) -->
    <input type="hidden" id="device_fp_hash"  name="device_fp_hash"  value="" />
    <!-- device_signals: high-entropy structured subset, always valid JSON, always < 2 KB -->
    <input type="hidden" id="device_signals"  name="device_signals"  value="" />

    <!-- CONTEXTUAL signals -->
    <input type="hidden" id="device_tz"           name="device_tz"          value="" />
    <input type="hidden" id="device_screen"       name="device_screen"      value="" />
    <input type="hidden" id="device_lang"         name="device_lang"        value="" />
    <input type="hidden" id="device_color_depth"  name="device_color_depth" value="" />

    <!-- HARDWARE signals -->
    <input type="hidden" id="device_cpu_cores"       name="device_cpu_cores"       value="" />
    <input type="hidden" id="device_memory_gb"       name="device_memory_gb"       value="" />
    <input type="hidden" id="device_touch"           name="device_touch"           value="" />
    <input type="hidden" id="device_platform"        name="device_platform"        value="" />
    <input type="hidden" id="device_connection"      name="device_connection"      value="" />

    <!-- GPU signals (device.webgl_vendor T2, device.webgl_renderer T3) -->
    <input type="hidden" id="device_webgl_vendor"    name="device_webgl_vendor"    value="" />
    <input type="hidden" id="device_webgl_renderer"  name="device_webgl_renderer"  value="" />

    <!-- PASSIVE DISCRIMINATORS (v2.2) -->
    <!-- touch_points: actual count (0=desktop,1=pen,5=phone,10=tablet) — more discriminant than boolean -->
    <input type="hidden" id="device_touch_points"  name="device_touch_points"  value="" />
    <!-- orientation: "portrait-primary"|"landscape-primary" — mobile vs desktop classifier -->
    <input type="hidden" id="device_orientation"   name="device_orientation"   value="" />
    <!-- hash_perf_ms: SHA-256 CPU benchmark — 1-15ms=real browser, 50-200ms=slow VM/bot -->
    <input type="hidden" id="device_hash_perf_ms"  name="device_hash_perf_ms"  value="" />

    <!-- BEHAVIORAL signal -->
    <input type="hidden" id="device_load_ms"      name="device_load_ms"     value="" />

    <!-- Fallback: only visible when JavaScript is disabled -->
    <noscript>
      <div class="noscript-box">
        <p>${msg("humifortis.deviceCollector.noscript", "Please click Continue to proceed.")}</p>
        <button type="submit">${msg("humifortis.deviceCollector.continueBtn", "Continue")}</button>
      </div>
    </noscript>
  </form>

  <!--
    Optional "Securing your session…" indicator.
    Hidden by default (display:none in CSS).
    To enable: uncomment the line below in the JS bundle or add:
      document.getElementById('collecting-indicator').style.display = 'block'
  -->
  <div id="collecting-indicator">
    <div class="spinner"></div>
    <span>${msg("humifortis.deviceCollector.securing", "Securing your session…")}</span>
  </div>

  <!--
    Inline safety timer — submits the form after 8s as a last-resort fallback if the
    bundle FAILS TO LOAD entirely (network error, 404, etc.).
    This runs BEFORE the bundle so the timer is guaranteed to be set.

    NOTE: The bundle does NOT cancel this timer — it cancels only its own internal 3s timer.
    In practice this is harmless: when the bundle submits the form at ~1-3s, the browser
    navigates away and the old page's timers are cleared automatically.
    This 8s timer only fires if the bundle never executes at all.
  -->
  <script>
    (function() {
      var _hfSafety = setTimeout(function() {
        var form = document.getElementById('kc-device-collector');
        if (form) {
          console.debug('[Humifortis] Inline 8s safety timer: bundle did not load — submitting empty form');
          form.submit();
        }
      }, 8000);
      // Exposed for diagnostic purposes (not cancelled by bundle — see note above)
      window.__hfSafetyTimer = _hfSafety;
    })();
  </script>

  <!--
    Humifortis device bundle — Vite IIFE build, self-contained.
    Placed at end of <body>: DOM is already ready when this runs,
    so collect() is called synchronously (no DOMContentLoaded wait).
  -->
  <script src="${url.resourcesPath}/js/humifortis-device.bundle.js"></script>

</body>
</html>
