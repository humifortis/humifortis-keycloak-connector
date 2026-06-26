#!/usr/bin/env bash
# =============================================================================
# build-all.sh — Build Java connector JAR + JS device collector bundle
#
# Usage:
#   ./build-all.sh                   # full build
#   ./build-all.sh --js-only         # rebuild JS bundle only
#   ./build-all.sh --java-only       # rebuild Java JAR only
#
# Output:
#   humifortis-keycloak-connector.jar        ← deploy to Keycloak providers/
#   dist-theme/js/humifortis-device.bundle.js ← deploy to theme login/resources/js/
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UI_DIR="$SCRIPT_DIR/device-collector-ui"
THEME_JS_OUT="$SCRIPT_DIR/dist-theme/js"

BUILD_JAVA=true
BUILD_JS=true

for arg in "$@"; do
  case $arg in
    --js-only)   BUILD_JAVA=false ;;
    --java-only) BUILD_JS=false   ;;
  esac
done

echo "======================================================="
echo "  Humifortis Keycloak Connector — Full Build"
echo "======================================================="

# ── JS Bundle ────────────────────────────────────────────────────────────────
if [ "$BUILD_JS" = true ]; then
  echo ""
  echo "▶ [1/2] Building JS device collector bundle..."
  cd "$UI_DIR"

  if [ ! -d "node_modules" ]; then
    echo "  npm install..."
    npm install
  fi

  npm run build

  mkdir -p "$THEME_JS_OUT"
  cp dist/humifortis-device.bundle.js "$THEME_JS_OUT/"
  echo "  ✅ JS bundle → dist-theme/js/humifortis-device.bundle.js"
  cd "$SCRIPT_DIR"
fi

# ── Java JAR ─────────────────────────────────────────────────────────────────
if [ "$BUILD_JAVA" = true ]; then
  echo ""
  echo "▶ [2/2] Building Java connector JAR..."
  cd "$SCRIPT_DIR"
  ./mvnw clean package -q
  echo "  ✅ JAR → target/humifortis-keycloak-connector.jar"
fi

echo ""
echo "======================================================="
echo "  Build complete!"
echo ""
echo "  Deploy:"
echo "  1. cp target/humifortis-keycloak-connector.jar \\"
echo "        /opt/keycloak/providers/"
echo ""
echo "  2. cp dist-theme/js/humifortis-device.bundle.js \\"
echo "        /opt/keycloak/themes/<your-theme>/login/resources/js/"
echo ""
echo "  3. cp src/main/resources/theme-resources/templates/humifortis-device-collector.ftl \\"
echo "        /opt/keycloak/themes/<your-theme>/login/"
echo ""
echo "  4. Restart Keycloak"
echo "======================================================="

