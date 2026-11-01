import { defineConfig } from 'vite'

export default defineConfig({
  build: {
    lib: {
      entry: 'src/main.js',
      name: 'HumifortisDeviceCollector',
      // Always output as a single fixed filename — referenced by the .ftl template and by
      // scripts=js/humifortis-device.bundle.js in a login theme
      fileName: () => 'humifortis-device.bundle.js',
      // IIFE = Immediately Invoked Function Expression
      // Required for a plain <script src="..."> in a Keycloak FreeMarker template.
      // ES modules are NOT supported without a bundler/import map on the page.
      formats: ['iife'],
    },
    // straight into the connector jar: theme-resources are served to EVERY login theme, so the
    // script works whatever theme a realm uses (no copy into the customer's theme)
    outDir: '../src/main/resources/theme-resources/resources/js',
    emptyOutDir: false,
    minify: true,
    // No code splitting — single self-contained file
    rollupOptions: {
      output: {
        // Inline all assets (no separate chunk files)
        inlineDynamicImports: true,
      },
    },
  },
})

