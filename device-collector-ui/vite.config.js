import { defineConfig } from 'vite'

export default defineConfig({
  build: {
    lib: {
      entry: 'src/main.js',
      name: 'HumifortisDeviceCollector',
      // Always output as a single fixed filename — referenced by the .ftl template
      fileName: () => 'humifortis-device.bundle.js',
      // IIFE = Immediately Invoked Function Expression
      // Required for a plain <script src="..."> in a Keycloak FreeMarker template.
      // ES modules are NOT supported without a bundler/import map on the page.
      formats: ['iife'],
    },
    outDir: 'dist',
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

