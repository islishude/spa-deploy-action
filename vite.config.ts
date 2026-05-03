import { builtinModules } from 'node:module'
import { defineConfig } from 'vite'

const nodeBuiltins = new Set([
  ...builtinModules,
  ...builtinModules.map(moduleName => `node:${moduleName}`)
])

export default defineConfig({
  build: {
    copyPublicDir: false,
    emptyOutDir: true,
    license: {
      fileName: 'licenses.txt'
    },
    minify: false,
    outDir: 'dist',
    reportCompressedSize: false,
    rolldownOptions: {
      external: id => nodeBuiltins.has(id),
      output: {
        codeSplitting: false,
        entryFileNames: 'index.js',
        format: 'es'
      }
    },
    sourcemap: true,
    ssr: 'src/index.ts',
    target: 'node24'
  },
  ssr: {
    noExternal: true
  }
})
