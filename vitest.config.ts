import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    clearMocks: true,
    coverage: {
      exclude: ['dist/**', 'node_modules/**'],
      include: ['src/**'],
      provider: 'v8',
      reporter: ['json-summary', 'text', 'lcov'],
      reportsDirectory: './coverage'
    },
    environment: 'node',
    exclude: ['dist/**', 'node_modules/**'],
    globals: false,
    include: ['src/**/*.test.ts']
  }
})
