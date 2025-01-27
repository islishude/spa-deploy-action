// See: https://rollupjs.org/introduction/

import commonjs from '@rollup/plugin-commonjs'
import jsonPlugin from '@rollup/plugin-json'
import nodeResolve from '@rollup/plugin-node-resolve'
import typescript from '@rollup/plugin-typescript'

const config = {
  input: 'src/index.ts',
  output: {
    inlineDynamicImports: true,
    esModule: true,
    file: 'dist/index.js',
    format: 'es',
    sourcemap: true
  },
  plugins: [typescript(), nodeResolve(), commonjs(), jsonPlugin()]
}

export default config
