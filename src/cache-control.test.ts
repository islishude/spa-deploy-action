import * as CacheControl from './cache-control'

describe('cache-control', () => {
  it('merge', () => {
    const merged = CacheControl.Merge({ 'index.html': 'no-cache' })

    expect(merged).toEqual(
      new Map(
        Object.entries({
          'index.html': 'no-cache',
          '*.css': CacheControl.optimizedPolicy,
          '*.js': CacheControl.optimizedPolicy,
          '*.png': CacheControl.defaultPolicy,
          '*.jpg': CacheControl.defaultPolicy,
          '*.ico': CacheControl.defaultPolicy
        })
      )
    )
  })

  it('get', () => {
    let res = CacheControl.Get('index.html', CacheControl.builtin, 'no-cache')
    expect(res).toEqual(CacheControl.indexHtmlPolicy)

    res = CacheControl.Get('hello.pdf', CacheControl.builtin, 'no-cache')
    expect(res).toEqual('no-cache')
  })
})
