import * as CacheControl from './cache-control'

describe('cache-control', () => {
  it('merge', () => {
    const merged = CacheControl.Merge({ 'index.html': 'no-cache' })

    const expected = new Map(CacheControl.builtin)
    expected.set('index.html', 'no-cache')
    expect(merged).toEqual(expected)
  })

  it('get', () => {
    let res = CacheControl.Get('index.html', CacheControl.builtin, 'no-cache')
    expect(res).toEqual(CacheControl.indexHtmlPolicy)

    res = CacheControl.Get('hello.pdf', CacheControl.builtin, 'no-cache')
    expect(res).toEqual('no-cache')
  })
})
