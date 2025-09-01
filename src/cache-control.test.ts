import * as CacheControl from './cache-control.js'

describe('cache-control', () => {
  it('merge:upsert', () => {
    const merged = CacheControl.Merge({ 'index.html': 'no-cache' }, 'upsert')

    const expected = new Map(CacheControl.builtin)
    expected.set('index.html', 'no-cache')
    expect(merged).toEqual(expected)
  })

  it('merge:replace', () => {
    const merged = CacheControl.Merge({ 'index.html': 'no-cache' }, 'replace')

    const expected = new Map([['index.html', 'no-cache']])
    expect(merged).toEqual(expected)
  })

  it('get', () => {
    let res = CacheControl.Get('index.html', CacheControl.builtin, 'no-cache')
    expect(res).toEqual(CacheControl.indexHtmlPolicy)

    res = CacheControl.Get('hello.pdf', CacheControl.builtin, 'no-cache')
    expect(res).toEqual('no-cache')
  })
})
