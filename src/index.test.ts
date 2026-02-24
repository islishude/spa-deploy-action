import { jest } from '@jest/globals'

describe('index', () => {
  beforeEach(() => {
    jest.resetModules()
    jest.clearAllMocks()
  })

  it('should read inputs and call run with parsed options', async () => {
    const run = jest.fn(async () => {})
    const setFailed = jest.fn()

    const inputMap: Record<string, string> = {
      's3-bucket': 'my-bucket',
      's3-bucket-prefix': 'web',
      'dir-path': 'dist',
      'default-cache-control': 'no-cache',
      'cache-control-merge-policy': 'upsert',
      'cache-control': '{"index.html":"no-cache"}'
    }

    const getInput = jest.fn((name: string) => inputMap[name] ?? '')
    const getBooleanInput = jest.fn(() => true)

    jest.unstable_mockModule('@actions/core', () => ({
      getInput,
      getBooleanInput,
      setFailed
    }))
    jest.unstable_mockModule('./run.js', () => ({ run }))

    await import('./index.js')

    expect(run).toHaveBeenCalledTimes(1)
    expect(run).toHaveBeenCalledWith({
      bucket: 'my-bucket',
      prefix: 'web',
      dirPath: 'dist',
      isDelete: true,
      cacheControlJson: { 'index.html': 'no-cache' },
      cacheControlMergePolicy: 'upsert',
      defaultCacheControl: 'no-cache'
    })
    expect(setFailed).not.toHaveBeenCalled()
    expect(getInput).toHaveBeenCalledWith('s3-bucket', { required: true })
    expect(getInput).toHaveBeenCalledWith('dir-path', { required: true })
    expect(getBooleanInput).toHaveBeenCalledWith('delete')
  })

  it('should call setFailed when run rejects', async () => {
    const run = jest.fn(() => Promise.reject(new Error('boom')))
    const setFailed = jest.fn()

    const inputMap: Record<string, string> = {
      's3-bucket': 'my-bucket',
      's3-bucket-prefix': '',
      'dir-path': 'dist',
      'default-cache-control': 'no-cache',
      'cache-control-merge-policy': 'replace',
      'cache-control': '{}'
    }

    jest.unstable_mockModule('@actions/core', () => ({
      getInput: (name: string) => inputMap[name] ?? '',
      getBooleanInput: () => false,
      setFailed
    }))
    jest.unstable_mockModule('./run.js', () => ({ run }))

    await import('./index.js')
    await Promise.resolve()

    expect(setFailed).toHaveBeenCalledTimes(1)
    expect(setFailed).toHaveBeenCalledWith('boom')
  })
})
