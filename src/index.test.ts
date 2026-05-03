import type { run as runAction } from './run.js'

import { beforeEach, describe, expect, it, vi } from 'vitest'

type RunAction = typeof runAction

describe('index', () => {
  beforeEach(() => {
    vi.resetModules()
    vi.clearAllMocks()
    vi.doUnmock('@actions/core')
    vi.doUnmock('./run.js')
  })

  it('should read inputs and call run with parsed options', async () => {
    const run = vi.fn<RunAction>(async () => {})
    const setFailed = vi.fn<(message: string) => void>()

    const inputMap: Record<string, string> = {
      's3-bucket': 'my-bucket',
      's3-bucket-prefix': 'web',
      'dir-path': 'dist',
      'default-cache-control': 'no-cache',
      'cache-control-merge-policy': 'upsert',
      'cache-control': '{"index.html":"no-cache"}'
    }

    const getInput = vi.fn<(name: string) => string>(
      name => inputMap[name] ?? ''
    )
    const getBooleanInput = vi.fn<() => boolean>(() => true)

    vi.doMock('@actions/core', () => ({
      getInput,
      getBooleanInput,
      setFailed
    }))
    vi.doMock('./run.js', () => ({ run }))

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
    const run = vi.fn<RunAction>(() => Promise.reject(new Error('boom')))
    const setFailed = vi.fn<(message: string) => void>()

    const inputMap: Record<string, string> = {
      's3-bucket': 'my-bucket',
      's3-bucket-prefix': '',
      'dir-path': 'dist',
      'default-cache-control': 'no-cache',
      'cache-control-merge-policy': 'replace',
      'cache-control': '{}'
    }

    vi.doMock('@actions/core', () => ({
      getInput: (name: string) => inputMap[name] ?? '',
      getBooleanInput: () => false,
      setFailed
    }))
    vi.doMock('./run.js', () => ({ run }))

    await import('./index.js')
    await Promise.resolve()

    expect(setFailed).toHaveBeenCalledTimes(1)
    expect(setFailed).toHaveBeenCalledWith('boom')
  })
})
