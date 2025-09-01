import * as CacheControl from './cache-control.js'
import { run } from './run.js'

import * as s3 from '@aws-sdk/client-s3'
import fs from 'node:fs/promises'
import path from 'node:path'
import { Readable } from 'node:stream'

async function streamToString(reader: Readable): Promise<string> {
  const chunks = []
  for await (const chunk of reader) {
    chunks.push(Buffer.from(chunk))
  }
  return Buffer.concat(chunks).toString('utf-8')
}

describe('chore', () => {
  beforeAll(() => {
    process.env = Object.assign(process.env, {
      AWS_ACCESS_KEY_ID: 'foo',
      AWS_SECRET_ACCESS_KEY: 'bar',
      AWS_REGION: 'us-east-1',
      LOCAL_STACK_ENDPOINT: 'http://127.0.0.1:4566'
    })
  })

  it('run', async () => {
    const client = new s3.S3Client({
      endpoint: process.env.LOCAL_STACK_ENDPOINT
    })

    const bucket = `bucket-${Math.floor(Math.random() * 100).toString()}`

    await client.send(new s3.CreateBucketCommand({ Bucket: bucket }))

    // uploading 1
    {
      const dirPath = 'testdata/1'
      const prefix = 'web'
      await run({
        bucket,
        prefix,
        dirPath,
        isDelete: true,
        cacheControlJson: { 'index.html': 'no-cache' },
        cacheControlMergePolicy: 'upsert',
        defaultCacheControl: 'no-cache'
      })

      const checks: { [file: string]: [string, string] } = {
        'favicon-32x32.png': ['image/png', CacheControl.defaultPolicy],
        'css/index.css': [
          'text/css; charset=utf-8',
          CacheControl.optimizedPolicy
        ],
        'js/index.js': [
          'text/javascript; charset=utf-8',
          CacheControl.optimizedPolicy
        ],
        'index.html': ['text/html; charset=utf-8', 'no-cache']
      }

      const s3files = await client
        .send(new s3.ListObjectsV2Command({ Bucket: bucket, Prefix: prefix }))
        .then(v =>
          v.Contents?.map(f => path.relative(prefix, f.Key as string)).sort()
        )
      expect(Object.keys(checks).sort()).toEqual(s3files)

      for (const file of Object.keys(checks)) {
        const [cont, s3obj] = await Promise.all([
          fs.readFile(path.join(dirPath, file), { encoding: 'utf-8' }),
          client.send(
            new s3.GetObjectCommand({
              Bucket: bucket,
              Key: path.join(prefix, file)
            })
          )
        ])
        expect(await streamToString(s3obj.Body as Readable)).toBe(cont)
        expect(checks[file]).toEqual([s3obj.ContentType, s3obj.CacheControl])
      }
    }

    // uploading 2
    {
      const dirPath = 'testdata/2'
      const prefix = ''
      await run({
        bucket,
        prefix,
        dirPath,
        isDelete: true,
        cacheControlJson: {},
        cacheControlMergePolicy: 'upsert',
        defaultCacheControl: 'no-cache'
      })

      const checks: { [file: string]: [string, string] } = {
        'favicon.ico': ['image/vnd.microsoft.icon', CacheControl.defaultPolicy],
        'index.css': ['text/css; charset=utf-8', CacheControl.optimizedPolicy],
        'index.js': [
          'text/javascript; charset=utf-8',
          CacheControl.optimizedPolicy
        ],
        'index.html': [
          'text/html; charset=utf-8',
          CacheControl.indexHtmlPolicy
        ],
        'index.json': ['application/json; charset=utf-8', 'no-cache']
      }

      const s3files = await client
        .send(new s3.ListObjectsV2Command({ Bucket: bucket, Prefix: prefix }))
        .then(v =>
          v.Contents?.map(f => path.relative(prefix, f.Key as string)).sort()
        )
      expect(Object.keys(checks).sort()).toEqual(s3files)

      for (const file of Object.keys(checks)) {
        const [cont, s3obj] = await Promise.all([
          fs.readFile(path.join(dirPath, file), { encoding: 'utf-8' }),
          client.send(
            new s3.GetObjectCommand({
              Bucket: bucket,
              Key: path.join(prefix, file)
            })
          )
        ])
        expect(await streamToString(s3obj.Body as Readable)).toBe(cont)
        expect(checks[file]).toEqual([s3obj.ContentType, s3obj.CacheControl])
      }
    }
  })
})
