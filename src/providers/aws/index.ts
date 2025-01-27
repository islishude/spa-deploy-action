import * as core from '@actions/core'
import * as s3 from '@aws-sdk/client-s3'
import fs from 'fs'
import path from 'path'

import type { Provider } from '../index.js'

export default class S3Provider implements Provider {
  private client: s3.S3Client

  constructor(
    private bucket: string,
    private prefix?: string
  ) {
    this.client = process.env.LOCAL_STACK_ENDPOINT
      ? new s3.S3Client({
          endpoint: process.env.LOCAL_STACK_ENDPOINT
        })
      : new s3.S3Client()
  }

  async listObjects(): Promise<string[]> {
    const files: string[] = []

    let pageKey: string | undefined = undefined
    let loop = true

    while (loop) {
      const s3files: s3.ListObjectsV2Output = await this.client.send(
        new s3.ListObjectsV2Command({
          Bucket: this.bucket,
          Prefix: this.prefix,
          ContinuationToken: pageKey
        })
      )

      if (s3files.Contents) {
        for (const item of s3files.Contents) {
          if (item.Key) {
            const s3Key = this.prefix
              ? path.relative(this.prefix, item.Key)
              : item.Key
            files.push(s3Key)
          }
        }
      }

      pageKey = s3files.NextContinuationToken
      loop = pageKey !== undefined
    }

    return files
  }

  async putObject(
    dir: string,
    fpath: string,
    contentType: string,
    cacheControl?: string
  ): Promise<void> {
    const s3Key = this.prefix ? path.join(this.prefix, fpath) : fpath
    core.info(
      `Uploading s3://${this.bucket}/${s3Key} | content-type=${contentType} | cache-control=${cacheControl}`
    )

    await this.client.send(
      new s3.PutObjectCommand({
        Bucket: this.bucket,
        Key: s3Key,
        Body: fs.createReadStream(path.join(dir, fpath)),
        ContentType: contentType,
        CacheControl: cacheControl
      })
    )
  }

  async deleteObjects(key: string): Promise<void> {
    const s3Key = this.prefix ? path.join(this.prefix, key) : key

    core.info(`Deleting s3://${this.bucket}/${s3Key}`)
    await this.client.send(
      new s3.DeleteObjectCommand({
        Bucket: this.bucket,
        Key: s3Key
      })
    )
  }
}
