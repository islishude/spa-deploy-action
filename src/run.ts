import fs from 'node:fs/promises'
import path from 'path'
import { contentType } from 'mime-types'

import S3Provider from './providers/aws'
import * as CacheControl from './cache-control'

export async function run({
  bucket,
  prefix,
  dirPath,
  isDelete,
  cacheControlJson,
  cacheControlMergePolicy,
  defaultCacheControl
}: {
  bucket: string
  prefix: string
  dirPath: string
  isDelete: boolean
  cacheControlJson: CacheControl.Pattern
  cacheControlMergePolicy: string
  defaultCacheControl: string
}): Promise<void> {
  const cacheControls = CacheControl.Merge(
    cacheControlJson,
    cacheControlMergePolicy as CacheControl.MergePolicy
  )

  const s3c = new S3Provider(bucket, prefix)

  const [localFiles, remoteFiles] = await Promise.all([
    fs
      .readdir(dirPath, { recursive: true, withFileTypes: true })
      .then(i => i.filter(f => f.isFile()))
      .then(i => i.map(f => path.relative(dirPath, path.join(f.path, f.name)))),
    s3c.listObjects()
  ])

  const upload = async (filePath: string): Promise<void> => {
    await s3c.putObject(
      dirPath,
      filePath,
      contentType(path.extname(filePath)) || 'application/octet-stream',
      CacheControl.Get(filePath, cacheControls, defaultCacheControl)
    )
  }

  await Promise.all(
    localFiles.filter(v => path.extname(v) !== '.html').map(upload)
  )

  await Promise.all(
    [...localFiles].filter(v => path.extname(v) === '.html').map(upload)
  )

  if (isDelete) {
    const localFilesSet = new Set(localFiles)
    await Promise.all(
      remoteFiles
        .filter(v => !localFilesSet.has(v))
        .map(async v => s3c.deleteObjects(v))
    )
  }
}
