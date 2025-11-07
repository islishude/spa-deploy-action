import { contentType } from 'mime-types'
import fs from 'node:fs/promises'
import path from 'path'

import * as CacheControl from './cache-control.js'
import S3Provider from './providers/aws/index.js'

async function getAllFiles(dirPath: string): Promise<string[]> {
  const files: string[] = []

  async function walk(currentPath: string): Promise<void> {
    const entries = await fs.readdir(currentPath, { withFileTypes: true })

    for (const entry of entries) {
      const fullPath = path.join(currentPath, entry.name)

      if (entry.isDirectory()) {
        await walk(fullPath)
      } else if (entry.isFile()) {
        files.push(path.relative(dirPath, fullPath))
      }
    }
  }

  await walk(dirPath)
  return files
}

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
    getAllFiles(dirPath),
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
