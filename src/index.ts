import * as core from '@actions/core'
import { run } from './run'

const bucket = core.getInput('s3-bucket', { required: true })
const prefix = core.getInput('s3-bucket-prefix')
const dirPath = core.getInput('dir-path', { required: true })
const isDelete = core.getBooleanInput('delete')
const defaultCacheControl = core.getInput('default-cachec-control')
const cacheControlMergePolicy = core.getInput('cache-control-merge-policy')
const cacheControlJson = JSON.parse(core.getInput('cache-control'))

run({
  bucket,
  prefix,
  dirPath,
  isDelete,
  cacheControlJson,
  cacheControlMergePolicy,
  defaultCacheControl
}).catch(err => {
  if (err instanceof Error) core.setFailed(err.message)
})
