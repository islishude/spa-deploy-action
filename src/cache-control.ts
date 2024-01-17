import { minimatch } from 'minimatch'

export interface Pattern {
  [glob: string]: string
}

export const defaultPolicy =
  'public,max-age=86400,stale-while-revalidate=2592000'

export const optimizedPolicy = 'public,max-age=31536000,immutable'

export const indexHtmlPolicy =
  'public,max-age=60,stale-while-revalidate=2592000'

export type MergePolicy = 'upsert' | 'replace'

export const builtin: Map<string, string> = new Map(
  Object.entries({
    'index.html': indexHtmlPolicy,
    '*.css': optimizedPolicy,
    '*.js': optimizedPolicy,
    '*.png': defaultPolicy,
    '*.jpg': defaultPolicy,
    '*.ico': defaultPolicy,
    '*.svg': defaultPolicy
  })
)

export function Merge(i: Pattern, policy: MergePolicy): Map<string, string> {
  const merged = policy === 'upsert' ? new Map(builtin) : new Map()
  for (const [key, value] of Object.entries(i)) {
    merged.set(key, value)
  }
  return merged
}

export function Get(
  filePath: string,
  patterns: Map<string, string>,
  _default: string
): string | undefined {
  for (const [glob, cacheControl] of patterns) {
    if (minimatch(filePath, glob, { matchBase: true })) {
      return cacheControl
    }
  }
  return _default || undefined
}
