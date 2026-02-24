# spa-deploy-action

[![Lint and test](https://github.com/islishude/spa-deploy-action/actions/workflows/ci.yml/badge.svg)](https://github.com/islishude/spa-deploy-action/actions/workflows/ci.yml)
![TestCoverage](./badges/coverage.svg)

Deploy a Single Page Application (SPA) to S3 with sensible `Cache-Control`
headers.

## Quick start

```yaml
name: Build and deploy SPA

on:
  push:
    branches: [main]

permissions:
  contents: read
  id-token: write

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v6
        with:
          role-to-assume: arn:aws:iam::111111111111:role/my-github-actions-role
          aws-region: us-east-1

      - uses: actions/setup-node@v6
        with:
          node-version: 24
          cache: npm

      - run: npm ci
      - run: npm run build

      - name: Deploy to S3
        uses: islishude/spa-deploy-action@v1
        with:
          dir-path: dist
          s3-bucket: your-s3-bucket-name
```

## Inputs

| Name                         | Default  | Required | Description                                                                                          |
| ---------------------------- | -------- | -------- | ---------------------------------------------------------------------------------------------------- |
| `dir-path`                   | -        | yes      | Local build directory to upload (for example `dist`).                                                |
| `s3-bucket`                  | -        | yes      | Target S3 bucket name.                                                                               |
| `s3-bucket-prefix`           | -        | no       | Target prefix inside bucket (for example `web`).                                                     |
| `delete`                     | `true`   | no       | Delete S3 files that are not present in local directory.                                             |
| `cache-control`              | `{}`     | no       | JSON map: file glob -> `Cache-Control` value. Uses [minimatch](https://github.com/isaacs/minimatch). |
| `cache-control-merge-policy` | `upsert` | no       | `upsert` merges with built-in rules, `replace` uses only your rules.                                 |
| `default-cache-control`      | -        | no       | Fallback `Cache-Control` when no glob matches.                                                       |

## Built-in cache-control rules

```json
{
  "index.html": "public,max-age=60,stale-while-revalidate=2592000",
  "*.css": "public,max-age=31536000,immutable",
  "*.js": "public,max-age=31536000,immutable",
  "*.png": "public,max-age=86400,stale-while-revalidate=2592000",
  "*.jpg": "public,max-age=86400,stale-while-revalidate=2592000",
  "*.ico": "public,max-age=86400,stale-while-revalidate=2592000",
  "*.svg": "public,max-age=86400,stale-while-revalidate=2592000"
}
```

## Custom cache-control examples

Use `upsert` (default): keep built-in rules and override a few.

```yaml
with:
  cache-control: |
    {
      "index.html": "no-cache",
      "*.json": "no-cache"
    }
  cache-control-merge-policy: upsert
```

Use `replace`: ignore built-in rules and only use yours.

```yaml
with:
  cache-control: |
    {
      "**/*": "public,max-age=300"
    }
  cache-control-merge-policy: replace
```

## Required AWS IAM policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:ListBucket"],
      "Resource": "arn:aws:s3:::mybucket"
    },
    {
      "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:DeleteObject"],
      "Resource": "arn:aws:s3:::mybucket/prefix/*"
    }
  ]
}
```

## Troubleshooting

- `AccessDenied`: check IAM policy and OIDC role trust policy.
- Wrong files under bucket root: set `s3-bucket-prefix`.
- Stale `index.html`: set `index.html` to `no-cache` or low max-age in
  `cache-control`.
