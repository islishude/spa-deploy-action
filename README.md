# spa-deploy-action

[![Lint and test](https://github.com/islishude/spa-deploy-action/actions/workflows/ci.yml/badge.svg)](https://github.com/islishude/spa-deploy-action/actions/workflows/ci.yml)
![TestCoverage](./badges/coverage.svg)

Deploy your single page application to S3 with correct cache control

## Usage

```yaml
name: Build and deploy your spa
on:
  push:
    branches:
      - main

permissions:
  contents: read
  id-token: write

jobs:
  spa_build_deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v5
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v5
        with:
          role-to-assume: arn:aws:iam::111111111111:role/my-github-actions-role
          aws-region: us-east-1
      - name: Use Node.js
        uses: actions/setup-node@v5
        with:
          node-version: 24
          cache: npm
      - name: Install dependencies
        run: npm ci
      - name: Build
        run: npm run build
      - name: Deploy
        uses: islishude/spa-deploy-action@v1
        with:
          dir-path: 'dist'
          s3-bucket: your-s3-bucket-name
```

## Inputs

| Name                       | Type   | Default | Required | Description                                                                                                         |
| -------------------------- | ------ | ------- | -------- | ------------------------------------------------------------------------------------------------------------------- |
| dir-path                   | string |         | yes      | directory path for deploying                                                                                        |
| s3-bucket                  | string |         | yes      | aws s3 bucket name                                                                                                  |
| s3-bucket-prefix           | string |         | no       | aws s3 bucket prefix to deploy                                                                                      |
| delete                     | bool   | true    | no       | files that exist in the s3 but not in the local are deleted                                                         |
| cache-control              | json   | {}      | no       | file glob and cache control directive pairs, the glob matcher uses [minimatch](https://github.com/isaacs/minimatch) |
| cache-control-merge-policy | string | upsert  | no       | used for merge built-in and your custom cache-control                                                               |
| default-cache-control      | string |         | no       | use if no matched with cache-control                                                                                |

## Built-in cache control mapping

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

you can provide a cache-control input to update it.

if you use the default `cache-control-merge-policy: 'upsert'`, the action will
update an existing key if a specified value already exists in the built-in cache
control mapping, and insert a new key-value if the specified value doesn't
already exist

if you use `cache-control-merge-policy: 'replace'`, the action will use the
`cache-control` input you provided.

## Required AWS IAM Policy

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
