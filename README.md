# Deploy your single page application to S3 with correct cache control

## Usage

```yaml
steps:
  - name: Checkout
    uses: actions/checkout@v3
  - name: Configure AWS credentials from Test account
    uses: aws-actions/configure-aws-credentials@v3
    with:
      role-to-assume: arn:aws:iam::111111111111:role/my-github-actions-role-test
      aws-region: us-east-1
  - name: Deploy SPA
    uses: islishude/spa-deploy-action@v1
    with:
      dir-path: 'dist'
      s3-bucket: your-s3-bucket-name
      s3-bucket-prefix: your-s3-bucket-prefix
      delete: true
      cache-control: |
        {
          "*.pdf": "public,max-age=31536000"
        }
      default-cache-control: no-cache
```

## Built-in cache control mapping

See [cache-control.ts](src/cache-control.ts)
