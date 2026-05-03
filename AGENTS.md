# Agent Instructions

## Project overview

This repository contains a Node.js GitHub Action that deploys a Single Page
Application (SPA) directory to Amazon S3 with predictable `Cache-Control`
headers.

The runtime entrypoint is `src/index.ts`, and the main implementation lives in
`src/run.ts`, `src/cache-control.ts`, and provider-specific modules under
`src/providers/`.

## Environment

- Use Node.js 24 or newer.
- Install dependencies with `npm ci`.
- Tests use Docker Compose to start local AWS-compatible services, so Docker
  must be running before `npm test`.

## Common commands

- `npm run lint` checks the code with oxlint.
- `npm run format:check` checks formatting.
- `npm run format:write` formats files.
- `npm run typecheck` runs TypeScript without emitting output.
- `npm test` runs Vitest with coverage and refreshes `badges/coverage.svg`.
- `npm run package` type-checks and bundles the action into `dist/index.js`.
- `npm run all` runs formatting, linting, tests, and packaging.

## Development notes

- Keep source changes in `src/`; `dist/index.js` must be regenerated with
  `npm run package` when action runtime behavior changes.
- Preserve the public action contract in `action.yml` and keep README input
  documentation aligned with it.
- Cache-control behavior should be covered by focused tests in
  `src/cache-control.test.ts` or `src/run.test.ts`.
- AWS provider changes should stay behind the provider boundary in
  `src/providers/aws/` unless shared provider contracts need to change.
- Avoid committing unrelated generated artifacts. Coverage output under
  `coverage/` is local test output; `badges/coverage.svg` is intentionally
  refreshed by `npm test`.

## Pull request checklist

- Dependencies installed with `npm ci`.
- Formatting and linting pass.
- Type checks pass.
- Relevant tests pass.
- Bundled `dist/` output is updated when runtime code changes.
