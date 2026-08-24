# ASR Dev Deployment

Quick build-and-deploy workflow for local development. Two scripts, two commands.

## Prerequisites

- AWS CLI v2
- Valid AWS credentials configured (via `aws configure`, environment variables, or IAM role)
- All build prerequisites from the main [README](../../README.md#prerequisites-for-customization)
- `npm install` already run in `source/`

## First-time setup

```bash
cd deployment/dev
./init.sh
```

`init.sh` will prompt you for:

| Value | Default            | Description |
|-------|--------------------|-------------|
| Account ID | *(required)*       | AWS account to deploy into |
| Region | `us-east-1`        | Deployment region |
| SecHub Admin Account | same as Account ID | Security Hub administrator account |
| Solution version | `v4.0.0.dev`       | Version string for the build |

The script generates a unique namespace, creates two S3 buckets (with public access blocked), and writes all values to `local-config.json`.

## Deploy

```bash
./deploy-dev.sh
```

This single command:
1. Builds the solution (`build-s3-dist.sh`)
2. Uploads artifacts to S3
3. Deploys Admin, Member Roles, and Member CloudFormation stacks (sequentially, with waits)

All stacks use `--disable-rollback` so you can inspect failures in the console.

## Lifecycle

- The first deployment runs `create-stack` and stores the stackIds in local-config.json.
- Any subsequent run will detect the stackIds in the config and `update-stack` instead of `create-stack`.
- If you run `./deploy-dev.sh delete`, the stacks will be deleted and the stackIds removed from local-config.json.

## Fresh namespace

Run `init.sh` again to generate a new namespace and new buckets. The old stacks/buckets are not deleted automatically — clean them up manually if needed.

## Files

| File | Tracked | Description |
|------|---------|-------------|
| `init.sh` | ✅ | Interactive setup, creates buckets and config |
| `deploy-dev.sh` | ✅ | Build + upload + deploy |
| `local-config.json` | ❌ (.gitignore) | Your local config values |
