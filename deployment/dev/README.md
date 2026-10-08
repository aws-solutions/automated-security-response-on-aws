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

To deploy the optional MCP server, add `"enableMcpServer": "yes"` to
`local-config.json`. The value defaults to `"no"` when omitted.

To register additional MCP OAuth callbacks, add a comma-separated
`"additionalMcpCallbackUrls"` value with no whitespace:

```json
{
  "enableMcpServer": "yes",
  "additionalMcpCallbackUrls": "https://ide.example.com/oauth/callback,http://localhost:9999/callback"
}
```

Additional callbacks are validated during deployment. They must use HTTPS, or HTTP
on a loopback host. A loopback callback on any port follows the same local-machine
trust model as the built-in Kiro and Claude Code callbacks: another local process
could receive the authorization code if it binds that port first.

## Lifecycle

- The first deployment runs `create-stack` and stores the stackIds in local-config.json.
- Any subsequent run will detect the stackIds in the config and `update-stack` instead of `create-stack`.
- If you run `./deploy-dev.sh delete`, the stacks will be deleted and the stackIds removed from local-config.json.

### What `delete` tears down beyond the stacks

ASR retains its stateful resources on stack deletion, so `delete` also removes the
retained orphans that would otherwise collide with the next deploy: the namespaced
buckets, the DynamoDB tables, the `SO0111-*` roles and instance profiles, and the
remediation configuration bucket plus the `ASR-RemediationConfigBucketAccess-<region>`
managed policy. Log groups are left in place.

Two of those are named per account+region with no namespace, so they are shared
region-wide: the remediation configuration bucket and its access policy. Deleting the
policy requires detaching it from every IAM identity holding it, which includes EC2
instance roles that ASR did not create — the Inspector remediation attaches the policy
to whatever role the target instance already had. Those instances keep their patches
and only lose read access to a bucket that is being deleted anyway, and the next
deployment's remediation re-attaches the policy on its next run. Every detached
identity is printed during teardown.

Do not run `delete` while an Inspector remediation is mid-patch — that run will fail.

## Fresh namespace

Run `init.sh` again to generate a new namespace and new buckets. The old stacks/buckets are not deleted automatically — clean them up manually if needed.

## Files

| File | Tracked | Description |
|------|---------|-------------|
| `init.sh` | ✅ | Interactive setup, creates buckets and config |
| `deploy-dev.sh` | ✅ | Build + upload + deploy |
| `local-config.json` | ❌ (.gitignore) | Your local config values |
