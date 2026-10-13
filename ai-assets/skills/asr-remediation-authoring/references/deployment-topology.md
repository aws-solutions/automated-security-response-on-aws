# ASR deployment topology

ASR uses three CloudFormation stack types. Place each stack according to its
scope before adding another account or Region.

For the complete deployment model, see the Automated Security Response on AWS
implementation guide section "Deciding where to deploy each stack."

## Stack placement

| Stack | Scope | Placement |
|---|---|---|
| Administrator | Orchestration and Security Hub integration | Once, in the Security Hub finding-aggregation account and Region |
| Member roles | IAM roles used by remediations | Once per account; IAM roles are global |
| Member | SSM Automation documents and regional resources | Every account and Region where findings are remediated |

Deploy the administrator stack first so member stacks can establish their trust
relationships.

## Security Hub aggregation

A member stack is useful only when findings from that account and Region are
aggregated into the administrator account and Region. Verify the configured
Regions before deployment:

```bash
aws securityhub list-finding-aggregators --region <aggregation-region>
aws securityhub get-finding-aggregator   --finding-aggregator-arn <arn>   --region <aggregation-region>   --query '[FindingAggregationRegion,RegionLinkingMode,Regions]'
```

## Multi-Region constraints

- SSM document names do not include the deployment namespace. Only one ASR member
  stack can own those document names in an account and Region.
- The member roles stack must be deployed only once per account because its IAM
  resources are global.
- The optional action-log CloudTrail bucket name does not include a Region.
  Enable it in only one Region per account.
- Lambda asset buckets are regional. Each additional Region needs its own asset
  bucket and uploaded distribution.

## Commands

```bash
python3 "<skill-dir>/scripts/deploy_stack.py" deploy
python3 "<skill-dir>/scripts/deploy_stack.py" deploy-member --region <region>
python3 "<skill-dir>/scripts/deploy_stack.py" status --region <region>
```

`deploy` manages the administrator, member-roles, and member stacks in the Region
from `deployment/dev/local-config.json`. `deploy-member` prepares the regional
asset bucket and creates or updates only the member stack in an additional
Region.

Before `deploy-member`, verify:

1. the target Region participates in Security Hub aggregation;
2. the member roles stack already exists in the account;
3. no ASR member stack already owns the target names in that Region;
4. the regional distribution assets are available;
5. action-log CloudTrail is disabled for the additional Region.
