// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { CustomResource, Duration, Stack } from 'aws-cdk-lib';
import { IManagedPolicy, PolicyDocument, PolicyStatement, Role, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { Bucket } from 'aws-cdk-lib/aws-s3';
import { Construct } from 'constructs';
import { addCfnGuardSuppression } from '../cdk-helper/add-cfn-guard-suppression';
import { getLambdaCode } from '../cdk-helper/lambda-code-manifest';
import { createLogGroup } from '../cdk-helper/log-group';

const CUSTOM_RUNBOOK_TAG_KEY = 'aws-solutions:custom-runbook';

export interface CustomRunbookRoleCleanupProps {
  readonly solutionTradeMarkName: string;
  readonly solutionVersion: string;
  readonly solutionDistBucket: string;
  readonly runtimePython: lambda.Runtime;
  /** Prefix of the role names ASR gives Custom Runbook remediation roles, e.g. `SO0111-Remediate-Custom-`. */
  readonly roleNamePrefix: string;
  /** The permissions boundary ASR attaches to every Custom Runbook remediation role. */
  readonly remediationBoundaryPolicy: IManagedPolicy;
}

/**
 * Deletes the Custom Runbook remediation roles ASR created at runtime when the stack is deleted.
 *
 * Those roles use the stack's remediation permissions boundary, and IAM refuses to delete a policy that
 * is still a role's boundary, so without this the stack delete ends in DELETE_FAILED. The custom
 * resource references the boundary policy, so CloudFormation deletes it (running the cleanup) before
 * it deletes the policy.
 */
export class CustomRunbookRoleCleanup extends Construct {
  constructor(scope: Construct, id: string, props: CustomRunbookRoleCleanupProps) {
    super(scope, id);
    const stack = Stack.of(this);
    const roleArnPattern = `arn:${stack.partition}:iam::${stack.account}:role/${props.roleNamePrefix}*`;

    const logGroup = createLogGroup(this, 'LogGroup');
    const role = new Role(this, 'Role', {
      assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
      description: 'Deletes the ASR Custom Runbook remediation roles when the Member Roles stack is deleted',
      // Inline, not addToPolicy: a separate Policy resource could be deleted before the custom resource.
      inlinePolicies: {
        CustomRunbookRoleCleanupPolicy: new PolicyDocument({
          statements: [
            // ListRoles has no resource-level permissions.
            new PolicyStatement({ actions: ['iam:ListRoles'], resources: ['*'] }), // NOSONAR
            new PolicyStatement({
              actions: ['iam:GetRole', 'iam:ListRolePolicies', 'iam:ListAttachedRolePolicies'],
              resources: [roleArnPattern],
            }),
            // Only roles carrying the ASR custom-runbook tag can be changed, whatever the Lambda decides.
            new PolicyStatement({
              actions: ['iam:DeleteRolePolicy', 'iam:DetachRolePolicy', 'iam:DeleteRole'],
              resources: [roleArnPattern],
              conditions: { Null: { [`iam:ResourceTag/${CUSTOM_RUNBOOK_TAG_KEY}`]: 'false' } },
            }),
            new PolicyStatement({ actions: ['cloudformation:DescribeStacks'], resources: [stack.stackId] }),
            new PolicyStatement({
              actions: ['logs:CreateLogStream', 'logs:PutLogEvents'],
              resources: [logGroup.logGroupArn],
            }),
          ],
        }),
      },
    });
    addCfnGuardSuppression(role, 'IAM_NO_INLINE_POLICY_CHECK');
    addCfnGuardSuppression(role, 'IAM_POLICYDOCUMENT_NO_WILDCARD_RESOURCE');

    const solutionsBucket = Bucket.fromBucketName(
      this,
      'SolutionsBucket',
      `${props.solutionDistBucket}-${stack.region}`,
    );
    const cleanupFunction = new lambda.Function(this, 'Function', {
      code: getLambdaCode(
        solutionsBucket,
        props.solutionTradeMarkName,
        props.solutionVersion,
        'custom_runbook_role_cleanup.zip',
      ),
      handler: 'custom_runbook_role_cleanup.lambda_handler',
      runtime: props.runtimePython,
      description: 'ASR - Deletes Custom Runbook remediation roles when the Member Roles stack is deleted',
      environment: { LOG_LEVEL: 'INFO' },
      timeout: Duration.minutes(5),
      role,
      logGroup,
    });
    addCfnGuardSuppression(cleanupFunction, 'LAMBDA_INSIDE_VPC');
    addCfnGuardSuppression(cleanupFunction, 'LAMBDA_CONCURRENCY_CHECK');

    new CustomResource(this, 'Cleanup', {
      resourceType: 'Custom::CustomRunbookRoleCleanup',
      serviceToken: cleanupFunction.functionArn,
      properties: {
        RoleNamePrefix: props.roleNamePrefix,
        PermissionsBoundaryArn: props.remediationBoundaryPolicy.managedPolicyArn,
      },
    });
  }
}
