// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { CustomResource, Duration, Stack } from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { CfnFunction } from 'aws-cdk-lib/aws-lambda';
import { CfnPolicy, CfnRole, Effect, Policy, PolicyStatement, Role, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import { IBucket } from 'aws-cdk-lib/aws-s3';
import { Construct } from 'constructs';
import { addCfnGuardSuppression } from './cdk-helper/add-cfn-guard-suppression';
import { createLogGroup } from './cdk-helper/log-group';
import { getLambdaCode } from './cdk-helper/lambda-code-manifest';
import { EmailTopicCleanupEnvironmentConfig } from '@asr/data-models';

export interface EmailTopicCleanupConstructProps {
  readonly solutionId: string;
  readonly solutionTMN: string;
  readonly solutionVersion: string;
  readonly sourceCodeBucket: IBucket;
  readonly resourceNamePrefix: string;
}

/**
 * Custom Resource that deletes all ASR-managed email notification SNS topics
 * (prefixed with `asr-notifications-`) when the stack is deleted.
 * On Create/Update it is a no-op.
 */
export class EmailTopicCleanupConstruct extends Construct {
  constructor(scope: Construct, id: string, props: EmailTopicCleanupConstructProps) {
    super(scope, id);

    const stack = Stack.of(this);
    const RESOURCE_NAME_PREFIX = props.solutionId.replace(/^DEV-/, '');

    const cleanupPolicy = new Policy(this, 'EmailTopicCleanupPolicy', {
      policyName: RESOURCE_NAME_PREFIX + '-ASR_EmailTopicCleanup',
      statements: [
        new PolicyStatement({
          actions: ['logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'],
          resources: [`arn:${stack.partition}:logs:${stack.region}:${stack.account}:log-group:*`],
        }),
        new PolicyStatement({
          effect: Effect.ALLOW,
          actions: ['sns:ListTopics'],
          resources: ['*'],
        }),
        new PolicyStatement({
          effect: Effect.ALLOW,
          actions: ['sns:DeleteTopic'],
          resources: [`arn:${stack.partition}:sns:${stack.region}:${stack.account}:asr-notifications-*`],
        }),
      ],
    });

    {
      const child = cleanupPolicy.node.findChild('Resource') as CfnPolicy;
      child.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason:
                'Resource * is required for sns:ListTopics (does not support resource-level permissions) and for CloudWatch Logs.',
            },
          ],
        },
      };
    }

    const cleanupRole = new Role(this, 'EmailTopicCleanupRole', {
      assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
      description: 'Lambda role for ASR email topic cleanup custom resource',
      roleName: `${RESOURCE_NAME_PREFIX}-ASR-EmailTopicCleanup`,
    });
    cleanupRole.attachInlinePolicy(cleanupPolicy);

    {
      const child = cleanupRole.node.findChild('Resource') as CfnRole;
      child.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W28',
              reason: 'Static name chosen intentionally for email topic cleanup function.',
            },
          ],
        },
      };
    }
    addCfnGuardSuppression(cleanupRole, 'IAM_NO_INLINE_POLICY_CHECK');

    const cleanupLogGroup = createLogGroup(this, 'EmailTopicCleanupLogGroup');

    const cleanupLambda = new lambda.Function(this, 'EmailTopicCleanupLambda', {
      functionName: `${props.resourceNamePrefix}-ASR-EmailTopicCleanup`,
      handler: 'notification-channels/email-topic-cleanup-handler.handler',
      runtime: lambda.Runtime.NODEJS_24_X,
      description: 'Custom resource to delete ASR email notification SNS topics on stack deletion',
      code: getLambdaCode(props.sourceCodeBucket, props.solutionTMN, props.solutionVersion, 'asr_lambdas.zip'),
      environment: {
        POWERTOOLS_SERVICE_NAME: 'email_topic_cleanup',
        POWERTOOLS_LOG_LEVEL: 'INFO',
        TOPIC_PREFIX: 'asr-notifications-',
      } satisfies EmailTopicCleanupEnvironmentConfig,
      memorySize: 128,
      timeout: Duration.minutes(5),
      role: cleanupRole,
      tracing: lambda.Tracing.ACTIVE,
      logGroup: cleanupLogGroup,
    });

    {
      const child = cleanupLambda.node.findChild('Resource') as CfnFunction;
      child.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            { id: 'W58', reason: 'False positive. Access is provided via a policy' },
            { id: 'W89', reason: 'There is no need to run this lambda in a VPC' },
            { id: 'W92', reason: 'There is no need for Reserved Concurrency' },
          ],
        },
      };
    }
    addCfnGuardSuppression(cleanupLambda, 'LAMBDA_INSIDE_VPC');
    addCfnGuardSuppression(cleanupLambda, 'LAMBDA_CONCURRENCY_CHECK');

    const customResource = new CustomResource(this, 'EmailTopicCleanupResource', {
      serviceToken: cleanupLambda.functionArn,
      resourceType: 'Custom::EmailTopicCleanup',
    });

    customResource.node.addDependency(cleanupRole);
    customResource.node.addDependency(cleanupPolicy);
  }
}
