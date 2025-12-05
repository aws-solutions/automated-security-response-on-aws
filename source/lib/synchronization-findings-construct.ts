// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as lambda from 'aws-cdk-lib/aws-lambda';
import { Construct } from 'constructs';
import { CfnPolicy, CfnRole, Effect, Policy, PolicyStatement, Role, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import { Code, Runtime, Tracing, CfnFunction } from 'aws-cdk-lib/aws-lambda';
import { Rule, RuleTargetInput, Schedule } from 'aws-cdk-lib/aws-events';
import { LambdaFunction } from 'aws-cdk-lib/aws-events-targets';
import { addCfnGuardSuppression } from './cdk-helper/add-cfn-guard-suppression';
import { getLambdaCode } from './cdk-helper/lambda-code-manifest';
import { IKey } from 'aws-cdk-lib/aws-kms';
import { IBucket } from 'aws-cdk-lib/aws-s3';
import { Duration, Stack } from 'aws-cdk-lib';
import { Table } from 'aws-cdk-lib/aws-dynamodb';
import * as cdk from 'aws-cdk-lib';

export interface SynchronizationFindingsConstructProps {
  readonly solutionId: string;
  readonly solutionTMN: string;
  readonly solutionVersion: string;
  readonly resourceNamePrefix: string;
  readonly sourceCodeBucket: IBucket;
  readonly findingsTable: string;
  readonly kmsKey: IKey;
  readonly findingsTTL: string;
  readonly remediationConfigTable: string;
}

export class SynchronizationFindingsConstruct extends Construct {
  public readonly synchronizationLambda: lambda.Function;
  public readonly synchronizationRole: Role;
  public readonly customResourceProvider: lambda.Function;

  constructor(scope: Construct, id: string, props: SynchronizationFindingsConstructProps) {
    super(scope, id);

    const stack = Stack.of(this);

    //---------------------------------------------------------------------
    // Synchronization Lambda Role and Policy
    //---------------------------------------------------------------------
    const synchronizationPolicy = new Policy(this, 'synchronizationPolicy', {
      policyName: props.resourceNamePrefix + '-ASR_Synchronization',
      statements: [
        new PolicyStatement({
          actions: ['logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'],
          resources: [`arn:${stack.partition}:logs:*:${stack.account}:log-group:*`],
        }),
        new PolicyStatement({
          actions: ['securityhub:GetFindings'],
          resources: ['*'],
        }),
        new PolicyStatement({
          actions: ['kms:Encrypt', 'kms:Decrypt', 'kms:GenerateDataKey'],
          resources: [props.kmsKey.keyArn],
        }),
        new PolicyStatement({
          actions: ['ssm:GetParameter', 'ssm:PutParameter'],
          resources: [
            `arn:${stack.partition}:ssm:${stack.region}:${stack.account}:parameter/Solutions/${props.solutionId}/anonymous_metrics_uuid`,
            `arn:${stack.partition}:ssm:${stack.region}:${stack.account}:parameter/Solutions/${props.solutionId}/metrics_uuid`,
            `arn:${stack.partition}:ssm:${stack.region}:${stack.account}:parameter/Solutions/${props.solutionId}/version`,
          ],
        }),
        new PolicyStatement({
          actions: ['ssm:GetParameters', 'ssm:GetParameter', 'ssm:GetParametersByPath'],
          resources: [
            `arn:${cdk.Stack.of(this).partition}:ssm:*:*:parameter/Solutions/SO0111/*`,
            `arn:${cdk.Stack.of(this).partition}:ssm:*:*:parameter/ASR/Filters`,
            `arn:${cdk.Stack.of(this).partition}:ssm:*:*:parameter/ASR/Filters/*`,
          ],
          effect: Effect.ALLOW,
        }),
        new PolicyStatement({
          actions: ['organizations:ListParents', 'organizations:DescribeAccount'],
          resources: ['*'],
          effect: Effect.ALLOW,
        }),
      ],
    });

    {
      const childToMod = synchronizationPolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for CloudWatch Logs policies used by synchronization Lambda function.',
            },
          ],
        },
      };
    }

    this.synchronizationRole = new Role(this, 'synchronizationRole', {
      assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
      description: 'Lambda role for ASR synchronization function',
      roleName: `${props.resourceNamePrefix}-ASR-Synchronization`,
    });

    this.synchronizationRole.attachInlinePolicy(synchronizationPolicy);

    {
      const childToMod = this.synchronizationRole.node.findChild('Resource') as CfnRole;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W28',
              reason: 'Static names chosen intentionally to provide easy integration with synchronization function.',
            },
          ],
        },
      };
    }
    addCfnGuardSuppression(this.synchronizationRole, 'IAM_NO_INLINE_POLICY_CHECK');

    //---------------------------------------------------------------------
    // Synchronization Lambda Function
    //---------------------------------------------------------------------
    this.synchronizationLambda = new lambda.Function(this, 'SynchronizationFindingsLambda', {
      functionName: props.resourceNamePrefix + '-ASR-SynchronizationFindingsLambda',
      handler: 'synchronization/synchronizationHandler.handler',
      runtime: Runtime.NODEJS_22_X,
      description: 'Synchronization findings lambda',
      code: getLambdaCode(props.sourceCodeBucket, props.solutionTMN, props.solutionVersion, 'asr_lambdas.zip'),
      environment: {
        SOLUTION_TRADEMARKEDNAME: props.solutionTMN,
        POWERTOOLS_SERVICE_NAME: 'synchronization_findings',
        POWERTOOLS_LOG_LEVEL: 'INFO',
        POWERTOOLS_LOGGER_LOG_EVENT: 'false',
        POWERTOOLS_TRACER_CAPTURE_RESPONSE: 'true',
        POWERTOOLS_TRACER_CAPTURE_ERROR: 'true',
        FINDINGS_TABLE_ARN: props.findingsTable,
        REMEDIATION_CONFIG_TABLE_ARN: props.remediationConfigTable,
        FINDINGS_TTL_DAYS: props.findingsTTL,
        AWS_ACCOUNT_ID: stack.account,
        STACK_ID: stack.stackId,
      },
      memorySize: 512,
      timeout: Duration.minutes(15),
      role: this.synchronizationRole,
      tracing: Tracing.ACTIVE,
    });

    {
      const childToMod = this.synchronizationLambda.node.findChild('Resource') as CfnFunction;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W58',
              reason: 'False positive. Access is provided via a policy',
            },
            {
              id: 'W89',
              reason: 'There is no need to run this lambda in a VPC',
            },
            {
              id: 'W92',
              reason: 'There is no need for Reserved Concurrency',
            },
          ],
        },
      };
    }

    const findingsTable = Table.fromTableArn(this, 'FindingsTable', props.findingsTable);
    findingsTable.grantReadWriteData(this.synchronizationLambda);

    const remediationConfigTable = Table.fromTableArn(this, 'RemediationConfigTable', props.remediationConfigTable);
    remediationConfigTable.grantReadWriteData(this.synchronizationLambda);

    //---------------------------------------------------------------------
    // Custom Resource Provider Lambda for Initial Synchronization Trigger
    //---------------------------------------------------------------------
    const customResourcePolicy = new Policy(this, 'CustomResourcePolicy', {
      policyName: props.resourceNamePrefix + '-ASR_SynchronizationTrigger',
      statements: [
        new PolicyStatement({
          actions: ['logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'],
          resources: [`arn:${stack.partition}:logs:*:${stack.account}:log-group:*`],
        }),
        new PolicyStatement({
          actions: ['lambda:InvokeFunction'],
          resources: [this.synchronizationLambda.functionArn],
        }),
      ],
    });

    {
      const childToMod = customResourcePolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for CloudWatch Logs policies used by custom resource Lambda function.',
            },
          ],
        },
      };
    }
    const customResourceRole = new Role(this, 'customResourceRole', {
      assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
      description: 'Lambda role for ASR synchronization trigger custom resource',
      roleName: `${props.resourceNamePrefix}-ASR-SynchronizationTrigger`,
    });

    customResourceRole.attachInlinePolicy(customResourcePolicy);

    {
      const childToMod = customResourceRole.node.findChild('Resource') as CfnRole;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W28',
              reason: 'Static names chosen intentionally to provide easy integration with synchronization trigger.',
            },
          ],
        },
      };
    }
    addCfnGuardSuppression(customResourceRole, 'IAM_NO_INLINE_POLICY_CHECK');

    this.customResourceProvider = new lambda.Function(this, 'SynchronizationTriggerProvider', {
      functionName: props.resourceNamePrefix + '-ASR-SynchronizationTriggerProvider',
      handler: 'synchronization/customResourceHandler.handler',
      runtime: Runtime.NODEJS_22_X,
      description: 'Custom resource provider to trigger initial synchronization',
      code: getLambdaCode(props.sourceCodeBucket, props.solutionTMN, props.solutionVersion, 'asr_lambdas.zip'),
      environment: {
        SOLUTION_TRADEMARKEDNAME: props.solutionTMN,
        POWERTOOLS_SERVICE_NAME: 'synchronization_trigger',
        POWERTOOLS_LOG_LEVEL: 'INFO',
        POWERTOOLS_LOGGER_LOG_EVENT: 'false',
        POWERTOOLS_TRACER_CAPTURE_RESPONSE: 'true',
        POWERTOOLS_TRACER_CAPTURE_ERROR: 'true',
        SYNCHRONIZATION_FUNCTION_NAME: this.synchronizationLambda.functionName,
        AWS_ACCOUNT_ID: stack.account,
        STACK_ID: stack.stackId,
      },
      memorySize: 128,
      timeout: Duration.minutes(5),
      role: customResourceRole,
      tracing: Tracing.ACTIVE,
    });

    {
      const childToMod = this.customResourceProvider.node.findChild('Resource') as CfnFunction;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W58',
              reason: 'False positive. Access is provided via a policy',
            },
            {
              id: 'W89',
              reason: 'There is no need to run this lambda in a VPC',
            },
            {
              id: 'W92',
              reason: 'There is no need for Reserved Concurrency',
            },
          ],
        },
      };
    }
    addCfnGuardSuppression(this.customResourceProvider, 'LAMBDA_INSIDE_VPC');
    addCfnGuardSuppression(this.customResourceProvider, 'LAMBDA_CONCURRENCY_CHECK');

    //---------------------------------------------------------------------
    // Synchronization EventBridge Rule - Weekly scheduled trigger
    //---------------------------------------------------------------------
    const synchronizationWeeklyRule = new Rule(this, 'SynchronizationFindingsLambdaWeeklyRule', {
      ruleName: props.resourceNamePrefix + '-ASR-SynchronizationFindingsLambdaWeeklyRule',
      schedule: Schedule.cron({
        minute: '0',
        hour: '2', // 2 AM UTC
        weekDay: 'SAT', // Every Saturday
      }),
      description: 'Weekly full synchronization of Security Hub findings - always performs complete sync',
    });

    synchronizationWeeklyRule.addTarget(
      new LambdaFunction(this.synchronizationLambda, {
        event: RuleTargetInput.fromObject({
          source: 'aws.events',
          'detail-type': 'Scheduled Event',
          detail: {
            syncType: 'baseline',
          },
        }),
        retryAttempts: 2,
      }),
    );
  }
}
