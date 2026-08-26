// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as lambda from 'aws-cdk-lib/aws-lambda';
import { CfnFunction, Runtime, Tracing } from 'aws-cdk-lib/aws-lambda';
import { Construct } from 'constructs';
import { CfnPolicy, CfnRole, Policy, PolicyStatement, Role, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import { addCfnGuardSuppression } from '../cdk-helper/add-cfn-guard-suppression';
import { createLogGroup } from '../cdk-helper/log-group';
import { getLambdaCode } from '../cdk-helper/lambda-code-manifest';
import { IBucket } from 'aws-cdk-lib/aws-s3';
import { IKey } from 'aws-cdk-lib/aws-kms';
import { CustomResource, Duration, Stack } from 'aws-cdk-lib';

export interface IaCTemplateSyncConstructProps {
  readonly solutionId: string;
  readonly solutionTMN: string;
  readonly solutionVersion: string;
  readonly sourceCodeBucket: IBucket;
  readonly customerBucket: IBucket;
  readonly customerBucketEncryptionKey: IKey;
  readonly namespace: string;
}

export class IaCTemplateSyncConstruct extends Construct {
  constructor(scope: Construct, id: string, props: IaCTemplateSyncConstructProps) {
    super(scope, id);

    const stack = Stack.of(this);
    const RESOURCE_NAME_PREFIX = props.solutionId.replace(/^DEV-/, '');

    //---------------------------------------------------------------------
    // IaC Template Sync Lambda Role and Policy
    //---------------------------------------------------------------------
    const iacTemplateSyncPolicy = new Policy(this, 'IaCTemplateSyncPolicy', {
      policyName: RESOURCE_NAME_PREFIX + '-ASR_IaCTemplateSync',
      statements: [
        new PolicyStatement({
          actions: ['logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'],
          resources: [`arn:${stack.partition}:logs:*:${stack.account}:log-group:*`],
        }),
        new PolicyStatement({
          actions: ['s3:GetObject'],
          resources: [`${props.sourceCodeBucket.bucketArn}/*`],
        }),
        new PolicyStatement({
          actions: ['s3:GetObject', 's3:PutObject', 's3:DeleteObject'],
          resources: [`${props.customerBucket.bucketArn}/*`],
        }),
        new PolicyStatement({
          actions: ['s3:ListBucket'],
          resources: [props.customerBucket.bucketArn],
        }),
        // The customer bucket is encrypted with the solution CMK, so reading and
        // writing objects requires KMS access in addition to the S3 actions above.
        new PolicyStatement({
          actions: ['kms:Decrypt', 'kms:GenerateDataKey'],
          resources: [props.customerBucketEncryptionKey.keyArn],
        }),
      ],
    });

    {
      const childToMod = iacTemplateSyncPolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required for CloudWatch Logs policies used by IaC template sync Lambda function.',
            },
          ],
        },
      };
    }

    const iacTemplateSyncRole = new Role(this, 'IaCTemplateSyncRole', {
      assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
      description: 'Lambda role for ASR IaC template sync function',
      roleName: `${RESOURCE_NAME_PREFIX}-ASR-IaCTemplateSync`,
    });

    iacTemplateSyncRole.attachInlinePolicy(iacTemplateSyncPolicy);

    {
      const childToMod = iacTemplateSyncRole.node.findChild('Resource') as CfnRole;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W28',
              reason: 'Static names chosen intentionally to provide easy integration with IaC template sync function.',
            },
          ],
        },
      };
    }
    addCfnGuardSuppression(iacTemplateSyncRole, 'IAM_NO_INLINE_POLICY_CHECK');

    //---------------------------------------------------------------------
    // IaC Template Sync Lambda Function
    //---------------------------------------------------------------------
    const iacTemplateSyncLambda = new lambda.Function(this, 'IaCTemplateSyncLambda', {
      functionName: RESOURCE_NAME_PREFIX + '-ASR-IaCTemplateSyncLambda',
      logGroup: createLogGroup(this, 'IaCTemplateSyncLambdaLogGroup'),
      handler: 'iac-template-sync/iacTemplateSyncHandler.handler',
      runtime: Runtime.NODEJS_24_X,
      description: 'IaC template sync custom resource lambda',
      code: getLambdaCode(props.sourceCodeBucket, props.solutionTMN, props.solutionVersion, 'asr_lambdas.zip'),
      environment: {
        SOLUTION_TRADEMARKEDNAME: props.solutionTMN,
        POWERTOOLS_SERVICE_NAME: 'iac_template_sync',
        POWERTOOLS_LOG_LEVEL: 'INFO',
        POWERTOOLS_LOGGER_LOG_EVENT: 'false',
        POWERTOOLS_TRACER_CAPTURE_RESPONSE: 'true',
        POWERTOOLS_TRACER_CAPTURE_ERROR: 'true',
        AWS_ACCOUNT_ID: stack.account,
        STACK_ID: stack.stackId,
      },
      memorySize: 256,
      timeout: Duration.minutes(5),
      role: iacTemplateSyncRole,
      tracing: Tracing.ACTIVE,
    });

    {
      const childToMod = iacTemplateSyncLambda.node.findChild('Resource') as CfnFunction;
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
    addCfnGuardSuppression(iacTemplateSyncLambda, 'LAMBDA_INSIDE_VPC');
    addCfnGuardSuppression(iacTemplateSyncLambda, 'LAMBDA_CONCURRENCY_CHECK');

    //---------------------------------------------------------------------
    // Custom Resource for IaC Template Sync
    //---------------------------------------------------------------------
    const iacTemplateSyncResource = new CustomResource(this, 'IaCTemplateSyncResource', {
      serviceToken: iacTemplateSyncLambda.functionArn,
      resourceType: 'Custom::IaCTemplateSync',
      properties: {
        SolutionsBucketName: props.sourceCodeBucket.bucketName,
        CustomerBucketName: props.customerBucket.bucketName,
        ManifestKey: `${props.solutionTMN}/${props.solutionVersion}/iac-templates/.metadata/manifest.json`,
        SolutionVersion: props.solutionVersion,
        TemplatePrefix: `${props.solutionTMN}/${props.solutionVersion}/iac-templates/`,
      },
      serviceTimeout: Duration.minutes(5),
    });

    // Ensure the Lambda and its role/policy are not deleted before the custom resource
    // delete handler has finished executing. Without this, a partial stack delete can
    // remove the Lambda on the first pass, causing the custom resource delete to time
    // out on retry.
    iacTemplateSyncResource.node.addDependency(iacTemplateSyncLambda);
    iacTemplateSyncResource.node.addDependency(iacTemplateSyncRole);
    iacTemplateSyncResource.node.addDependency(iacTemplateSyncPolicy);
  }
}
