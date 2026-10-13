// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from 'constructs';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { addCfnGuardSuppression } from './add-cfn-guard-suppression';
import { createLogGroup } from './log-group';
import { IBucket } from 'aws-cdk-lib/aws-s3';
import { getLambdaCode } from './lambda-code-manifest';
import { CfnPolicy, Policy, PolicyDocument, PolicyStatement, Role, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import { CfnParameter, Duration, Stack } from 'aws-cdk-lib';
import * as cdk from 'aws-cdk-lib';
import { attachCommercialPartitionSecurityHubV2Policy } from './is-commercial-partition';

interface MetricResourcesProps {
  solutionTMN: string;
  solutionVersion: string;
  solutionId: string;
  runtimePython: lambda.Runtime;
  solutionsBucket: IBucket;
  lambdaLayer: lambda.ILayerVersion;
}

export default class MetricResources extends Construct {
  securityHubV2Enabled: string;

  constructor(scope: Construct, id: string, props: MetricResourcesProps) {
    super(scope, id);
    const stack = Stack.of(this);

    const customResourceLambdaPolicyDocument = new PolicyDocument({
      statements: [
        new PolicyStatement({ actions: ['cloudwatch:PutMetricData'], resources: ['*'] }),
        new PolicyStatement({
          actions: ['logs:CreateLogStream', 'logs:PutLogEvents'],
          resources: [`arn:${stack.partition}:logs:*:${stack.account}:log-group:*:log-stream:*`],
        }),
        new PolicyStatement({
          actions: ['logs:CreateLogGroup'],
          resources: [`arn:${stack.partition}:logs:*:${stack.account}:log-group:*`],
        }),
        new PolicyStatement({
          actions: ['ssm:GetParameter', 'ssm:GetParameters', 'ssm:PutParameter', 'ssm:DeleteParameter'],
          resources: [`arn:${stack.partition}:ssm:*:${stack.account}:parameter/Solutions/SO0111/*`],
        }),
      ],
    });

    const customResourceLambdaRole = new Role(this, `${id}Role`, {
      assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
      inlinePolicies: { LambdaPolicy: customResourceLambdaPolicyDocument },
    });

    // securityhub:DescribeSecurityHubV2 (Security Hub V2 / OCSF) exists only in the aws
    // (commercial) partition, so attaching it in aws-us-gov or aws-cn makes IAM reject this
    // role at CREATE and rolls the whole admin stack back. Gate it on the stack-level
    // commercial-partition condition, as the pre-processor and batch-processor roles already
    // do. Where the policy is omitted, the custom resource's describe_security_hub_v2 call
    // fails with AccessDeniedException, which is_securityhub_v2_enabled already treats as
    // "V2 unavailable" and reports as securityhub_v2_enabled=false — the correct answer in a
    // partition that has no Security Hub V2 — so the resource still succeeds.
    const securityHubV2Policy = attachCommercialPartitionSecurityHubV2Policy(
      this,
      'MetricResourcesSecurityHubV2Policy',
      customResourceLambdaRole,
    );

    addCfnGuardSuppression(customResourceLambdaRole, 'IAM_NO_INLINE_POLICY_CHECK');
    addCfnGuardSuppression(customResourceLambdaRole, 'IAM_POLICYDOCUMENT_NO_WILDCARD_RESOURCE');

    const customResourceFunction = new lambda.Function(this, 'ASR-DeploymentCustomResource-Lambda', {
      code: getLambdaCode(
        props.solutionsBucket,
        props.solutionTMN,
        props.solutionVersion,
        'deployment_metrics_custom_resource.zip',
      ),
      handler: 'deployment_metrics_custom_resource.lambda_handler',
      runtime: props.runtimePython,
      description: 'ASR - Handles deployment related custom actions',
      environment: {
        LOG_LEVEL: 'INFO',
        AWS_PARTITION: Stack.of(this).partition,
        SOLUTION_ID: props.solutionId,
        SOLUTION_VERSION: props.solutionVersion,
        POWERTOOLS_SERVICE_NAME: 'deployment_metrics_custom_resource',
        POWERTOOLS_LOG_LEVEL: 'INFO',
        POWERTOOLS_LOGGER_LOG_EVENT: 'false',
        POWERTOOLS_TRACER_CAPTURE_RESPONSE: 'true',
        POWERTOOLS_TRACER_CAPTURE_ERROR: 'true',
        AWS_ACCOUNT_ID: stack.account,
        STACK_ID: stack.stackId,
      },
      memorySize: 256,
      timeout: Duration.seconds(5),
      role: customResourceLambdaRole,
      layers: [props.lambdaLayer],
      logGroup: createLogGroup(this, 'ASR-DeploymentCustomResource-LambdaLogGroup'),
    });

    addCfnGuardSuppression(customResourceFunction, 'LAMBDA_INSIDE_VPC');
    addCfnGuardSuppression(customResourceFunction, 'LAMBDA_CONCURRENCY_CHECK');

    const deploymentMetricsCustomResource = new cdk.CustomResource(this, `ASR-DeploymentMetricsCustomResource`, {
      properties: {
        StackParameters: MetricResources.getAllStackParameters(Stack.of(this)),
        Timestamp: Date.now().toString(), // Forces the custom resource to run on stack updates
        // Orders the invoke after the gated policy so describe_security_hub_v2 does not run before the grant exists.
        // A DependsOn would fail CreateStack in aws-us-gov and aws-cn, where the policy is not created.
        SecurityHubV2PolicyDependency: MetricResources.conditionalReference(securityHubV2Policy),
      },
      resourceType: 'Custom::DeploymentMetrics',
      serviceToken: customResourceFunction.functionArn,
    });

    this.securityHubV2Enabled = deploymentMetricsCustomResource.getAtt('securityhub_v2_enabled').toString();
  }

  /** Resolves to a `Ref` to `policy` when its condition holds and to `AWS::NoValue` otherwise. */
  private static conditionalReference(policy: Policy): string {
    const cfnPolicy = policy.node.defaultChild;
    const condition = cfnPolicy instanceof CfnPolicy ? cfnPolicy.cfnOptions.condition : undefined;
    if (!(cfnPolicy instanceof CfnPolicy) || !condition) {
      throw new Error(`${policy.node.id}: expected a conditioned AWS::IAM::Policy to reference`);
    }
    return cdk.Fn.conditionIf(condition.logicalId, cfnPolicy.ref, cdk.Aws.NO_VALUE).toString();
  }

  private static getAllStackParameters(stack: Stack): Record<string, string> {
    const parameters: Record<string, string> = {};

    const children = stack.node.findAll();
    children.forEach((child) => {
      if (child instanceof CfnParameter) {
        parameters[child.logicalId] = MetricResources.getParameterValue(child);
      }
    });

    return parameters;
  }

  private static getParameterValue(parameter: CfnParameter): string {
    const isListParameter = parameter.type.includes('List<') || parameter.type.includes('CommaDelimitedList');

    return isListParameter ? cdk.Fn.join(',', parameter.valueAsList) : parameter.valueAsString;
  }
}
