// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from 'constructs';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { addCfnGuardSuppression } from './add-cfn-guard-suppression';
import { IBucket } from 'aws-cdk-lib/aws-s3';
import { PolicyDocument, PolicyStatement, Role, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import { CfnParameter, Duration, Stack } from 'aws-cdk-lib';
import * as cdk from 'aws-cdk-lib';

interface MetricResourcesProps {
  solutionTMN: string;
  solutionVersion: string;
  solutionId: string;
  runtimePython: lambda.Runtime;
  solutionsBucket: IBucket;
  lambdaLayer: lambda.ILayerVersion;
}

export default class MetricResources extends Construct {
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
          actions: ['ssm:GetParameter', 'ssm:GetParameters', 'ssm:PutParameter'],
          resources: [`arn:${stack.partition}:ssm:*:${stack.account}:parameter/Solutions/SO0111/*`],
        }),
      ],
    });

    const customResourceLambdaRole = new Role(this, `${id}Role`, {
      assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
      inlinePolicies: { LambdaPolicy: customResourceLambdaPolicyDocument },
    });

    addCfnGuardSuppression(customResourceLambdaRole, 'IAM_NO_INLINE_POLICY_CHECK');
    addCfnGuardSuppression(customResourceLambdaRole, 'IAM_POLICYDOCUMENT_NO_WILDCARD_RESOURCE');

    const customResourceFunction = new lambda.Function(this, 'ASR-DeploymentCustomResource-Lambda', {
      code: lambda.Code.fromBucket(
        props.solutionsBucket,
        props.solutionTMN + '/' + props.solutionVersion + '/lambda/deployment_metrics_custom_resource.zip',
      ),
      handler: 'deployment_metrics_custom_resource.lambda_handler',
      runtime: props.runtimePython,
      description: 'ASR - Handles deployment related custom actions',
      environment: {
        LOG_LEVEL: 'INFO',
        AWS_PARTITION: Stack.of(this).partition,
        SOLUTION_ID: props.solutionId,
        SOLUTION_VERSION: props.solutionVersion,
      },
      memorySize: 256,
      timeout: Duration.seconds(5),
      role: customResourceLambdaRole,
      layers: [props.lambdaLayer],
    });

    addCfnGuardSuppression(customResourceFunction, 'LAMBDA_INSIDE_VPC');
    addCfnGuardSuppression(customResourceFunction, 'LAMBDA_CONCURRENCY_CHECK');

    new cdk.CustomResource(this, `ASR-DeploymentMetricsCustomResource`, {
      properties: {
        StackParameters: MetricResources.getAllStackParameters(Stack.of(this)),
      },
      resourceType: 'Custom::DeploymentMetrics',
      serviceToken: customResourceFunction.functionArn,
    });
  }

  private static getAllStackParameters(stack: Stack): { [key: string]: any } {
    const parameters: { [key: string]: any } = {};

    const children = stack.node.findAll();
    children.forEach((child) => {
      if (child instanceof CfnParameter) {
        parameters[child.logicalId] = child.valueAsString;
      }
    });

    return parameters;
  }
}
