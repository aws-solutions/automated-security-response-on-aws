// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { CustomResource, Duration, Stack } from 'aws-cdk-lib';
import { PolicyDocument, PolicyStatement, Role, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import { Code, Function, Runtime } from 'aws-cdk-lib/aws-lambda';
import { Bucket } from 'aws-cdk-lib/aws-s3';
import { NagSuppressions } from 'cdk-nag';
import { Construct } from 'constructs';
import { addCfnGuardSuppression } from './cdk-helper/add-cfn-nag-suppression';

export interface WaitProviderProps {
  readonly serviceToken: string;
}

export interface WaitProviderLambdaProps {
  readonly solutionVersion: string;
  readonly solutionTMN: string;
  readonly solutionDistBucket: string;
  readonly runtimePython: Runtime;
}

export interface WaitResourceProps {
  readonly createIntervalSeconds: number;
  readonly updateIntervalSeconds: number;
  readonly deleteIntervalSeconds: number;
  readonly extraResourceProps?: Record<string, any>;
}

export class WaitProvider extends Construct {
  readonly serviceToken: string;

  protected constructor(scope: Construct, id: string, props: WaitProviderProps) {
    super(scope, id);

    this.serviceToken = props.serviceToken;
  }

  createWaitResource(scope: Construct, id: string, props: WaitResourceProps): CustomResource {
    return new CustomResource(scope, id, {
      serviceToken: this.serviceToken,
      resourceType: 'Custom::Wait',
      properties: {
        ...props.extraResourceProps,
        CreateIntervalSeconds: props.createIntervalSeconds,
        UpdateIntervalSeconds: props.updateIntervalSeconds,
        DeleteIntervalSeconds: props.deleteIntervalSeconds,
      },
    });
  }

  static fromServiceToken(scope: Construct, id: string, serviceToken: string): WaitProvider {
    return new WaitProvider(scope, id, { serviceToken });
  }

  static fromLambdaProps(scope: Construct, id: string, props: WaitProviderLambdaProps): WaitProvider {
    const policyDocument = new PolicyDocument({
      statements: [
        new PolicyStatement({ actions: ['cloudwatch:PutMetricData'], resources: ['*'] }),
        new PolicyStatement({
          actions: ['logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'],
          resources: ['*'],
        }),
      ],
    });

    const role = new Role(scope, `${id}Role`, {
      assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
      inlinePolicies: { LambdaPolicy: policyDocument },
    });
    addCfnGuardSuppression(role, 'IAM_NO_INLINE_POLICY_CHECK');
    addCfnGuardSuppression(role, 'IAM_POLICYDOCUMENT_NO_WILDCARD_RESOURCE');

    NagSuppressions.addResourceSuppressions(role, [
      {
        id: 'AwsSolutions-IAM5',
        reason: 'Resource * is needed for CloudWatch Logs policies used on Lambda functions.',
      },
    ]);

    const lambdaFunction = new Function(scope, `${id}Function`, {
      //NOSONAR This is not unknown code.
      role,
      runtime: props.runtimePython,
      code: Code.fromBucket(
        Bucket.fromBucketName(scope, 'Bucket', `${props.solutionDistBucket}-${Stack.of(scope).region}`),
        props.solutionTMN + '/' + props.solutionVersion + '/lambda/wait_provider.zip',
      ),
      handler: 'wait_provider.lambda_handler',
      environment: { LOG_LEVEL: 'INFO' },
      timeout: Duration.minutes(15),
    });
    addCfnGuardSuppression(lambdaFunction, 'LAMBDA_CONCURRENCY_CHECK');
    addCfnGuardSuppression(lambdaFunction, 'LAMBDA_INSIDE_VPC');

    return new WaitProvider(scope, id, { serviceToken: lambdaFunction.functionArn });
  }
}
