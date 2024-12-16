// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { StackProps, Stack, App, CfnParameter } from 'aws-cdk-lib';
import { Bucket } from 'aws-cdk-lib/aws-s3';
import { CfnPolicy, Policy, PolicyStatement, Role, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import * as cdk_nag from 'cdk-nag';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { LogGroup, RetentionDays } from 'aws-cdk-lib/aws-logs';
import * as cdk from 'aws-cdk-lib';
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import { addCfnGuardSuppression } from '../../lib/cdk-helper/add-cfn-nag-suppression';

export interface SolutionProps extends StackProps {
  solutionId: string;
  solutionDistBucket: string;
  solutionVersion: string;
  solutionTMN: string;
  runtimePython: Runtime;
}

export interface BlueprintProps extends StackProps {
  solutionInfo: SolutionProps;
  functionName: string;
  serviceName: string;
  requiredSecretKeys: string[];
  exampleUri: string;
  uriPattern: string;
}

export class BlueprintStack extends Stack {
  private readonly solutionsBucket;
  private readonly instanceURIParam;
  private readonly secretArnParam;
  private readonly blueprintLayer;
  private readonly ticketGeneratorRole;
  constructor(scope: App, id: string, props: BlueprintProps) {
    super(scope, id, props);

    //-------------------------------------------------------------------------
    // Solutions Bucket - Source Code
    //
    const solutionsBucket = Bucket.fromBucketAttributes(this, 'SolutionsBucket', {
      bucketName: props.solutionInfo.solutionDistBucket + '-' + this.region,
    });

    const instanceURIParam = new CfnParameter(this, `InstanceURI`, {
      type: 'String',
      description: `The URI of your ${props.serviceName} instance. For example: ${props.exampleUri}`,
      allowedPattern: props.uriPattern,
    });

    const secretArnParam = new CfnParameter(this, 'SecretArn', {
      type: 'String',
      description: `The ARN of the Secrets Manager secret where you have stored your API credentials. This must be a JSON secret with the following keys: ${props.requiredSecretKeys.toString()}.`,
      allowedPattern: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):secretsmanager:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:secret:.+$`,
    });

    const ticketGeneratorPolicy = new Policy(this, `TicketGeneratorPolicy-${props.serviceName}`, {
      statements: [
        new PolicyStatement({
          actions: ['secretsmanager:GetSecretValue'],
          resources: [secretArnParam.valueAsString],
        }),
        new PolicyStatement({
          actions: ['logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'],
          resources: ['*'],
        }),
        new PolicyStatement({
          actions: ['organizations:ListAccounts'],
          resources: ['*'],
        }),
      ],
    });

    {
      const childToMod = ticketGeneratorPolicy.node.findChild('Resource') as CfnPolicy;
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W12',
              reason: 'Resource * is required to create CloudWatch logs.',
            },
          ],
        },
      };
    }

    cdk_nag.NagSuppressions.addResourceSuppressions(ticketGeneratorPolicy, [
      {
        id: 'AwsSolutions-IAM5',
        appliesTo: ['Resource::*'],
        reason: 'Resource * is required to create CloudWatch logs.',
      },
    ]);

    const ticketGeneratorRole = new Role(this, `TicketGeneratorRole-${props.serviceName}`, {
      assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
      description: `Lambda role created by ${props.solutionInfo.solutionTMN} to grant permissions to the ${props.serviceName}TicketGenerator Lambda.`,
    });
    ticketGeneratorRole.attachInlinePolicy(ticketGeneratorPolicy);

    const blueprintLayer = new lambda.LayerVersion(this, `ASR-BlueprintLayer-${props.serviceName}`, {
      compatibleRuntimes: [props.solutionInfo.runtimePython],
      description: `Layer created by ${props.solutionInfo.solutionTMN} to package dependencies necessary for Blueprint ticket generator functions.`,
      license: 'https://www.apache.org/licenses/LICENSE-2.0',
      code: lambda.Code.fromBucket(
        solutionsBucket,
        props.solutionInfo.solutionTMN + '/' + props.solutionInfo.solutionVersion + '/lambda/blueprints/python.zip',
      ),
    });

    const ticketGeneratorLogs = new LogGroup(this, `Ticket-Generator-Logs-${props.serviceName}`, {
      logGroupName: `/aws/lambda/${props.functionName}`,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      retention: RetentionDays.TEN_YEARS,
    });
    addCfnGuardSuppression(ticketGeneratorLogs, 'CLOUDWATCH_LOG_GROUP_ENCRYPTED');

    this.solutionsBucket = solutionsBucket;
    this.instanceURIParam = instanceURIParam;
    this.secretArnParam = secretArnParam;
    this.blueprintLayer = blueprintLayer;
    this.ticketGeneratorRole = ticketGeneratorRole;
  }

  protected getInstanceURIParam() {
    return this.instanceURIParam;
  }

  protected getSolutionsBucket() {
    return this.solutionsBucket;
  }

  protected getSecretArnParam() {
    return this.secretArnParam;
  }

  protected getBlueprintLayer() {
    return this.blueprintLayer;
  }

  protected getTicketGeneratorRole() {
    return this.ticketGeneratorRole;
  }
}
