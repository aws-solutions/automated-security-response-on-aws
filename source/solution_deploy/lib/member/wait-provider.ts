// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { createHash, Hash } from 'crypto';
import { CfnCustomResource, CustomResource, Duration, Stack } from 'aws-cdk-lib';
import { Code, Function, Runtime } from 'aws-cdk-lib/aws-lambda';
import { Bucket } from 'aws-cdk-lib/aws-s3';
import { CfnDocument } from 'aws-cdk-lib/aws-ssm';
import { Construct } from 'constructs';
import { PolicyDocument, PolicyStatement, Role, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import { NagSuppressions } from 'cdk-nag';

export interface SsmDocumentWaitProviderProps {
  readonly solutionDistBucket?: string;
  readonly solutionVersion?: string;
  readonly solutionTMN?: string;
  readonly runtimePython?: Runtime;
  readonly serviceToken?: string;
}

export interface SsmDocumentWaitResourceProps {
  readonly document: CfnDocument;
}

export class SsmDocumentWaitProvider extends Construct {
  public readonly serviceToken: string;

  constructor(scope: Construct, id: string, props: SsmDocumentWaitProviderProps) {
    super(scope, id);

    if (!props.serviceToken) {
      if (!props.solutionDistBucket || !props.solutionVersion || !props.solutionTMN || !props.runtimePython) {
        throw new Error('If not specifying service token, you must specify all required properties');
      }

      const policyDocument = new PolicyDocument({
        statements: [
          new PolicyStatement({ actions: ['cloudwatch:PutMetricData'], resources: ['*'] }),
          new PolicyStatement({
            actions: ['logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'],
            resources: ['*'],
          }),
        ],
      });

      const role = new Role(this, 'Role', {
        assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
        inlinePolicies: { LambdaPolicy: policyDocument },
      });

      NagSuppressions.addResourceSuppressions(role, [
        {
          id: 'AwsSolutions-IAM5',
          reason: 'Resource * is needed for CloudWatch Logs policies used on Lambda functions.',
        },
      ]);

      const lambdaFunction = new Function(this, 'Function', {
        role,
        runtime: props.runtimePython,
        code: Code.fromBucket(
          Bucket.fromBucketName(this, 'Bucket', `${props.solutionDistBucket}-${Stack.of(this).region}`),
          props.solutionTMN + '/' + props.solutionVersion + '/lambda/wait_provider.zip'
        ),
        handler: 'wait_provider.lambda_handler',
        environment: { LOG_LEVEL: 'WARNING' },
        timeout: Duration.minutes(15),
      });

      this.serviceToken = lambdaFunction.functionArn;
    } else {
      this.serviceToken = props.serviceToken;
    }
  }

  private currentWaitResource: CustomResource | undefined;
  private hash: Hash | undefined;
  private readonly maxBatchedDocuments = 5;
  private batchedDocuments = 0;

  createWaitResource(scope: Construct, id: string, props: SsmDocumentWaitResourceProps): CustomResource {
    if (!this.currentWaitResource || !this.hash) {
      // no need for cryptographic security, we just need a property that indicates when the underlying document changes
      this.hash = createHash('sha256');
      this.currentWaitResource = new CustomResource(scope, id, {
        serviceToken: this.serviceToken,
        properties: {
          CreateIntervalSeconds: 1,
          UpdateIntervalSeconds: 1,
          DeleteIntervalSeconds: 0.5,
        },
        resourceType: 'Custom::Wait',
      });
    }

    const relevantProperties: string[] = [
      props.document.name,
      props.document.documentFormat,
      props.document.documentType,
      props.document.content,
      props.document.updateMethod,
    ];
    this.hash.update(JSON.stringify(relevantProperties));

    const waitResource = this.currentWaitResource;

    (waitResource.node.defaultChild as CfnCustomResource).addPropertyOverride(
      'DocumentPropertiesHash',
      this.hash.copy().digest('hex') // multiple calls to digest not allowed, copy to create rolling hash
    );

    ++this.batchedDocuments;

    if (this.batchedDocuments >= this.maxBatchedDocuments) {
      this.batchedDocuments = 0;
      this.currentWaitResource = undefined;
    }

    return waitResource;
  }

  createWaitResourceOld(scope: Construct, id: string, props: SsmDocumentWaitResourceProps): CustomResource {
    const relevantProperties: string[] = [
      props.document.name,
      props.document.documentFormat,
      props.document.documentType,
      props.document.content,
      props.document.updateMethod,
    ];
    // no need for cryptographic security, we just need a property that indicates when the underlying document changes
    const propertiesHash = createHash('sha256').update(JSON.stringify(relevantProperties)).digest('hex');
    return new CustomResource(scope, id, {
      serviceToken: this.serviceToken,
      properties: {
        CreateIntervalSeconds: 1,
        UpdateIntervalSeconds: 1,
        DeleteIntervalSeconds: 0.5,
        DocumentPropertiesHash: propertiesHash,
      },
      resourceType: 'Custom::Wait',
    });
  }
}
