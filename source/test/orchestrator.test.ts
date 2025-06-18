// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { App, Aspects, DefaultStackSynthesizer, Stack } from 'aws-cdk-lib';
import { PolicyStatement, PolicyDocument, ServicePrincipal, AccountRootPrincipal } from 'aws-cdk-lib/aws-iam';
import { Key } from 'aws-cdk-lib/aws-kms';
import { StringParameter } from 'aws-cdk-lib/aws-ssm';
import { Template } from 'aws-cdk-lib/assertions';
import { AwsSolutionsChecks } from 'cdk-nag';
import { OrchestratorConstruct } from '../lib/common-orchestrator-construct';
import * as sqs from 'aws-cdk-lib/aws-sqs';

test('test App Orchestrator Construct', () => {
  const app = new App();
  const stack = new Stack(app, 'testStack', {
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    stackName: 'testStack',
  });

  const kmsKeyPolicy: PolicyDocument = new PolicyDocument();

  const kmsServicePolicy = new PolicyStatement({
    principals: [new ServicePrincipal('sns.amazonaws.com'), new ServicePrincipal(`logs.${stack.urlSuffix}`)],
    actions: ['kms:Encrypt*', 'kms:Decrypt*', 'kms:ReEncrypt*', 'kms:GenerateDataKey*', 'kms:Describe*'],
    resources: ['*'],
  });
  kmsKeyPolicy.addStatements(kmsServicePolicy);

  const kmsRootPolicy = new PolicyStatement({
    principals: [new AccountRootPrincipal()],
    actions: ['kms:*'],
    resources: ['*'],
  });
  kmsKeyPolicy.addStatements(kmsRootPolicy);

  const kmsKey = new Key(stack, 'SHARR-key', {
    enableKeyRotation: true,
    alias: 'TO0111-SHARR-Key',
    policy: kmsKeyPolicy,
  });

  const kmsKeyParm = new StringParameter(stack, 'SHARR_Key', {
    description: 'KMS Customer Managed Key that SHARR will use to encrypt data',
    parameterName: `/Solutions/SO0111/CMK_ARN`,
    stringValue: kmsKey.keyArn,
  });

  const schedulingQueue = new sqs.Queue(stack, 'SchedulingQueue', {
    encryption: sqs.QueueEncryption.KMS,
    enforceSSL: true,
    encryptionMasterKey: kmsKey,
  });

  new OrchestratorConstruct(stack, 'Orchestrator', {
    roleArn: 'arn:aws-test:iam::111122223333:role/TestRole',
    ssmDocStateLambda: 'arn:aws:lambda:us-east-1:111122223333:function/foobar',
    ssmExecDocLambda: 'arn:aws:lambda:us-east-1:111122223333:function/foobar',
    ssmExecMonitorLambda: 'arn:aws:lambda:us-east-1:111122223333:function/foobar',
    notifyLambda: 'arn:aws:lambda:us-east-1:111122223333:function/foobar',
    getApprovalRequirementLambda: 'arn:aws:lambda:us-east-1:111122223333:function/foobar',
    solutionId: 'bbb',
    solutionName: 'This is a test',
    solutionVersion: '1.1.1',
    orchLogGroup: 'ORCH_LOG_GROUP',
    kmsKeyParm: kmsKeyParm,
    sqsQueue: schedulingQueue,
  });
  Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));
  expect(Template.fromStack(stack)).toMatchSnapshot();
});
