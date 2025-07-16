// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as cdk from 'aws-cdk-lib';
import { LogGroup, RetentionDays } from 'aws-cdk-lib/aws-logs';
import { Key } from 'aws-cdk-lib/aws-kms';

export interface OrchLogStackProps extends cdk.StackProps {
  logGroupName: string;
  solutionId: string;
}

export class OrchLogStack extends cdk.Stack {
  constructor(scope: cdk.App, id: string, props: OrchLogStackProps) {
    super(scope, id, props);

    const reuseOrchLogGroup = new cdk.CfnParameter(this, 'Reuse Log Group', {
      type: 'String',
      description: `Reuse existing Orchestrator Log Group? Choose "yes" if the Orchestrator Log Group still exists from an earlier deployment in this account, otherwise "no". 
      If you are performing a stack update from an earlier version than v2.3.0 choose "no".`,
      default: 'no',
      allowedValues: ['yes', 'no'],
    });
    reuseOrchLogGroup.overrideLogicalId(`ReuseOrchestratorLogGroup`);

    const kmsKeyArn = new cdk.CfnParameter(this, 'KMS Key Arn', {
      type: 'String',
      description: `ARN of the KMS key to use to encrypt log data.`,
    });
    kmsKeyArn.overrideLogicalId(`KmsKeyArn`);

    const kmsKey = Key.fromKeyArn(this, 'KmsKey', kmsKeyArn.valueAsString);
    new LogGroup(this, 'Orchestrator-Logs-Encrypted', {
      logGroupName: props.logGroupName,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      retention: RetentionDays.TEN_YEARS,
      encryptionKey: kmsKey,
    });
  }
}
