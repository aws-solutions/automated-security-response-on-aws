// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as cdk from 'aws-cdk-lib';
import { LogGroup, CfnLogGroup, RetentionDays } from 'aws-cdk-lib/aws-logs';
import { Key } from 'aws-cdk-lib/aws-kms';

export interface OrchLogStackProps extends cdk.StackProps {
  logGroupName: string;
  solutionId: string;
}

export class OrchLogStack extends cdk.Stack {
  constructor(scope: cdk.App, id: string, props: OrchLogStackProps) {
    super(scope, id, props);
    const stack = cdk.Stack.of(this);

    const reuseOrchLogGroup = new cdk.CfnParameter(this, 'Reuse Log Group', {
      type: 'String',
      description: `Reuse existing Orchestrator Log Group? Choose "yes" if the log group already exists, else "no"`,
      default: 'no',
      allowedValues: ['yes', 'no'],
    });
    reuseOrchLogGroup.overrideLogicalId(`ReuseOrchestratorLogGroup`);

    const kmsKeyArn = new cdk.CfnParameter(this, 'KMS Key Arn', {
      type: 'String',
      description: `ARN of the KMS key to use to encrypt log data.`,
    });
    kmsKeyArn.overrideLogicalId(`KmsKeyArn`);

    /**********************
     * Encrypted log group
     */
    // As of March 2021, CWLogs encryption is not yet supported in GovCloud
    // Choose based on partition

    const kmsKey = Key.fromKeyArn(this, 'KmsKey', kmsKeyArn.valueAsString);
    const orchestratorLogGroupEncrypted: LogGroup = new LogGroup(this, 'Orchestrator-Logs-Encrypted', {
      logGroupName: props.logGroupName,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      retention: RetentionDays.TEN_YEARS,
      encryptionKey: kmsKey,
    });

    /************************
     * Unencrypted log group
     */
    const orchestratorLogGroupNOTEncrypted: LogGroup = new LogGroup(this, 'Orchestrator-Logs', {
      logGroupName: props.logGroupName,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      retention: RetentionDays.TEN_YEARS,
    });

    /*******************
     *  Conditions
     */
    const isNotGovCloud = new cdk.CfnCondition(this, 'isNotGovCloud', {
      expression: cdk.Fn.conditionNot(cdk.Fn.conditionEquals(stack.partition, 'aws-us-gov')),
    });
    {
      const childToMod = orchestratorLogGroupEncrypted.node.defaultChild as CfnLogGroup;
      childToMod.cfnOptions.condition = new cdk.CfnCondition(this, 'Encrypted Log Group', {
        expression: cdk.Fn.conditionAnd(isNotGovCloud, cdk.Fn.conditionEquals(reuseOrchLogGroup.valueAsString, 'no')),
      });
    }

    {
      const childToMod = orchestratorLogGroupNOTEncrypted.node.defaultChild as CfnLogGroup;
      childToMod.cfnOptions.condition = new cdk.CfnCondition(this, 'Unencrypted Log Group', {
        expression: cdk.Fn.conditionAnd(
          cdk.Fn.conditionNot(isNotGovCloud),
          cdk.Fn.conditionEquals(reuseOrchLogGroup.valueAsString, 'no'),
        ),
      });
      childToMod.cfnOptions.metadata = {
        cfn_nag: {
          rules_to_suppress: [
            {
              id: 'W84',
              reason: 'KmsKeyId is not supported in GovCloud.',
            },
          ],
        },
      };
    }
  }
}
