// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { CfnParameter } from 'aws-cdk-lib';
import { EventPatternHelper } from '../cdk-helper/eventeattern-helper';

export default class AccountTargetParam extends Construct {
  private static readonly targetAccountIDsParameterDefault: string = 'ALL';
  public static readonly targetAccountIDsParameterRegex: RegExp = /^(ALL|\d{12}(,\s*\d{12})*)$/;
  private static readonly targetAccountIDsStrategyInclude: string = 'INCLUDE';
  private static readonly targetAccountIDsStrategyExclude: string = 'EXCLUDE';

  public readonly targetAccountIDs: CfnParameter;
  public readonly targetAccountIDsStrategy: CfnParameter;

  constructor(scope: Construct, id: string) {
    super(scope, id);

    // Each EventBridge rule's EventPattern has a maximum size limit of 4096 characters.
    // GeneratorId field can be up to 512 characters long.
    // We reserve an additional 20 characters as a buffer for other fields (e.g., fixed JSON structure overhead).
    // Therefore, the maximum allowed size for the list of AWS Account IDs is: 4096 - (512 + 20) = 3564 characters.
    // The TargetAccountIDs parameter must be "ALL" or a comma-separated list of 12-digit AWS Account IDs,
    const targetAccountIDs = new CfnParameter(this, 'TargetAccountIDs', {
      type: 'String',
      default: AccountTargetParam.targetAccountIDsParameterDefault,
      description: `List of AWS Account IDs. Use "ALL" to target all accounts, or provide a comma-separated list of 12-digit AWS account IDs.`,
      allowedPattern: AccountTargetParam.targetAccountIDsParameterRegex.source,
      constraintDescription: `Must be "ALL" or a comma-separated list of 12-digit AWS account IDs (e.g., "123456789012,098765432109")`,
      maxLength: EventPatternHelper.getPatternMaxLength(),
    });
    targetAccountIDs.overrideLogicalId('TargetAccountIDs');
    this.targetAccountIDs = targetAccountIDs;

    const targetAccountIDsStrategy = new CfnParameter(this, 'TargetAccountIDsStrategy', {
      type: 'String',
      default: AccountTargetParam.targetAccountIDsStrategyInclude,
      allowedValues: [
        AccountTargetParam.targetAccountIDsStrategyInclude,
        AccountTargetParam.targetAccountIDsStrategyExclude,
      ],
      description: `INCLUDE: Apply automated remediation only to the accounts listed. 
      EXCLUDE: Apply automated remediation to all accounts except those listed. \n
      You must manually enable automatic remediations in the Admin account after deploying (create/update) the solution's CloudFormation stacks.`,
    });
    targetAccountIDsStrategy.overrideLogicalId('TargetAccountIDsStrategy');
    this.targetAccountIDsStrategy = targetAccountIDsStrategy;
  }
}
