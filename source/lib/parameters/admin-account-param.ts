// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { CfnParameter } from 'aws-cdk-lib';
import { Construct } from 'constructs';

export default class AdminAccountParam extends Construct {
  public readonly paramId: string;
  public readonly value: string;

  constructor(scope: Construct, id: string) {
    super(scope, id);

    const accountIdRegex = /^\d{12}$/;
    const param = new CfnParameter(this, 'Admin Account Number', {
      description: 'Admin account number',
      type: 'String',
      allowedPattern: accountIdRegex.source,
    });
    param.overrideLogicalId(`SecHubAdminAccount`);
    this.paramId = param.logicalId;

    this.value = param.valueAsString;
  }
}
