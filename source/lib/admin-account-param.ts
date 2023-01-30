// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';

export default class AdminAccountParam extends Construct {
  public readonly value: string;

  constructor(scope: Construct, id: string) {
    super(scope, id);

    const validAwsAccount = '^\\d{12}$';

    const param = new cdk.CfnParameter(this, 'Admin Account Number', {
      description: 'Admin account number',
      type: 'String',
      allowedPattern: validAwsAccount,
    });
    param.overrideLogicalId(`SecHubAdminAccount`);
    this.value = param.valueAsString;
  }
}
