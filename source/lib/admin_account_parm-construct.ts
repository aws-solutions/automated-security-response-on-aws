// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';

export class AdminAccountParm extends Construct {
  public readonly adminAccountNumber: cdk.CfnParameter;

  constructor(scope: Construct, id: string) {
    super(scope, id);

    const validAwsAccount = '\\d{12}';

    this.adminAccountNumber = new cdk.CfnParameter(this, 'Admin Account Number', {
      description: 'Admin account number',
      type: 'String',
      allowedPattern: validAwsAccount,
    });
    this.adminAccountNumber.overrideLogicalId(`SecHubAdminAccount`);
  }
}
