// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { Input, StringFormat, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new RevokeUnrotatedKeysDocument(scope, id, { ...props, controlId: 'IAM.3' });
}

export class RevokeUnrotatedKeysDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    const docInputs: Input[] = [
      Input.ofTypeString('MaxCredentialUsageAge', {
        description: '(Required) Maximum number of days a key can be unrotated. The default value is 90 days.',
        defaultValue: '90',
        allowedPattern: String.raw`^(?:[1-9]\d{0,3}|10000)$`,
      }),
    ];

    super(scope, id, {
      ...props,
      docInputs,
      securityControlId: 'IAM.3',
      remediationName: 'RevokeUnrotatedKeys',
      scope: RemediationScope.GLOBAL,
      resourceIdName: 'IAMUserName',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):iam::\d{12}:user(?:(?:\/)|(?:\/.{1,510}\/))([\w+=,.@_-]{1,64})$`,
      updateDescription: new StringFormat('Deactivated unrotated keys for %s.', [
        StringVariable.of(`ParseInput.IAMUserName`),
      ]),
    });
  }

  protected override getRemediationParams(): Record<string, any> {
    const params: Record<string, any> = super.getRemediationParams();

    if (this.resourceIdName) {
      // Not used by remediation
      delete params[this.resourceIdName];
    }
    params.IAMUserName = StringVariable.of('ParseInput.IAMUserName');
    params.MaxCredentialUsageAge = StringVariable.of('MaxCredentialUsageAge');

    return params;
  }
}
