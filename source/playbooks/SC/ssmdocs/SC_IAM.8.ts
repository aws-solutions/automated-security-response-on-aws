// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ParameterRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new RevokeUnusedIAMUserCredentialsDocument(scope, id, { ...props, controlId: 'IAM.8' });
}

export class RevokeUnusedIAMUserCredentialsDocument extends ControlRunbookDocument {
  maxCredentialUsageAge?: string;
  constructor(scope: Construct, id: string, props: ParameterRunbookProps) {
    const remediationName = 'RevokeUnusedIAMUserCredentials';

    super(scope, id, {
      ...props,
      securityControlId: 'IAM.8',
      remediationName,
      scope: RemediationScope.GLOBAL,
      resourceIdName: 'IAMUserName',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):iam::\d{12}:user(?:(?:\/)|(?:\/.{1,510}\/))([\w+=,.@_-]{1,64})$`,
      updateDescription: HardCodedString.of(
        `Deactivated unused keys and expired logins using the ${props.solutionAcronym}-${remediationName} runbook.`,
      ),
    });
    this.maxCredentialUsageAge = props.parameterToPass ?? '90';
  }

  protected override getRemediationParams(): Record<string, any> {
    const params: Record<string, any> = super.getRemediationParams();

    params.IAMUserName = StringVariable.of('ParseInput.IAMUserName');
    params.MaxCredentialUsageAge = HardCodedString.of(this.maxCredentialUsageAge as string);
    return params;
  }
}
