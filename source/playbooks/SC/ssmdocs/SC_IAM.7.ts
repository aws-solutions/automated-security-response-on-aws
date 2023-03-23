// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedBoolean, HardCodedNumber, HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new SetIAMPasswordPolicyDocument(scope, id, {
    ...props,
    controlId: 'IAM.7',
    otherControlIds: ['IAM.11', 'IAM.12', 'IAM.13', 'IAM.14', 'IAM.15', 'IAM.16', 'IAM.17'],
  });
}

export class SetIAMPasswordPolicyDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    const remediationName = 'SetIAMPasswordPolicy';

    super(scope, id, {
      ...props,
      securityControlId: 'IAM.7',
      remediationName,
      scope: RemediationScope.GLOBAL,
      updateDescription: HardCodedString.of(
        `Established a baseline password policy using the ${props.solutionAcronym}-${remediationName} runbook.`
      ),
    });
  }

  /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const params: { [_: string]: any } = super.getRemediationParams();

    params.AllowUsersToChangePassword = HardCodedBoolean.TRUE;
    params.HardExpiry = HardCodedBoolean.TRUE;
    params.MaxPasswordAge = HardCodedNumber.of(90);
    params.MinimumPasswordLength = HardCodedNumber.of(14);
    params.RequireSymbols = HardCodedBoolean.TRUE;
    params.RequireNumbers = HardCodedBoolean.TRUE;
    params.RequireUppercaseCharacters = HardCodedBoolean.TRUE;
    params.RequireLowercaseCharacters = HardCodedBoolean.TRUE;
    params.PasswordReusePrevention = HardCodedNumber.of(24);

    return params;
  }
}
