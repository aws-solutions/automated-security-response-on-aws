// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { DataTypeEnum, HardCodedString, Output, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new IAM_8_ControlRunbookDocument(scope, id, { ...props, controlId: 'IAM.8' });
}

export class IAM_8_ControlRunbookDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    const remediationName = 'RevokeUnusedIAMUserCredentials';

    super(scope, id, {
      ...props,
      securityControlId: 'IAM.8',
      remediationName,
      scope: RemediationScope.GLOBAL,
      updateDescription: HardCodedString.of(
        `Deactivated unused keys and expired logins using the ${props.solutionAcronym}-${remediationName} runbook.`
      ),
    });
  }

  /** @override */
  protected getParseInputStepOutputs(): Output[] {
    const outputs: Output[] = super.getParseInputStepOutputs();

    outputs.push({
      name: 'IAMResourceId',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.details.AwsIamUser.UserId',
    });

    return outputs;
  }

  /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const params: { [_: string]: any } = super.getRemediationParams();

    params.IAMResourceId = StringVariable.of('ParseInput.IAMResourceId');

    return params;
  }
}
