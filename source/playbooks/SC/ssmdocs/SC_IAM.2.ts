// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { DataTypeEnum, HardCodedString, Output, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new CreateIAMGroupToAttachUserPolicyDocument(scope, id, { ...props, controlId: 'IAM.2' });
}

class CreateIAMGroupToAttachUserPolicyDocument extends ControlRunbookDocument {
  constructor(stage: Construct, id: string, props: ControlRunbookProps) {
    super(stage, id, {
      ...props,
      securityControlId: 'IAM.2',
      remediationName: 'CreateIAMGroupToAttachUserPolicy',
      scope: RemediationScope.GLOBAL,
      updateDescription: HardCodedString.of('Created IAMGroup to attach user policies'),
    });
  }

  /** @override */
  protected getParseInputStepOutputs(): Output[] {
    const outputs: Output[] = super.getParseInputStepOutputs();

    outputs.push({
      name: 'IAMUser',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.details',
    });

    return outputs;
  }

  /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const params: { [_: string]: any } = super.getRemediationParams();

    params.IAMUser = StringVariable.of('ParseInput.IAMUser');
    return params;
  }
}
