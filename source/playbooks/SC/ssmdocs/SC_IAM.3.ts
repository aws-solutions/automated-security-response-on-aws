// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { DataTypeEnum, Input, Output, StringFormat, StringVariable } from '@cdklabs/cdk-ssm-documents';

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

    const resourceIdName = 'IAMUser';

    super(scope, id, {
      ...props,
      docInputs,
      securityControlId: 'IAM.3',
      remediationName: 'RevokeUnrotatedKeys',
      scope: RemediationScope.GLOBAL,
      resourceIdName,
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):iam::\d{12}:user(?:(?:\u002F)|(?:\u002F[\u0021-\u007F]{1,510}\u002F))([\w+=,.@-]{1,64})$`,
      updateDescription: new StringFormat('Deactivated unrotated keys for %s.', [
        StringVariable.of(`ParseInput.${resourceIdName}`),
      ]),
    });
  }

  protected override getParseInputStepOutputs(): Output[] {
    const outputs: Output[] = super.getParseInputStepOutputs();

    outputs.push({
      name: 'IAMResourceId',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.details.AwsIamUser.UserId',
    });

    return outputs;
  }

  protected override getRemediationParams(): Record<string, any> {
    const params: Record<string, any> = super.getRemediationParams();

    if (this.resourceIdName) {
      // Not used by remediation
      delete params[this.resourceIdName];
    }
    params.IAMResourceId = StringVariable.of('ParseInput.IAMResourceId');
    params.MaxCredentialUsageAge = StringVariable.of('MaxCredentialUsageAge');

    return params;
  }
}
