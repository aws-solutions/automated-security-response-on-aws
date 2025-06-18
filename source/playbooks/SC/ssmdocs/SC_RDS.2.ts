// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { DataTypeEnum, HardCodedString, Output, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new DisablePublicAccessToRDSInstanceDocument(scope, id, { ...props, controlId: 'RDS.2' });
}

export class DisablePublicAccessToRDSInstanceDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'RDS.2',
      remediationName: 'DisablePublicAccessToRDSInstance',
      scope: RemediationScope.REGIONAL,
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):rds:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:db:((?!.*--.*)(?!.*-$)[a-z][a-z0-9-]{0,62})$`,
      updateDescription: HardCodedString.of('Disabled public access to RDS instance'),
    });
  }

  protected override getParseInputStepOutputs(): Output[] {
    const outputs = super.getParseInputStepOutputs();

    outputs.push({
      name: 'DbiResourceId',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.resource.Details.AwsRdsDbInstance.DbiResourceId',
    });

    return outputs;
  }

  protected override getRemediationParams(): Record<string, any> {
    const params = super.getRemediationParams();

    params.DbiResourceId = StringVariable.of('ParseInput.DbiResourceId');

    return params;
  }
}
