// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { DataTypeEnum, HardCodedBoolean, HardCodedString, Output, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new ConfigureS3PublicAccessBlockDocument(scope, id, { ...props, controlId: 'S3.1' });
}

export class ConfigureS3PublicAccessBlockDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'S3.1',
      remediationName: 'ConfigureS3PublicAccessBlock',
      scope: RemediationScope.GLOBAL,
      updateDescription: HardCodedString.of('Configured the account to block public S3 access.'),
    });
  }

  protected override getParseInputStepOutputs(): Output[] {
    const outputs = super.getParseInputStepOutputs();

    outputs.push({
      name: 'RemediationAccount',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.account_id',
    });

    return outputs;
  }

  protected override getRemediationParams(): Record<string, any> {
    const params = super.getRemediationParams();

    params.AccountId = StringVariable.of('ParseInput.RemediationAccount');
    params.RestrictPublicBuckets = HardCodedBoolean.TRUE;
    params.BlockPublicAcls = HardCodedBoolean.TRUE;
    params.IgnorePublicAcls = HardCodedBoolean.TRUE;
    params.BlockPublicPolicy = HardCodedBoolean.TRUE;

    return params;
  }
}
