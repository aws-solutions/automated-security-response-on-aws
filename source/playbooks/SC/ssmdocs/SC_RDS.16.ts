// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { DataTypeEnum, HardCodedBoolean, HardCodedString, Output, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableCopyTagsToSnapshotOnRDSClusterDocument(scope, id, { ...props, controlId: 'RDS.16' });
}

class EnableCopyTagsToSnapshotOnRDSClusterDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'RDS.16',
      remediationName: 'EnableCopyTagsToSnapshotOnRDSCluster',
      scope: RemediationScope.REGIONAL,
      updateDescription: HardCodedString.of('Copy Tags to Snapshots enabled on RDS DB cluster'),
    });
  }

  /** @override */
  protected getParseInputStepOutputs(): Output[] {
    const outputs = super.getParseInputStepOutputs();

    outputs.push({
      name: 'DbiResourceId',
      outputType: DataTypeEnum.STRING,
      selector: '$.Payload.details.AwsRdsDbCluster.DbClusterResourceId',
    });

    return outputs;
  }

  /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    const params = super.getRemediationParams();

    params.DbClusterResourceId = StringVariable.of('ParseInput.DbiResourceId');
    params.ApplyImmediately = HardCodedBoolean.TRUE;

    return params;
  }
}
