// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import {
  AutomationStep,
  DataTypeEnum,
  NumberVariable,
  Output,
  StringFormat,
  StringVariable,
} from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableElastiCacheBackups(scope, id, { ...props, controlId: 'ElastiCache.1' });
}

export class EnableElastiCacheBackups extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'ElastiCache.1',
      remediationName: 'EnableElastiCacheBackups',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'ResourceARN',
      updateDescription: new StringFormat('Automatic backups enabled for cluster %s.', [
        StringVariable.of(`ParseInput.ResourceARN`),
      ]),
    });
  }

  protected override getExtraSteps(): AutomationStep[] {
    return [
      super.getInputParamsStep({
        snapshotRetentionPeriod: 1,
      }),
    ];
  }

  protected override getInputParamsStepOutput(): Output[] {
    const requiredTagKeys: Output = {
      name: 'snapshotRetentionPeriod',
      outputType: DataTypeEnum.INTEGER,
      selector: '$.Payload.snapshotRetentionPeriod',
    };

    return [requiredTagKeys];
  }

  protected override getRemediationParams(): Record<string, any> {
    const params: Record<string, any> = super.getRemediationParams();

    params.SnapshotRetentionPeriod = NumberVariable.of('GetInputParams.snapshotRetentionPeriod');

    return params;
  }
}
