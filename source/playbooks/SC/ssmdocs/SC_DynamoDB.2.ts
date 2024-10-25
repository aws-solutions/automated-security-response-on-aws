// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnablePITRForDynamoDbTableDocument(scope, id, { ...props, controlId: 'DynamoDB.2' });
}

export class EnablePITRForDynamoDbTableDocument extends ControlRunbookDocument {
  constructor(stage: Construct, id: string, props: ControlRunbookProps) {
    super(stage, id, {
      ...props,
      securityControlId: 'DynamoDB.2',
      remediationName: 'EnablePITRForDynamoDbTable',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'TableName',
      resourceIdRegex: String.raw`[a-zA-Z0-9_.-]{3,255}`,
      updateDescription: HardCodedString.of('Enables PointInTimeRecovery on an Amazon DynamoDB table using the UpdateContinuousBackups API.'),
    });
  }
}