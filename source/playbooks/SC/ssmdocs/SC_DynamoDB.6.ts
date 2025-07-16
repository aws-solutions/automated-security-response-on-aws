// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { StringFormat, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableDynamoDBDeletionProtection(scope, id, { ...props, controlId: 'DynamoDB.6' });
}

export class EnableDynamoDBDeletionProtection extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'DynamoDB.6',
      remediationName: 'EnableDynamoDBDeletionProtection',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'ResourceArn',
      updateDescription: new StringFormat('Deletion protection enabled for DynamoDB Table %s.', [
        StringVariable.of(`ParseInput.ResourceArn`),
      ]),
    });
  }
}
