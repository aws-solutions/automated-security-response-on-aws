// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableAPIGatewayCacheDataEncryptionDocument(scope, id, { ...props, controlId: 'APIGateway.5' });
}

export class EnableAPIGatewayCacheDataEncryptionDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'APIGateway.5',
      remediationName: 'EnableAPIGatewayCacheDataEncryption',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'APIGatewayStageArn',
      updateDescription: HardCodedString.of('API Gateway REST API stage cache data encryption enabled'),
    });
  }
}
