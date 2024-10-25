// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { StringFormat, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableAPIGatewayTracingDocument(scope, id, { ...props, controlId: 'APIGateway.3' });
}

export class EnableAPIGatewayTracingDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'APIGateway.3',
      remediationName: 'EnableAPIGatewayTracing',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'StageArn',
      resourceIdRegex: String.raw`^arn:aws:apigateway:[a-z0-9-]+::\/restapis\/[a-z0-9]+\/stages\/[a-zA-Z0-9_-]+$`,
      updateDescription: new StringFormat('Enabled tracing on an Amazon API Gateway (API Gateway) stage/%s', [
        StringVariable.of('ParseInput.StageArn'),
      ]),
    });
  }
}
