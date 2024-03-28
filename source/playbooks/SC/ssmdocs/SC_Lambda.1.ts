// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { StringFormat, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new RemoveLambdaPublicAccessDocument(scope, id, { ...props, controlId: 'Lambda.1' });
}

export class RemoveLambdaPublicAccessDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    const resourceIdName = 'FunctionName';

    super(scope, id, {
      ...props,
      securityControlId: 'Lambda.1',
      remediationName: 'RemoveLambdaPublicAccess',
      scope: RemediationScope.REGIONAL,
      resourceIdName,
      resourceIdRegex: String.raw`^arn:(?:aws|aws-us-gov|aws-cn):lambda:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:function:([a-zA-Z0-9\-_]{1,64})$`,
      updateDescription: new StringFormat('Lamdba %s policy updated to remove public access', [
        StringVariable.of(`ParseInput.${resourceIdName}`),
      ]),
    });
  }
}
