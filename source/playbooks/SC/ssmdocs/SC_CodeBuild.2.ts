// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new ReplaceCodeBuildClearTextCredentialsDocument(scope, id, { ...props, controlId: 'CodeBuild.2' });
}

export class ReplaceCodeBuildClearTextCredentialsDocument extends ControlRunbookDocument {
  constructor(stage: Construct, id: string, props: ControlRunbookProps) {
    super(stage, id, {
      ...props,
      securityControlId: 'CodeBuild.2',
      remediationName: 'ReplaceCodeBuildClearTextCredentials',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'ProjectName',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):codebuild:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:project\/([A-Za-z0-9][A-Za-z0-9\-_]{1,254})$`,
      updateDescription: HardCodedString.of('Replaced clear text credentials with SSM parameters.'),
    });
  }
}
