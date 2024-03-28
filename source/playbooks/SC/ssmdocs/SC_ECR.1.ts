// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(stage: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnablePrivateRepositoryScanningDocument(stage, id, { ...props, controlId: 'ECR.1' });
}

export class EnablePrivateRepositoryScanningDocument extends ControlRunbookDocument {
  constructor(stage: Construct, id: string, props: ControlRunbookProps) {
    super(stage, id, {
      ...props,
      securityControlId: 'ECR.1',
      remediationName: 'EnablePrivateRepositoryScanning',
      scope: RemediationScope.GLOBAL,
      resourceIdName: 'RepositoryName',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):ecr:[a-z]{2}-[a-z]+-\d{1}:\d{12}:repository\/([a-z0-9._\/\-]+)$`,
      updateDescription: HardCodedString.of('Enabling image scanning for private ECR repository.'),
    });
  }
}
