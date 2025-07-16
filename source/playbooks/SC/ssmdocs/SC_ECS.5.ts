// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { StringFormat, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(stage: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new LimitECSRootFilesystemAccess(stage, id, { ...props, controlId: 'ECS.5' });
}

export class LimitECSRootFilesystemAccess extends ControlRunbookDocument {
  constructor(stage: Construct, id: string, props: ControlRunbookProps) {
    super(stage, id, {
      ...props,
      securityControlId: 'ECS.5',
      remediationName: 'LimitECSRootFilesystemAccess',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'TaskDefinitionId',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):ecs:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:task-definition/([a-zA-Z0-9_-]{1,255}:\d)$`,
      updateDescription: new StringFormat('Created new revision for task definition %s.', [
        StringVariable.of(`ParseInput.TaskDefinitionId`),
      ]),
    });
  }
}
