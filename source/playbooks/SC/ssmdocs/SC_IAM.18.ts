// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new CreateIAMSupportRoleDocument(scope, id, { ...props, controlId: 'IAM.18' });
}

export class CreateIAMSupportRoleDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    const remediationName = 'CreateIAMSupportRole';

    super(scope, id, {
      ...props,
      securityControlId: 'IAM.18',
      remediationName,
      scope: RemediationScope.GLOBAL,
      updateDescription: HardCodedString.of(
        `Create an IAM role to allow authorized users to manage incidents with AWS Support using the ${props.solutionAcronym}-${remediationName} runbook.`,
      ),
    });
  }
}
