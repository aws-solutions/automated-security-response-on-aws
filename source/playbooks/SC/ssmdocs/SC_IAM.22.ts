// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { RevokeUnusedIAMUserCredentialsDocument } from './SC_IAM.8';

export function createControlRunbook(stage: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new RevokeUnusedIAMUserCredentialsDocument(stage, id, {
    ...props,
    controlId: 'IAM.22',
    parameterToPass: '45',
  });
}
