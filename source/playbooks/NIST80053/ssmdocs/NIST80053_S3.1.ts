// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { PlaybookProps } from '../../SC/lib/control_runbooks-construct';
import { ControlRunbookDocument } from '../../SC/ssmdocs/control_runbook';
import { ConfigureS3PublicAccessBlockDocument } from '../../SC/ssmdocs/SC_S3.1';

export function createControlRunbook(stage: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new ConfigureS3PublicAccessBlockDocument(stage, id, { ...props, controlId: 'S3.1' });
}
