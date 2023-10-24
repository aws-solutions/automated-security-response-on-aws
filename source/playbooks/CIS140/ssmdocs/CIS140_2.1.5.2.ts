// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { PlaybookProps } from '../../SC/lib/control_runbooks-construct';
import { ControlRunbookDocument } from '../../SC/ssmdocs/control_runbook';
import { ConfigureS3BucketPublicAccessBlockDocument } from '../../SC/ssmdocs/SC_S3.2';

export function createControlRunbook(stage: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new ConfigureS3BucketPublicAccessBlockDocument(stage, id, { ...props, controlId: '2.1.5.2' }); //NOSONAR This is not an IP Address.
}
