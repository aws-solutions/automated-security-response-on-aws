// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString, StringVariable } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new EnableWAFV2LoggingDocument(scope, id, { ...props, controlId: 'WAF.11' });
}

export class EnableWAFV2LoggingDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    super(scope, id, {
      ...props,
      securityControlId: 'WAF.11',
      remediationName: 'EnableWAFV2LoggingDocument',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'LogDestinationConfigs',
      resourceIdRegex: String.raw`^arn:aws[a-z0-9-]*:logs:[a-z0-9-]+:\d{12}:log-group:[A-Za-z0-9\.\-\_\#\/]{1,1024}\:\*$`,
      updateDescription: HardCodedString.of('This document enables logging for an AWS WAF (AWS WAFV2) web access control list (web ACL) with the specified Amazon Data Firehose (Firehose) delivery stream.'),
    });
  }
  /** @override */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  protected getRemediationParams(): { [_: string]: any } {
    const params = super.getRemediationParams();

    params.LogDestinationConfigs = StringVariable.of('ParseInput.LogDestinationConfigs');
    params.WebAclArn = StringVariable.of('ParseInput.WebAclArn');

    return params;
  }
}