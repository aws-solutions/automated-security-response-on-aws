// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new DropInvalidHeadersForALBDocument(scope, id, { ...props, controlId: 'ELB.4' });
}

/*
ssm:StartAutomationExecution
ssm:GetAutomationExecution
elasticloadbalancing:DescribeLoadBalancerAttributes
elasticloadbalancing:ModifyLoadBalancerAttributes
*/

export class DropInvalidHeadersForALBDocument extends ControlRunbookDocument {
  constructor(stage: Construct, id: string, props: ControlRunbookProps) {
    super(stage, id, {
      ...props,
      securityControlId: 'ELB.4',
      remediationName: 'DropInvalidHeadersForALB',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'LoadBalancerArn',
      resourceIdRegex: String.raw`^arn:(aws[a-zA-Z-]*)?:elasticloadbalancing:[a-z]{2}-[a-z]+-[0-9]{1}:[0-9]{12}:loadbalancer\/app\/((?!internal-)(?!-)[0-9a-zA-Z-]{1,32}(?<!-))\/[0-9aA-zZ]{16}$`,
      updateDescription: HardCodedString.of('This document will enable the drop invalid headers setting for the load balancer you specify in the `LoadBalancerArn` parameter.'),
    });
  }
}