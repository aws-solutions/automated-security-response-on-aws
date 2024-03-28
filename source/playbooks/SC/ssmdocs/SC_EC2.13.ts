// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import {
  AutomationStep,
  ExecuteAutomationStep,
  HardCodedString,
  HardCodedStringMap,
  StringFormat,
  StringVariable,
} from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new DisablePublicAccessForSecurityGroupDocument(scope, id, {
    ...props,
    controlId: 'EC2.13',
    otherControlIds: ['EC2.14'],
  });
}

export class DisablePublicAccessForSecurityGroupDocument extends ControlRunbookDocument {
  constructor(scope: Construct, id: string, props: ControlRunbookProps) {
    const resourceIdName = 'GroupId';

    super(scope, id, {
      ...props,
      securityControlId: 'EC2.13',
      remediationName: 'DisablePublicAccessForSecurityGroup',
      scope: RemediationScope.REGIONAL,
      resourceIdName,
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):ec2:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:security-group\/(sg-[a-f\d]{8,17})$`,
      updateDescription: new StringFormat('Disabled public access to administrative ports in the security group %s.', [
        StringVariable.of(`ParseInput.${resourceIdName}`),
      ]),
    });
  }

  /** @override */
  protected getRemediationStep(): AutomationStep {
    return new ExecuteAutomationStep(this, 'Remediation', {
      documentName: HardCodedString.of(`AWS-${this.remediationName}`),
      runtimeParameters: HardCodedStringMap.of(this.getRemediationParams()),
    });
  }
}
