// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new ConfigureLaunchConfigNoPublicIPDocument(scope, id, { ...props, controlId: 'Autoscaling.5' });
}

export class ConfigureLaunchConfigNoPublicIPDocument extends ControlRunbookDocument {
  constructor(stage: Construct, id: string, props: ControlRunbookProps) {
    super(stage, id, {
      ...props,
      securityControlId: 'Autoscaling.5',
      remediationName: 'ConfigureAutoScalingLaunchConfigNoPublicIP',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'LaunchConfigurationName',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):autoscaling:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:launchConfiguration:(?:[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}):launchConfigurationName/(.{1,255})$`,
      updateDescription: HardCodedString.of(
        'AutoScaling Group Launch Configuration updated to not assign a public IP address',
      ),
    });
  }
}
