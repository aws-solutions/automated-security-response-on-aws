// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Construct } from 'constructs';
import { ControlRunbookDocument, ControlRunbookProps, RemediationScope } from './control_runbook';
import { PlaybookProps } from '../lib/control_runbooks-construct';
import { HardCodedString } from '@cdklabs/cdk-ssm-documents';

export function createControlRunbook(scope: Construct, id: string, props: PlaybookProps): ControlRunbookDocument {
  return new ConfigureLaunchConfigToRequireIMDSv2Document(scope, id, { ...props, controlId: 'AutoScaling.3' });
}

export class ConfigureLaunchConfigToRequireIMDSv2Document extends ControlRunbookDocument {
  constructor(stage: Construct, id: string, props: ControlRunbookProps) {
    super(stage, id, {
      ...props,
      securityControlId: 'AutoScaling.3',
      remediationName: 'ConfigureAutoScalingLaunchConfigToRequireIMDSv2',
      scope: RemediationScope.REGIONAL,
      resourceIdName: 'LaunchConfigurationName',
      resourceIdRegex: String.raw`^arn:(?:aws|aws-cn|aws-us-gov):autoscaling:(?:[a-z]{2}(?:-gov)?-[a-z]+-\d):\d{12}:launchConfiguration:(?:[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}):launchConfigurationName/(.{1,255})$`,
      updateDescription: HardCodedString.of('AutoScaling Group Launch Configuration updated to require IMDSv2'),
    });
  }
}
