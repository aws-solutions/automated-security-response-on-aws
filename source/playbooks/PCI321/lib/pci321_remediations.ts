// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { IControl } from '../../../lib/sharrplaybook-construct';
import { compareVersions } from 'compare-versions';

// Creates one rule per control Id. The Step Function determines what document to run based on
// Security Standard and Control Id. See cis-member-stack
const remediations: IControl[] = [
  { control: 'PCI.AutoScaling.1', versionAdded: '2.1.0' },
  { control: 'PCI.IAM.7', versionAdded: '2.1.0' },
  { control: 'PCI.CloudTrail.2', versionAdded: '2.1.0' },
  { control: 'PCI.CodeBuild.2', versionAdded: '2.1.0' },
  { control: 'PCI.CW.1', versionAdded: '2.1.0' },
  { control: 'PCI.EC2.1', versionAdded: '2.1.0' },
  { control: 'PCI.EC2.2', versionAdded: '2.1.0' },
  { control: 'PCI.GuardDuty.1', versionAdded: '2.1.0' },
  { control: 'PCI.IAM.8', versionAdded: '2.1.0' },
  { control: 'PCI.KMS.1', versionAdded: '2.1.0' },
  { control: 'PCI.Lambda.1', versionAdded: '2.1.0' },
  { control: 'PCI.RDS.1', versionAdded: '2.1.0' },
  { control: 'PCI.RDS.2', versionAdded: '2.1.0' },
  { control: 'PCI.Redshift.1', versionAdded: '2.1.0' },
  { control: 'PCI.CloudTrail.1', versionAdded: '2.1.0' },
  { control: 'PCI.EC2.6', versionAdded: '2.1.0' },
  { control: 'PCI.CloudTrail.3', versionAdded: '2.1.0' },
  { control: 'PCI.CloudTrail.4', versionAdded: '2.1.0' },
  { control: 'PCI.Config.1', versionAdded: '2.1.0' },
  { control: 'PCI.S3.1', versionAdded: '2.1.0' },
  {
    control: 'PCI.S3.2',
    executes: 'PCI.S3.1',
    versionAdded: '2.1.0',
  },
  { control: 'PCI.S3.4', versionAdded: '2.1.0' },
  { control: 'PCI.S3.5', versionAdded: '2.1.0' },
  { control: 'PCI.S3.6', versionAdded: '2.1.0' },
  { control: 'PCI.EC2.5', versionAdded: '2.1.0' },
  { control: 'PCI.SSM.3', versionAdded: '2.2.0' },
];
export const PCI321_REMEDIATIONS = [...remediations].sort((controlA, controlB) =>
  compareVersions(controlA.versionAdded, controlB.versionAdded),
);
