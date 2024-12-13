// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { IControl } from '../../../lib/sharrplaybook-construct';
import { compareVersions } from 'compare-versions';

// Creates one rule per control Id. The Step Function determines what document to run based on
// Security Standard and Control Id.
const remediations: IControl[] = [
  { control: '3.1', versionAdded: '2.2.0' },
  { control: '3.5', versionAdded: '2.2.0' },
  { control: '3.2', versionAdded: '2.2.0' },
  { control: '3.4', versionAdded: '2.2.0' },
  { control: '3.3', versionAdded: '2.2.0' },
  { control: '5.4', versionAdded: '2.2.0' },
  { control: '3.7', versionAdded: '2.2.0' },
  { control: '2.2.1', versionAdded: '2.2.0' },
  { control: '5.6', versionAdded: '2.2.0' },
  { control: '1.14', versionAdded: '2.2.0' },
  { control: '1.8', versionAdded: '2.2.0' },
  { control: '1.9', executes: '1.8', versionAdded: '2.2.0' },
  { control: '1.17', versionAdded: '2.2.0' },
  { control: '1.12', versionAdded: '2.2.0' },
  { control: '3.6', versionAdded: '2.2.0' },
  { control: '2.3.3', versionAdded: '2.2.0' },
  { control: '2.3.2', versionAdded: '2.2.0' },
  { control: '2.1.4', versionAdded: '2.2.0' },
  { control: '2.1.1', versionAdded: '2.2.0' },
];
export const CIS300_remediations = [...remediations].sort((controlA, controlB) =>
  compareVersions(controlA.versionAdded, controlB.versionAdded),
);
