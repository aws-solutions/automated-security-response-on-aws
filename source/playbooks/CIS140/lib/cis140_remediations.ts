// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { IControl } from '../../../lib/sharrplaybook-construct';
import { compareVersions } from 'compare-versions';

// Creates one rule per control Id. The Step Function determines what document to run based on
// Security Standard and Control Id. See cis-member-stack
// versionAdded is set to 2.1.0 for all remediations added up to that release
const remediations: IControl[] = [
  { control: '1.8', versionAdded: '2.1.0' },
  { control: '1.9', executes: '1.8', versionAdded: '2.1.0' },
  { control: '1.12', versionAdded: '2.1.0' },
  { control: '1.14', versionAdded: '2.1.0' },
  { control: '1.17', versionAdded: '2.1.0' },
  { control: '2.1.1', versionAdded: '2.1.0' },
  { control: '2.1.2', versionAdded: '2.1.0' },
  { control: '2.1.5.1', versionAdded: '2.1.0' }, //NOSONAR This is not an IP Address.
  { control: '2.1.5.2', versionAdded: '2.1.0' }, //NOSONAR This is not an IP Address.
  { control: '2.2.1', versionAdded: '2.1.0' },
  { control: '3.1', versionAdded: '2.1.0' },
  { control: '3.2', versionAdded: '2.1.0' },
  { control: '3.3', versionAdded: '2.1.0' },
  { control: '3.4', versionAdded: '2.1.0' },
  { control: '3.5', versionAdded: '2.1.0' },
  { control: '3.6', versionAdded: '2.1.0' },
  { control: '3.7', versionAdded: '2.1.0' },
  { control: '3.8', versionAdded: '2.1.0' },
  { control: '3.9', versionAdded: '2.1.0' },
  { control: '4.1', versionAdded: '2.1.0' },
  { control: '4.2', executes: '4.1', versionAdded: '2.1.0' },
  { control: '4.3', executes: '4.1', versionAdded: '2.1.0' },
  { control: '4.4', executes: '4.1', versionAdded: '2.1.0' },
  { control: '4.5', executes: '4.1', versionAdded: '2.1.0' },
  { control: '4.6', executes: '4.1', versionAdded: '2.1.0' },
  { control: '4.7', executes: '4.1', versionAdded: '2.1.0' },
  { control: '4.8', executes: '4.1', versionAdded: '2.1.0' },
  { control: '4.9', executes: '4.1', versionAdded: '2.1.0' },
  { control: '4.10', executes: '4.1', versionAdded: '2.1.0' },
  { control: '4.11', executes: '4.1', versionAdded: '2.1.0' },
  { control: '4.12', executes: '4.1', versionAdded: '2.1.0' },
  { control: '4.13', executes: '4.1', versionAdded: '2.1.0' },
  { control: '4.14', executes: '4.1', versionAdded: '2.1.0' },
  { control: '5.3', versionAdded: '2.1.0' },
];
export const CIS140_REMEDIATIONS = [...remediations].sort((controlA, controlB) =>
  compareVersions(controlA.versionAdded, controlB.versionAdded),
);
