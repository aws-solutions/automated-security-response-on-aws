// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { IControl } from '../../../lib/sharrplaybook-construct';
import { compareVersions } from 'compare-versions';

// Creates one rule per control Id. The Step Function determines what document to run based on
// Security Standard and Control Id. See cis-member-stack
// versionAdded is set to 2.1.0 for all remediations added up to that release
const remediations: IControl[] = [
  { control: '1.3', versionAdded: '2.1.0' },
  { control: '1.4', versionAdded: '2.1.0' },
  { control: '1.5', versionAdded: '2.1.0' },
  {
    control: '1.6',
    executes: '1.5',
    versionAdded: '2.1.0',
  },
  {
    control: '1.7',
    executes: '1.5',
    versionAdded: '2.1.0',
  },
  {
    control: '1.8',
    executes: '1.5',
    versionAdded: '2.1.0',
  },
  {
    control: '1.9',
    executes: '1.5',
    versionAdded: '2.1.0',
  },
  {
    control: '1.10',
    executes: '1.5',
    versionAdded: '2.1.0',
  },
  {
    control: '1.11',
    executes: '1.5',
    versionAdded: '2.1.0',
  },
  { control: '1.20', versionAdded: '2.1.0' },
  { control: '2.1', versionAdded: '2.1.0' },
  { control: '2.2', versionAdded: '2.1.0' },
  { control: '2.3', versionAdded: '2.1.0' },
  { control: '2.4', versionAdded: '2.1.0' },
  { control: '2.5', versionAdded: '2.1.0' },
  { control: '2.6', versionAdded: '2.1.0' },
  { control: '2.7', versionAdded: '2.1.0' },
  { control: '2.8', versionAdded: '2.1.0' },
  { control: '2.9', versionAdded: '2.1.0' },
  { control: '3.1', versionAdded: '2.1.0' },
  {
    control: '3.2',
    executes: '3.1',
    versionAdded: '2.1.0',
  },
  {
    control: '3.3',
    executes: '3.1',
    versionAdded: '2.1.0',
  },
  {
    control: '3.4',
    executes: '3.1',
    versionAdded: '2.1.0',
  },
  {
    control: '3.5',
    executes: '3.1',
    versionAdded: '2.1.0',
  },
  {
    control: '3.6',
    executes: '3.1',
    versionAdded: '2.1.0',
  },
  {
    control: '3.7',
    executes: '3.1',
    versionAdded: '2.1.0',
  },
  {
    control: '3.8',
    executes: '3.1',
    versionAdded: '2.1.0',
  },
  {
    control: '3.9',
    executes: '3.1',
    versionAdded: '2.1.0',
  },
  {
    control: '3.10',
    executes: '3.1',
    versionAdded: '2.1.0',
  },
  {
    control: '3.11',
    executes: '3.1',
    versionAdded: '2.1.0',
  },
  {
    control: '3.12',
    executes: '3.1',
    versionAdded: '2.1.0',
  },
  {
    control: '3.13',
    executes: '3.1',
    versionAdded: '2.1.0',
  },
  {
    control: '3.14',
    executes: '3.1',
    versionAdded: '2.1.0',
  },
  { control: '4.1', versionAdded: '2.1.0' },
  {
    control: '4.2',
    executes: '4.1',
    versionAdded: '2.1.0',
  },
  { control: '4.3', versionAdded: '2.1.0' },
];
export const CIS120_REMEDIATIONS = [...remediations].sort((controlA, controlB) =>
  compareVersions(controlA.versionAdded, controlB.versionAdded),
);
