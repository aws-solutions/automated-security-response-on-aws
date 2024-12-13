// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { AFSBP_REMEDIATIONS } from './AFSBP/lib/afsbp_remediations';
import { CIS120_REMEDIATIONS } from './CIS120/lib/cis120_remediations';
import { CIS140_REMEDIATIONS } from './CIS140/lib/cis140_remediations';
import { NIST80053_REMEDIATIONS } from './NIST80053/lib/nist80053_remediations';
import { PCI321_REMEDIATIONS } from './PCI321/lib/pci321_remediations';
import { SC_REMEDIATIONS } from './SC/lib/sc_remediations';
import { CIS300_remediations } from './CIS300/lib/cis300_remediations';

const SC_MEMBER_STACK_LIMIT = Number(process.env['SC_MEMBER_STACK_LIMIT']);
const NIST_MEMBER_STACK_LIMIT = Number(process.env['NIST_MEMBER_STACK_LIMIT']);
const AFSBP_MEMBER_STACK_LIMIT = Number(process.env['AFSBP_MEMBER_STACK_LIMIT']);

export interface PlaybookProps {
  name: string;
  useAppRegistry: boolean;
  totalControls: number;
  defaultParameterValue?: 'yes' | 'no';
  memberStackLimit?: number;
  description?: string;
}

// IMPORTANT, add new standards to the end of the list to prevent App Registry Logical ID shifts
//
// App Registry is intentionally disabled for PCI and SC standards
// Adding the NIST standard in v2.1.0 shifted the App Registry logical IDs for the nested stacks
// Disabling for these two standards prevents update failures
export const standardPlaybookProps: PlaybookProps[] = [
  {
    name: 'AFSBP',
    useAppRegistry: true,
    defaultParameterValue: 'no',
    memberStackLimit: AFSBP_MEMBER_STACK_LIMIT,
    totalControls: AFSBP_REMEDIATIONS.length,
  },
  {
    name: 'CIS120',
    useAppRegistry: true,
    defaultParameterValue: 'no',
    totalControls: CIS120_REMEDIATIONS.length,
  },
  {
    name: 'CIS140',
    useAppRegistry: true,
    defaultParameterValue: 'no',
    totalControls: CIS140_REMEDIATIONS.length,
  },
  {
    name: 'NIST80053',
    useAppRegistry: true,
    defaultParameterValue: 'no',
    memberStackLimit: NIST_MEMBER_STACK_LIMIT,
    totalControls: NIST80053_REMEDIATIONS.length,
  },
  {
    name: 'PCI321',
    useAppRegistry: false,
    defaultParameterValue: 'no',
    totalControls: PCI321_REMEDIATIONS.length,
  },
  {
    name: 'CIS300',
    useAppRegistry: true,
    defaultParameterValue: 'no',
    totalControls: CIS300_remediations.length,
  },
];

export const scPlaybookProps: PlaybookProps = {
  name: 'SC',
  useAppRegistry: false,
  memberStackLimit: SC_MEMBER_STACK_LIMIT,
  totalControls: SC_REMEDIATIONS.length,
  defaultParameterValue: 'yes',
  description:
    'If the consolidated control findings feature is turned on in Security Hub, only enable the Security Control (SC) playbook. If the feature is not turned on, enable the playbooks for the security standards that are enabled in Security Hub. Enabling additional playbooks can result in reaching the quota for EventBridge Rules.',
};
