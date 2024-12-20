// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

export interface PlaybookProps {
  name: string;
  useAppRegistry: boolean;
  defaultParameterValue?: 'yes' | 'no';
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
  },
  {
    name: 'CIS120',
    useAppRegistry: true,
    defaultParameterValue: 'no',
  },
  {
    name: 'CIS140',
    useAppRegistry: true,
    defaultParameterValue: 'no',
  },
  {
    name: 'NIST80053',
    useAppRegistry: true,
    defaultParameterValue: 'no',
  },
  {
    name: 'PCI321',
    useAppRegistry: false,
    defaultParameterValue: 'no',
  },
];

export const scPlaybookProps: PlaybookProps = {
  name: 'SC',
  useAppRegistry: false,
  defaultParameterValue: 'yes',
  description:
    'If the consolidated control findings feature is turned on in Security Hub, only enable the Security Control (SC) playbook. If the feature is not turned on, enable the playbooks for the security standards that are enabled in Security Hub. Enabling additional playbooks can result in reaching the quota for EventBridge Rules.',
};
