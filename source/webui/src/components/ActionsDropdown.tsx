// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { ButtonDropdown } from '@cloudscape-design/components';
import { FindingApiResponse } from '@data-models';
import { useConfig } from '../contexts/ConfigContext';

interface ActionsDropdownProps {
  selectedItems: readonly FindingApiResponse[];
  onRemediate: (items: readonly FindingApiResponse[]) => void;
  onRemediateAndGenerateTicket: (items: readonly FindingApiResponse[]) => void;
  onSuppress: (items: readonly FindingApiResponse[]) => void;
  onUnsuppress: (items: readonly FindingApiResponse[]) => void;
}

export const ActionsDropdown = ({
  selectedItems,
  onRemediate,
  onRemediateAndGenerateTicket,
  onSuppress,
  onUnsuppress
}: ActionsDropdownProps) => {
  const { ticketingEnabled } = useConfig();
  const isDisabled = selectedItems.length === 0;
  const hasSuppressedItems = selectedItems.some(item => item.suppressed);
  const hasUnsuppressedItems = selectedItems.some(item => !item.suppressed);
  const hasInProgressOrSuccessItems = selectedItems.some(item => 
    item.remediationStatus === 'IN_PROGRESS' || item.remediationStatus === 'SUCCESS'
  );

  const dropdownItems = [
    {
      id: 'remediate',
      text: 'Remediate',
      disabled: isDisabled || hasInProgressOrSuccessItems
    },
    {
      id: 'remediate-ticket',
      text: 'Remediate & Generate Ticket',
      disabled: isDisabled || hasInProgressOrSuccessItems || !ticketingEnabled
    },
    {
      id: 'suppress',
      text: 'Suppress',
      disabled: isDisabled || !hasUnsuppressedItems || hasInProgressOrSuccessItems
    },
    {
      id: 'unsuppress',
      text: 'Unsuppress',
      disabled: isDisabled || !hasSuppressedItems || hasInProgressOrSuccessItems
    }
  ];

  const handleItemClick = ({ detail }: { detail: { id: string } }) => {
    switch (detail.id) {
      case 'remediate':
        onRemediate(selectedItems);
        break;
      case 'remediate-ticket':
        onRemediateAndGenerateTicket(selectedItems);
        break;
      case 'suppress':
        onSuppress(selectedItems);
        break;
      case 'unsuppress':
        onUnsuppress(selectedItems);
        break;
    }
  };

  return (
    <div>
      <ButtonDropdown
        items={dropdownItems}
        onItemClick={handleItemClick}
        variant={isDisabled ? "normal" : "primary"}
        disabled={isDisabled}
      >
        Actions
      </ButtonDropdown>
    </div>
  );
};
