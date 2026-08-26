// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import Badge from '@cloudscape-design/components/badge';
import Popover from '@cloudscape-design/components/popover';
import Box from '@cloudscape-design/components/box';

interface ReadOnlyBadgeProps {
  visible: boolean;
}

export const ReadOnlyBadge = ({ visible }: ReadOnlyBadgeProps): React.ReactElement | null => {
  if (!visible) return null;

  return (
    <Popover
      dismissButton={false}
      position="bottom"
      size="small"
      triggerType="custom"
      content={<Box padding="s">You have read-only access. Contact an administrator to request edit permissions.</Box>}
    >
      <Badge color="grey">Read-only</Badge>
    </Popover>
  );
};
