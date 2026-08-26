// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import React from 'react';
import { Alert, Box, Button, SpaceBetween } from '@cloudscape-design/components';

interface UnsavedChangesBarProps {
  changedCount: number;
  onSave: () => void;
  onDiscard: () => void;
  isSaving: boolean;
}

export const UnsavedChangesBar = ({
  changedCount,
  onSave,
  onDiscard,
  isSaving,
}: UnsavedChangesBarProps): React.ReactElement => (
  <Alert
    type="warning"
    action={
      <SpaceBetween direction="horizontal" size="xs">
        <Button onClick={onDiscard} disabled={isSaving}>
          Discard
        </Button>
        <Button variant="primary" onClick={onSave} loading={isSaving}>
          Save changes
        </Button>
      </SpaceBetween>
    }
  >
    <Box>
      You have unsaved changes to{' '}
      <strong>
        {changedCount} {changedCount === 1 ? 'control' : 'controls'}
      </strong>
      {'.'}
    </Box>
  </Alert>
);
