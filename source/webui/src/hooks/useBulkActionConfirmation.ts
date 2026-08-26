// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { useCallback, useState } from 'react';

import { BulkFilterOperation } from '@data-models';

export interface BulkActionState<T> {
  item: T;
  operation: BulkFilterOperation;
}

interface UseBulkActionConfirmationResult<T> {
  bulkAction: BulkActionState<T> | null;
  openApplyToAll: (item: T) => void;
  openRemoveFromAll: (item: T) => void;
  closeBulkAction: () => void;
}

export function useBulkActionConfirmation<T>(): UseBulkActionConfirmationResult<T> {
  const [bulkAction, setBulkAction] = useState<BulkActionState<T> | null>(null);

  const openApplyToAll = useCallback((item: T) => {
    setBulkAction({ item, operation: 'applyFilterToAll' });
  }, []);

  const openRemoveFromAll = useCallback((item: T) => {
    setBulkAction({ item, operation: 'removeFilterFromAll' });
  }, []);

  const closeBulkAction = useCallback(() => {
    setBulkAction(null);
  }, []);

  return { bulkAction, openApplyToAll, openRemoveFromAll, closeBulkAction };
}
