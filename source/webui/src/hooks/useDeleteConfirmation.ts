// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { useCallback, useState } from 'react';

/**
 * Manages delete-confirmation modal state.
 *
 * @returns The item pending deletion and open/cancel callback functions.
 */
export function useDeleteConfirmation<T>() {
  const [deletingItem, setDeletingItem] = useState<T | null>(null);

  const openDeleteConfirmation = useCallback((item: T) => {
    setDeletingItem(item);
  }, []);

  const cancelDelete = useCallback(() => {
    setDeletingItem(null);
  }, []);

  const clearDeletingItem = useCallback(() => {
    setDeletingItem(null);
  }, []);

  return { deletingItem, openDeleteConfirmation, cancelDelete, clearDeletingItem };
}
