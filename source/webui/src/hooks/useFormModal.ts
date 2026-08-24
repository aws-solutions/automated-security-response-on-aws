// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { useCallback, useState } from 'react';

/**
 * Manages create/edit form modal state.
 *
 * @returns Form mode, the item being edited, and open/close helpers.
 */
export function useFormModal<T>() {
  const [formMode, setFormMode] = useState<'create' | 'edit' | null>(null);
  const [editingItem, setEditingItem] = useState<T | null>(null);

  const openCreateForm = useCallback(() => {
    setFormMode('create');
    setEditingItem(null);
  }, []);

  const openEditForm = useCallback((item: T) => {
    setFormMode('edit');
    setEditingItem(item);
  }, []);

  const closeForm = useCallback(() => {
    setFormMode(null);
    setEditingItem(null);
  }, []);

  return { formMode, editingItem, openCreateForm, openEditForm, closeForm };
}
