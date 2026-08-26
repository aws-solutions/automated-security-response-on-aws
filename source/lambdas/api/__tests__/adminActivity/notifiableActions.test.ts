// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { DeliveryChannelTypeSchema } from '@asr/data-models';
import { AdminActivityAction } from '../../services/adminActivityNotifier';
import { ACTION_SEVERITY, DESTINATION_FIELDS_BY_CHANNEL_TYPE } from '../../adminActivity/notifiableActions';

describe('notifiableActions', () => {
  it('grades every action and maps destination fields for every channel type', () => {
    // ARRANGE
    const allActions: AdminActivityAction[] = [
      'CHANNEL_CREATED',
      'CHANNEL_DESTINATION_CHANGED',
      'CHANNEL_UPDATED',
      'CHANNEL_DELETED',
      'CHANNEL_TOGGLED',
      'CONTROL_REMEDIATION_SET',
      'CONTROL_REMEDIATION_ENABLED',
      'BULK_FILTER_CHANGE',
    ];
    const allChannelTypes = DeliveryChannelTypeSchema.options;

    // ACT
    const gradedActions = Object.keys(ACTION_SEVERITY);
    const mappedChannelTypes = Object.keys(DESTINATION_FIELDS_BY_CHANNEL_TYPE);

    // ASSERT
    // Every action is graded exactly once, with no missing or extra keys
    expect(new Set(gradedActions)).toEqual(new Set(allActions));
    expect(Object.values(ACTION_SEVERITY).every((severity) => severity === 'high' || severity === 'medium')).toBe(true);

    // Every channel type maps to a non-empty destination field list
    expect(new Set(mappedChannelTypes)).toEqual(new Set(allChannelTypes));
    expect(Object.values(DESTINATION_FIELDS_BY_CHANNEL_TYPE).every((fields) => fields.length > 0)).toBe(true);

    // The security-critical actions are graded high
    expect(ACTION_SEVERITY.CONTROL_REMEDIATION_SET).toBe('high');
    expect(ACTION_SEVERITY.CHANNEL_DESTINATION_CHANGED).toBe('high');
    expect(ACTION_SEVERITY.BULK_FILTER_CHANGE).toBe('high');
  });
});
