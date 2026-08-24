// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { DeliveryChannelConfig, DeliveryChannelType, NotificationConfigurationItem } from '@asr/data-models';
import { DESTINATION_FIELDS_BY_CHANNEL_TYPE } from './notifiableActions';

export interface ChannelChange {
  readonly action: 'CHANNEL_DESTINATION_CHANGED' | 'CHANNEL_UPDATED';
  readonly changedFields: string[];
}

/** The subset of a notification configuration the channel diff depends on. */
type ChannelConfigInput = Pick<NotificationConfigurationItem, 'deliveryChannels'>;

/**
 * Classifies a notification configuration update as a destination change or a benign update by
 * diffing the delivery channels' destination fields (the fields that determine where finding data
 * is delivered, per channel type). Adding or removing a channel type, or changing any destination
 * field, is a destination change. Field values are compared structurally so array/object fields
 * (e.g. email recipients) are handled correctly. No raw credentials are inspected — only the
 * `credentialsSecretArn` reference, which is safe to surface.
 */
export function computeChannelChange(oldConfig: ChannelConfigInput, newConfig: ChannelConfigInput): ChannelChange {
  const changedFields = diffDestinationFields(oldConfig.deliveryChannels, newConfig.deliveryChannels);
  return {
    action: changedFields.length > 0 ? 'CHANNEL_DESTINATION_CHANGED' : 'CHANNEL_UPDATED',
    changedFields,
  };
}

function diffDestinationFields(
  oldChannels: readonly DeliveryChannelConfig[],
  newChannels: readonly DeliveryChannelConfig[],
): string[] {
  const changed: string[] = [];
  const oldByType = indexByType(oldChannels);
  const newByType = indexByType(newChannels);
  const types = new Set<string>([...oldByType.keys(), ...newByType.keys()]);

  for (const type of types) {
    const oldChannel = oldByType.get(type);
    const newChannel = newByType.get(type);

    // A channel type added or removed entirely is a destination change.
    if (!oldChannel || !newChannel) {
      changed.push(type);
      continue;
    }

    const fields = DESTINATION_FIELDS_BY_CHANNEL_TYPE[type as DeliveryChannelType] ?? [];
    for (const field of fields) {
      if (!valuesEqual(getField(oldChannel, field), getField(newChannel, field))) {
        changed.push(`${type}.${field}`);
      }
    }
  }

  return changed;
}

function indexByType(channels: readonly DeliveryChannelConfig[]): Map<string, DeliveryChannelConfig> {
  return new Map(channels.map((channel) => [channel.type, channel]));
}

// DeliveryChannelConfig is a discriminated union with no index signature, so data-driven access by
// a field name drawn from DESTINATION_FIELDS_BY_CHANNEL_TYPE requires a structural cast (last
// resort per ADR 0001). Only known destination field names for the channel type are ever passed.
function getField(channel: DeliveryChannelConfig, field: string): unknown {
  return (channel as Record<string, unknown>)[field];
}

function valuesEqual(first: unknown, second: unknown): boolean {
  return JSON.stringify(first ?? null) === JSON.stringify(second ?? null);
}
