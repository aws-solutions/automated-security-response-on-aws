// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { z } from 'zod';
import { ConfigIdSchema, DeliveryChannelTypeSchema } from './notification';

// --- Test Notification Request ---

export const TestNotificationRequestSchema = z.object({
  channels: z.array(DeliveryChannelTypeSchema).optional(),
});

// --- Channel Test Result ---

export const ChannelTestStatusSchema = z.enum(['success', 'failure']);

export const ChannelTestResultSchema = z.object({
  channelType: DeliveryChannelTypeSchema,
  enabled: z.boolean(),
  status: ChannelTestStatusSchema,
  error: z.string().max(500).optional(),
});

// --- Test Notification Result ---

export const TestNotificationResultSchema = z.object({
  success: z.boolean(),
  configId: ConfigIdSchema,
  configName: z.string().min(1),
  eventId: z.uuid(),
  testedAt: z.iso.datetime(),
  results: z.record(z.string(), ChannelTestResultSchema),
});

// --- Type exports ---

export type TestNotificationRequest = z.infer<typeof TestNotificationRequestSchema>;
export type ChannelTestStatus = z.infer<typeof ChannelTestStatusSchema>;
export type ChannelTestResult = z.infer<typeof ChannelTestResultSchema>;
export type TestNotificationResult = z.infer<typeof TestNotificationResultSchema>;
