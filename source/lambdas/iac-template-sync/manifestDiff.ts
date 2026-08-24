// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { DiffResult, Manifest, TemplateEntry } from './types';

/**
 * Compares an existing manifest against an incoming manifest and categorizes
 * every template entry into one of four groups: added, updated, unchanged,
 * or deprecated. The four categories partition all unique s3Keys from both
 * manifests without overlap or omission.
 */
export function diffManifests(existing: Manifest, incoming: Manifest): DiffResult {
  const existingByKey = new Map<string, TemplateEntry>();
  for (const entry of existing.templates) {
    existingByKey.set(entry.s3Key, entry);
  }

  const incomingByKey = new Map<string, TemplateEntry>();
  for (const entry of incoming.templates) {
    incomingByKey.set(entry.s3Key, entry);
  }

  const added: TemplateEntry[] = [];
  const updated: TemplateEntry[] = [];
  const unchanged: TemplateEntry[] = [];
  const deprecated: TemplateEntry[] = [];

  for (const [s3Key, incomingEntry] of incomingByKey) {
    const existingEntry = existingByKey.get(s3Key);
    if (!existingEntry) {
      added.push(incomingEntry);
    } else if (existingEntry.sha256 === incomingEntry.sha256) {
      unchanged.push(incomingEntry);
    } else {
      updated.push(incomingEntry);
    }
  }

  for (const [s3Key, existingEntry] of existingByKey) {
    if (!incomingByKey.has(s3Key)) {
      deprecated.push(existingEntry);
    }
  }

  return { added, updated, unchanged, deprecated };
}
