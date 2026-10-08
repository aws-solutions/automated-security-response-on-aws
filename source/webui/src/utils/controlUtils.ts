// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Derive the control id from a finding's findingType. Security Hub control
 * findingTypes are prefixed (e.g. "security-control/KMS.4"); the control id is
 * the segment after the last "/". A findingType with no "/" is already a bare
 * control id and is returned unchanged.
 */
export const extractControlId = (findingType: string): string =>
  findingType.includes('/') ? findingType.slice(findingType.lastIndexOf('/') + 1) : findingType;
