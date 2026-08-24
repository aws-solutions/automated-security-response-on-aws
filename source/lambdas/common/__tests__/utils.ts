// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { ConfigId, FindingId, ResolvedFindingType } from '@asr/data-models';

/** Cast a string to FindingId for use in tests */
export const asFindingId = (id: string): FindingId => id as FindingId;

/** Cast a string to ConfigId for use in tests */
export const asConfigId = (id: string): ConfigId => id as ConfigId;

/** Cast a string to ResolvedFindingType for use in tests. Production code must obtain the value
 * from `resolveFindingType` or `resolveControlId`, which are the only places that brand it. */
export const asResolvedFindingType = (findingType: string): ResolvedFindingType => findingType as ResolvedFindingType;
