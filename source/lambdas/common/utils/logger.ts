// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Logger } from '@aws-lambda-powertools/logger';

export function getLogger(serviceName: string) {
  return new Logger({ serviceName });
}
