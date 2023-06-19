// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Tags } from 'aws-cdk-lib';
import { IConstruct } from 'constructs';

/**
 * @description applies tag to cloudformation resources
 * @param resource
 * @param key
 * @param value
 */
export function applyTag(resource: IConstruct, key: string, value: string) {
  Tags.of(resource).add(key, value);
}
