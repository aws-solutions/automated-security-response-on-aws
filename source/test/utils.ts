// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { Template } from 'aws-cdk-lib/assertions';

/**
 * Omits the  hash from the template snapshot for testing
 */
export function omitWaitResourceHash(template: Template, templateJSON: { [p: string]: any }) {
  const waitResources = template.findResources('Custom::Wait');

  for (const waitResource in waitResources) {
    templateJSON['Resources'][waitResource]['Properties']['DocumentPropertiesHash'] =
      'Omitted to remove snapshot dependency on document hash';
  }
}
