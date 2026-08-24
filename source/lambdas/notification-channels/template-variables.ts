// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { NotificationType } from '@asr/data-models';

export interface TemplateVariableContext {
  readonly findingId: string;
  readonly controlId: string;
  readonly severity: string;
  readonly accountId: string;
  readonly region: string;
  readonly resourceArn: string;
  readonly configName: string;
}

export type TemplateVariable =
  | 'FINDING_ID'
  | 'CONTROL_ID'
  | 'SEVERITY'
  | 'ACCOUNT_ID'
  | 'REGION'
  | 'RESOURCE_ARN'
  | 'CONFIG_NAME';

export const VARIABLE_MAP: Record<TemplateVariable, keyof TemplateVariableContext> = {
  FINDING_ID: 'findingId',
  CONTROL_ID: 'controlId',
  SEVERITY: 'severity',
  ACCOUNT_ID: 'accountId',
  REGION: 'region',
  RESOURCE_ARN: 'resourceArn',
  CONFIG_NAME: 'configName',
};

/** Matches `${VARIABLE_NAME}` placeholders, capturing the name between braces. */
export const TEMPLATE_VARIABLE_PATTERN = /\$\{([^}]+)\}/g;

function isTemplateVariable(varName: string): varName is TemplateVariable {
  return varName in VARIABLE_MAP;
}

/**
 * Resolves `${VARIABLE}` placeholders against the context. An optional
 * `encodeValue` is applied to each substituted value only (never to literal
 * template text or unresolved placeholders), so callers can sanitize
 * finding-sourced data for a specific target system without affecting the
 * surrounding template.
 */
export function resolveTemplateVariables(
  value: string,
  context: TemplateVariableContext,
  encodeValue: (substituted: string) => string = (substituted) => substituted,
): string {
  return value.replaceAll(TEMPLATE_VARIABLE_PATTERN, (match, varName: string) => {
    if (isTemplateVariable(varName)) {
      return encodeValue(context[VARIABLE_MAP[varName]]);
    }
    return match;
  });
}

export interface BatchTemplateVariableContext {
  readonly configName: string;
  readonly notificationType: NotificationType;
  readonly findingCount: string;
  readonly remediationCount: string;
}

// CONFIG_NAME is intentionally shared with the single-event TemplateVariable type.
// Both resolve ${CONFIG_NAME} but in different contexts: single-event notifications
// use resolveTemplateVariables, batch notifications use resolveBatchTemplateVariables.
export type BatchTemplateVariable = 'CONFIG_NAME' | 'NOTIFICATION_TYPE' | 'FINDING_COUNT' | 'REMEDIATION_COUNT';

export const BATCH_VARIABLE_MAP: Record<BatchTemplateVariable, keyof BatchTemplateVariableContext> = {
  CONFIG_NAME: 'configName',
  NOTIFICATION_TYPE: 'notificationType',
  FINDING_COUNT: 'findingCount',
  REMEDIATION_COUNT: 'remediationCount',
};

function isBatchTemplateVariable(varName: string): varName is BatchTemplateVariable {
  return varName in BATCH_VARIABLE_MAP;
}

export function resolveBatchTemplateVariables(
  value: string,
  context: BatchTemplateVariableContext,
  encodeValue: (substituted: string) => string = (substituted) => substituted,
): string {
  return value.replace(TEMPLATE_VARIABLE_PATTERN, (match, varName: string) => {
    if (isBatchTemplateVariable(varName)) {
      return encodeValue(context[BATCH_VARIABLE_MAP[varName]]);
    }
    return match;
  });
}
