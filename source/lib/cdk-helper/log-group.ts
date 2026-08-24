// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { LogGroup, LogGroupProps, RetentionDays } from 'aws-cdk-lib/aws-logs';
import { Construct } from 'constructs';
import { addCfnGuardSuppression } from './add-cfn-guard-suppression';

// Compliant retention for every log group the solution creates. 10 years is the
// ceiling allowed without service-legal approval and clears the >=36 month floor
// for payment-adjacent services, so it satisfies retention policy either way.
// Without this, Lambda log groups default to never-expire.
export const ASR_LOG_RETENTION = RetentionDays.TEN_YEARS;

// Creates a log group at the compliant retention. Pass this to a Lambda's
// `logGroup` prop so the function logs to it instead of auto-creating an
// unbounded /aws/lambda/<name> group. The generated name is distinct from that
// default, so wiring this into an existing function orphans the old group rather
// than colliding with it on update.
export function createLogGroup(scope: Construct, id: string, props: Omit<LogGroupProps, 'retention'> = {}): LogGroup {
  const logGroup = new LogGroup(scope, id, { retention: ASR_LOG_RETENTION, ...props });
  // The solution's Lambda log groups use CloudWatch default (service-managed)
  // encryption rather than a CMK, consistent with the WebUI API log group.
  addCfnGuardSuppression(logGroup, 'CLOUDWATCH_LOG_GROUP_ENCRYPTED');
  return logGroup;
}
