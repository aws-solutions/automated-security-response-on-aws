// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { add, sub } from 'date-fns';
import {
  FindingApiResponse,
  FindingId,
  RemediationHistoryApiResponse,
  ROLLBACK_ELIGIBLE_FINDING_TYPE,
  User,
} from '@data-models';
import {
  randomAccountId,
  randomAlias,
  randomRemediationStatus,
  randomSeverity,
  randomWord,
} from './test-data-random-utils';

export const mockCurrentUser: User = {
  email: 'current@example.com',
  invitedBy: 'admin@example.com',
  invitationTimestamp: new Date().toISOString(),
  status: 'Confirmed',
  type: 'admin',
};

export const mockUserContext = {
  user: { username: 'testuser' } as any,
  email: 'current@example.com',
  groups: ['AdminGroup'],
  signOut: () => Promise.resolve(),
  checkUser: () => Promise.resolve(),
  signInWithRedirect: () => Promise.resolve(),
};

/** Cast a string to FindingId for use in tests */
export const asFindingId = (id: string): FindingId => id as FindingId;

// Functions to generate random test data for unit test and early stage UI development
export function generateTestRemediation(data?: Partial<RemediationHistoryApiResponse>): RemediationHistoryApiResponse {
  const id = asFindingId(window.crypto.randomUUID());
  const remediationStatus = data?.remediationStatus ?? randomRemediationStatus();
  const findingType = data?.findingType ?? randomWord(10, 15);
  return {
    executionId: id,
    findingId: id,
    lastUpdatedTime: sub(new Date(), {
      hours: Math.random() * 100,
      minutes: Math.random() * 60,
    }).toISOString(),
    accountId: randomAccountId(),
    remediationStatus,
    region: randomWord(5, 10),
    resourceId: randomWord(30, 40),
    resourceType: randomWord(10, 15),
    resourceTypeNormalized: randomWord(10, 15),
    findingType,
    lastUpdatedBy: randomAlias(),
    severity: randomSeverity(),
    consoleLink: `https://console.aws.amazon.com/states/home?region=${randomWord(5, 10)}#/executions/details/${id}`,
    // Mirror remediationService.convertToApiResponse: rollback is offered for a
    // GuardDuty.IAMUser whose original remediation succeeded or whose prior
    // rollback failed (retry). Never for a failed remediation or wrong type.
    isRollbackEligible:
      findingType.endsWith(ROLLBACK_ELIGIBLE_FINDING_TYPE) &&
      (remediationStatus === 'SUCCESS' || remediationStatus === 'ROLLBACK_FAILED'),
    ...data,
  };
}

export function generateTestRemediations(
  length: number,
  data?: Partial<RemediationHistoryApiResponse>,
): Array<RemediationHistoryApiResponse> {
  return Array.from({ length }).map(() => generateTestRemediation(data));
}

export function generateTestFinding(data?: Partial<FindingApiResponse>): FindingApiResponse {
  const id = asFindingId(window.crypto.randomUUID());
  const creationTime = sub(new Date(), {
    days: Math.floor(Math.random() * 30),
    hours: Math.floor(Math.random() * 24),
  }).toISOString();

  return {
    findingId: id,
    findingDescription: randomWord(20, 100),
    accountId: randomAccountId(),
    resourceId: randomWord(30, 40),
    resourceType: randomWord(8, 15),
    resourceTypeNormalized: randomWord(8, 15),
    findingType: randomWord(10, 15),
    region: randomWord(5, 10),
    severity: randomSeverity(),
    remediationStatus: randomRemediationStatus(),
    suppressed: Math.random() > 0.8, // 20% chance of being suppressed
    creationTime: creationTime,
    securityHubUpdatedAtTime: add(new Date(creationTime), {
      hours: Math.floor(Math.random() * 24),
    }).toISOString(),
    lastUpdatedTime: add(new Date(creationTime), {
      hours: Math.floor(Math.random() * 48),
    }).toISOString(),
    consoleLink: `https://console.aws.amazon.com/securityhub/home?region=${randomWord(5, 10)}#/findings/${id}`,
    ...data,
  };
}

export function generateTestFindings(length: number, data?: Partial<FindingApiResponse>): Array<FindingApiResponse> {
  return Array.from({ length }).map(() => generateTestFinding(data));
}

export function generateTestUsers(count: number): User[] {
  const users: User[] = [];
  for (let i = 0; i < count; i++) {
    if (i % 2 === 0) {
      users.push({
        email: `user${i}@example.com`,
        accountIds: ['123456789012', '123456789013'],
        invitedBy: 'admin@example.com',
        invitationTimestamp: new Date().toISOString(),
        status: 'Confirmed',
        type: 'account-operator',
      });
    } else {
      users.push({
        email: `delegated${i}@example.com`,
        invitedBy: 'admin@example.com',
        invitationTimestamp: new Date().toISOString(),
        status: 'Invited',
        type: 'delegated-admin',
      });
    }
  }
  return users;
}
