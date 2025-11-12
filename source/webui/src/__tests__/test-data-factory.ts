// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { add, sub } from 'date-fns';
import { FindingApiResponse, RemediationHistoryApiResponse, User } from '@data-models';
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

// Functions to generate random test data for unit test and early stage UI development
export function generateTestRemediation(data?: Partial<RemediationHistoryApiResponse>): RemediationHistoryApiResponse {
  const id = window.crypto.randomUUID();
  return {
    executionId: id,
    findingId: id,
    lastUpdatedTime: sub(new Date(), {
      hours: Math.random() * 100,
      minutes: Math.random() * 60,
    }).toISOString(),
    accountId: randomAccountId(),
    remediationStatus: randomRemediationStatus(),
    region: randomWord(5, 10),
    resourceId: randomWord(30, 40),
    resourceType: randomWord(10, 15),
    resourceTypeNormalized: randomWord(10, 15),
    findingType: randomWord(10, 15),
    lastUpdatedBy: randomAlias(),
    severity: randomSeverity(),
    consoleLink: `https://console.aws.amazon.com/states/home?region=${randomWord(5, 10)}#/executions/details/${id}`,
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
  const id = window.crypto.randomUUID();
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
