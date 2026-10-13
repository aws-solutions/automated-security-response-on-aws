// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import {
  DescribeSecurityHubV2Command,
  GetFindingsCommand,
  GetFindingsV2Command,
  InvalidAccessException,
  ResourceNotFoundException,
  SecurityHubClient,
} from '@aws-sdk/client-securityhub';
import { mockClient } from 'aws-sdk-client-mock';
import { SecurityHubUtils } from '../securityHub';

const securityHubMock = mockClient(SecurityHubClient);
const findingArn = (suffix: string): string =>
  `arn:aws:securityhub:us-east-1:111111111111:security-control/S3.1/finding/${suffix}`;

describe('SecurityHubUtils suppression lookup', () => {
  beforeEach(() => {
    securityHubMock.reset();
    securityHubMock.on(GetFindingsCommand).resolves({ Findings: [] });
    securityHubMock.on(GetFindingsV2Command).resolves({ Findings: [] });
  });

  it('reads each requested view in chunks and reports suppressed and unresolved findings', async () => {
    // ARRANGE: 12 findings, one suppressed in Security Hub V2 and the rest unknown to both views
    const findingIds = Array.from({ length: 12 }, (_, index) => findingArn(`finding-${index}`));
    securityHubMock.on(GetFindingsV2Command).resolves({
      Findings: [
        { finding_info: { uid: findingIds[0] }, status_id: 3 },
        { finding_info: { uid: findingIds[1] }, status_id: 1 },
        { unexpected: 'shape' },
      ],
    });

    // ACT
    const result = await new SecurityHubUtils(new SecurityHubClient({})).findSuppressedFindings(
      findingIds.map((findingId) => ({ findingId, shouldCheckCspm: true, shouldCheckSecurityHubV2: true })),
    );

    // ASSERT
    expect([...result.suppressedFindingIds]).toEqual([findingIds[0]]);
    expect(result.unresolvedFindingIds.has(findingIds[1])).toBe(false);
    expect(result.unresolvedFindingIds.size).toBe(10);
    expect(securityHubMock.commandCalls(GetFindingsCommand)).toHaveLength(2);
    const firstV2Filter = securityHubMock.commandCalls(GetFindingsV2Command)[0].args[0].input.Filters;
    expect(firstV2Filter?.CompositeFilters?.[0].Operator).toBe('OR');
    expect(firstV2Filter?.CompositeFilters?.[0].StringFilters).toHaveLength(10);
  });

  it.each([
    { cspmStatus: 'SUPPRESSED', securityHubV2StatusId: 1, isSuppressed: true, isUnresolved: false },
    { cspmStatus: 'NEW', securityHubV2StatusId: 3, isSuppressed: true, isUnresolved: false },
    { cspmStatus: 'NEW', securityHubV2StatusId: 1, isSuppressed: false, isUnresolved: false },
    { cspmStatus: 'SUPPRESSED', securityHubV2StatusId: undefined, isSuppressed: true, isUnresolved: false },
    { cspmStatus: undefined, securityHubV2StatusId: 1, isSuppressed: false, isUnresolved: false },
    { cspmStatus: undefined, securityHubV2StatusId: undefined, isSuppressed: false, isUnresolved: true },
  ] as const)(
    'treats CSPM $cspmStatus with Security Hub V2 status_id $securityHubV2StatusId as suppressed=$isSuppressed',
    async ({ cspmStatus, securityHubV2StatusId, isSuppressed, isUnresolved }) => {
      // ARRANGE
      const findingId = findingArn('conflict');
      if (cspmStatus) {
        securityHubMock.on(GetFindingsCommand).resolves({
          Findings: [
            {
              SchemaVersion: '2018-10-08',
              Id: findingId,
              ProductArn: 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
              GeneratorId: 'security-control/S3.1',
              AwsAccountId: '111111111111',
              CreatedAt: '2025-01-01T00:00:00Z',
              UpdatedAt: '2025-01-01T00:00:00Z',
              Title: 'title',
              Description: 'description',
              Resources: [{ Type: 'AwsS3Bucket', Id: 'arn:aws:s3:::bucket' }],
              Workflow: { Status: cspmStatus },
            },
          ],
        });
      }
      if (securityHubV2StatusId) {
        securityHubMock
          .on(GetFindingsV2Command)
          .resolves({ Findings: [{ finding_info: { uid: findingId }, status_id: securityHubV2StatusId }] });
      }

      // ACT
      const result = await new SecurityHubUtils(new SecurityHubClient({})).findSuppressedFindings([
        { findingId, shouldCheckCspm: true, shouldCheckSecurityHubV2: true },
      ]);

      // ASSERT
      expect(result.suppressedFindingIds.has(findingId)).toBe(isSuppressed);
      expect(result.unresolvedFindingIds.has(findingId)).toBe(isUnresolved);
    },
  );

  it('follows pagination tokens', async () => {
    // ARRANGE
    const findingId = findingArn('paged');
    securityHubMock
      .on(GetFindingsV2Command)
      .resolvesOnce({ Findings: [], NextToken: 'page-2' })
      .resolvesOnce({ Findings: [{ finding_info: { uid: findingId }, status_id: 3 }] });

    // ACT
    const result = await new SecurityHubUtils(new SecurityHubClient({})).findSuppressedFindings([
      { findingId, shouldCheckCspm: false, shouldCheckSecurityHubV2: true },
    ]);

    // ASSERT
    expect(result.suppressedFindingIds.has(findingId)).toBe(true);
    expect(securityHubMock.commandCalls(GetFindingsV2Command)[1].args[0].input.NextToken).toBe('page-2');
  });

  it('treats Security Hub CSPM as having no status when it is not enabled', async () => {
    // ARRANGE
    const findingId = findingArn('no-cspm');
    securityHubMock
      .on(GetFindingsCommand)
      .rejects(new InvalidAccessException({ message: 'not subscribed', $metadata: {} }));
    securityHubMock
      .on(GetFindingsV2Command)
      .resolves({ Findings: [{ finding_info: { uid: findingId }, status_id: 3 }] });

    // ACT
    const result = await new SecurityHubUtils(new SecurityHubClient({})).findSuppressedFindings([
      { findingId, shouldCheckCspm: true, shouldCheckSecurityHubV2: true },
    ]);

    // ASSERT
    expect(result.suppressedFindingIds.has(findingId)).toBe(true);
  });

  it('propagates other Security Hub CSPM errors so the caller can retry', async () => {
    // ARRANGE
    securityHubMock.on(GetFindingsCommand).rejects(new Error('Rate exceeded'));

    // ACT / ASSERT
    await expect(
      new SecurityHubUtils(new SecurityHubClient({})).findSuppressedFindings([
        { findingId: findingArn('throttled'), shouldCheckCspm: true, shouldCheckSecurityHubV2: false },
      ]),
    ).rejects.toThrow('Rate exceeded');
  });

  it('does not report a finding as unresolved when no view was requested', async () => {
    // ARRANGE
    const findingId = findingArn('no-view');

    // ACT
    const result = await new SecurityHubUtils(new SecurityHubClient({})).findSuppressedFindings([
      { findingId, shouldCheckCspm: false, shouldCheckSecurityHubV2: false },
    ]);

    // ASSERT
    expect(result.unresolvedFindingIds.size).toBe(0);
    expect(securityHubMock.commandCalls(GetFindingsCommand)).toHaveLength(0);
  });

  it('skips the views a target does not request', async () => {
    // ARRANGE
    const findingId = findingArn('cspm-only');

    // ACT
    await new SecurityHubUtils(new SecurityHubClient({})).findSuppressedFindings([
      { findingId, shouldCheckCspm: true, shouldCheckSecurityHubV2: false },
    ]);

    // ASSERT
    expect(securityHubMock.commandCalls(GetFindingsCommand)).toHaveLength(1);
    expect(securityHubMock.commandCalls(GetFindingsV2Command)).toHaveLength(0);
  });

  it('reports Security Hub V2 as disabled when the hub does not exist, and caches the answer', async () => {
    // ARRANGE
    securityHubMock
      .on(DescribeSecurityHubV2Command)
      .rejects(new ResourceNotFoundException({ message: 'not subscribed', $metadata: {} }));
    const securityHubUtils = new SecurityHubUtils(new SecurityHubClient({}));

    // ACT
    const firstAnswer = await securityHubUtils.isSecurityHubV2Enabled();
    const secondAnswer = await securityHubUtils.isSecurityHubV2Enabled();

    // ASSERT
    expect(firstAnswer).toBe(false);
    expect(secondAnswer).toBe(false);
    expect(securityHubMock.commandCalls(DescribeSecurityHubV2Command)).toHaveLength(1);
  });

  it('reports Security Hub V2 as disabled when the IAM role lacks DescribeSecurityHubV2 (GovCloud / China)', async () => {
    // ARRANGE: In aws-us-gov and aws-cn the admin stack intentionally omits
    // the securityhub:DescribeSecurityHubV2 IAM action because Security Hub V2
    // is unavailable there. The Lambda must then treat the AccessDeniedException
    // as "V2 not enabled" rather than propagating, so the CSPM path still runs.
    const accessDenied = Object.assign(
      new Error('User is not authorized to perform: securityhub:DescribeSecurityHubV2'),
      {
        name: 'AccessDeniedException',
      },
    );
    securityHubMock.on(DescribeSecurityHubV2Command).rejects(accessDenied);
    const securityHubUtils = new SecurityHubUtils(new SecurityHubClient({}));

    // ACT
    const firstAnswer = await securityHubUtils.isSecurityHubV2Enabled();
    const secondAnswer = await securityHubUtils.isSecurityHubV2Enabled();

    // ASSERT
    expect(firstAnswer).toBe(false);
    expect(secondAnswer).toBe(false);
    expect(securityHubMock.commandCalls(DescribeSecurityHubV2Command)).toHaveLength(1);
  });

  it('does not cache a transient failure to read whether Security Hub V2 is enabled', async () => {
    // ARRANGE
    securityHubMock
      .on(DescribeSecurityHubV2Command)
      .rejectsOnce(new Error('timeout'))
      .resolves({ HubV2Arn: 'arn:aws:securityhub:us-east-1:111111111111:hubv2/test' });
    const securityHubUtils = new SecurityHubUtils(new SecurityHubClient({}));

    // ACT / ASSERT
    await expect(securityHubUtils.isSecurityHubV2Enabled()).rejects.toThrow('timeout');
    await expect(securityHubUtils.isSecurityHubV2Enabled()).resolves.toBe(true);
  });
});
