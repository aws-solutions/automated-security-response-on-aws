// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { NormalizedFinding, NotificationConfigurationItem } from '@asr/data-models';
import { FindingNotificationConfigEvaluator } from '../findingNotificationConfigEvaluator';
import { NotificationConfigurationRepository } from '../../common/repositories/notificationConfigurationRepository';
import { ResourceFilterEvaluator } from '../ResourceFilterEvaluator';
import { Clock } from '../../common/utils/clock';
import { asConfigId } from '../../common/__tests__/utils';

describe('FindingNotificationConfigEvaluator', () => {
  const logger = new Logger({ logLevel: 'SILENT' });
  const fixedNow = new Date('2025-06-01T00:00:00Z');
  const stubClock: Clock = { now: () => fixedNow };

  let findByType: jest.Mock;
  let evaluateFilters: jest.Mock;
  let passingFilterIds: Set<string>;
  let evaluator: FindingNotificationConfigEvaluator;

  const createFinding = (overrides: Partial<NormalizedFinding> = {}): NormalizedFinding => ({
    id: 'finding-1',
    productArn: 'arn:aws:securityhub:us-east-1::product/aws/securityhub',
    findingTypeIdentifier: { type: 'securityControl', value: 'S3.1' },
    accountId: '111111111111',
    region: 'us-east-1',
    severity: 'HIGH',
    complianceStatus: 'FAILED',
    recordState: 'ACTIVE',
    workflowStatus: 'NEW',
    resources: [{ type: 'AwsS3Bucket', id: 'arn:aws:s3:::bucket', tags: {} }],
    title: 'Test Finding',
    description: 'Test description',
    createdAt: '2025-01-01T00:00:00Z',
    updatedAt: '2025-01-01T00:00:00Z',
    format: 'ASFF',
    raw: {},
    ...overrides,
  });

  const createConfig = (overrides: Partial<NotificationConfigurationItem> = {}): NotificationConfigurationItem => ({
    configId: asConfigId('aaaaaaaa-bbbb-cccc-dddd-000000000001'),
    name: 'Enforcement Config',
    enabled: true,
    notificationType: 'finding',
    severityFilter: ['All'],
    controlIds: [],
    resourceFilterIds: [],
    deliveryChannels: [],
    batchWindow: { enabled: false },
    contentOptions: {
      includeManualRemediationLink: false,
      includeRemediationDeadline: true,
      remediationDeadlineDays: 10,
      enforceDeadline: true,
      includeIaCSnippet: false,
      includeEnableAutomationLink: false,
    },
    version: 1,
    createdAt: '2025-01-01T00:00:00Z',
    createdBy: 'admin@example.com',
    ...overrides,
  });

  beforeEach(() => {
    // ARRANGE: stub the config repository and resource filter evaluator. The
    // filter evaluator faithfully mirrors the real one: an empty filter list
    // always passes, otherwise a filter id must be in the passing set.
    passingFilterIds = new Set();
    findByType = jest.fn();
    evaluateFilters = jest.fn().mockImplementation(async (_finding: NormalizedFinding, filterIds: string[]) => {
      if (filterIds.length === 0) {
        return { passed: true, reason: 'no_filters_configured' };
      }
      const passed = filterIds.some((id) => passingFilterIds.has(id));
      return { passed, reason: passed ? 'all_filters_matched' : 'filter_not_matched' };
    });

    const configurationRepository = {
      findByType,
    } as unknown as NotificationConfigurationRepository;
    const resourceFilterEvaluator = {
      evaluateFilters,
    } as unknown as ResourceFilterEvaluator;

    evaluator = new FindingNotificationConfigEvaluator(
      configurationRepository,
      resourceFilterEvaluator,
      stubClock,
      logger,
    );
  });

  describe('Property 2: write-time eligibility stamping', () => {
    it('marks a finding eligible only when control, severity, and resource filters all match', async () => {
      // ARRANGE: a fully matching enforcement config
      findByType.mockResolvedValue([createConfig()]);

      // ACT
      const result = (await evaluator.evaluateFindingConfigs(createFinding(), 'S3.1')).enforcement;

      // ASSERT: eligible; createdAt + 10 days (2025-01-11) precedes the grace floor, so the
      // result is clamped to fixedNow + 24h
      expect(result.isEligible).toBe(true);
      expect(result.remediationDueBy).toBe('2025-06-02T00:00:00.000Z');
      expect(result.matchingConfigIds).toEqual(['aaaaaaaa-bbbb-cccc-dddd-000000000001']);
      expect(evaluateFilters).toHaveBeenCalledWith(expect.anything(), [], 'include');
    });

    it('does not mark eligible when the control id is not in the config control filter', async () => {
      // ARRANGE: config restricted to a different control
      findByType.mockResolvedValue([createConfig({ controlIds: ['IAM.1'] })]);

      // ACT
      const result = (await evaluator.evaluateFindingConfigs(createFinding(), 'S3.1')).enforcement;

      // ASSERT
      expect(result.isEligible).toBe(false);
      expect(result.matchingConfigIds).toEqual([]);
    });

    it('does not mark eligible when the finding severity is excluded by the severity filter', async () => {
      // ARRANGE: config only targets Critical findings
      findByType.mockResolvedValue([createConfig({ severityFilter: ['Critical'] })]);

      // ACT: finding is HIGH severity
      const result = (await evaluator.evaluateFindingConfigs(createFinding({ severity: 'HIGH' }), 'S3.1')).enforcement;

      // ASSERT
      expect(result.isEligible).toBe(false);
      expect(result.matchingConfigIds).toEqual([]);
    });

    it('does not mark eligible when the resource filters do not match', async () => {
      // ARRANGE: config references a filter that is not in the passing set
      findByType.mockResolvedValue([createConfig({ resourceFilterIds: ['rf-no-match'] })]);

      // ACT
      const result = (await evaluator.evaluateFindingConfigs(createFinding(), 'S3.1')).enforcement;

      // ASSERT
      expect(result.isEligible).toBe(false);
      expect(result.matchingConfigIds).toEqual([]);
    });
  });

  describe('Property 3: shortest deadline wins', () => {
    it('uses the minimum deadline across matching configs and records every matching config id', async () => {
      // ARRANGE: two matching configs with different deadlines (30 and 10 days)
      const longDeadlineConfig = createConfig({
        configId: asConfigId('aaaaaaaa-bbbb-cccc-dddd-000000000030'),
        contentOptions: {
          includeManualRemediationLink: false,
          includeRemediationDeadline: true,
          remediationDeadlineDays: 30,
          enforceDeadline: true,
          includeIaCSnippet: false,
          includeEnableAutomationLink: false,
        },
      });
      const shortDeadlineConfig = createConfig({
        configId: asConfigId('aaaaaaaa-bbbb-cccc-dddd-000000000010'),
        contentOptions: {
          includeManualRemediationLink: false,
          includeRemediationDeadline: true,
          remediationDeadlineDays: 10,
          enforceDeadline: true,
          includeIaCSnippet: false,
          includeEnableAutomationLink: false,
        },
      });
      findByType.mockResolvedValue([longDeadlineConfig, shortDeadlineConfig]);

      // ACT
      const result = (await evaluator.evaluateFindingConfigs(createFinding(), 'S3.1')).enforcement;

      // ASSERT: the 10-day deadline wins over the 30-day one, but createdAt + 10 days
      // (2025-01-11) precedes the grace floor, so the result is clamped to fixedNow + 24h;
      // both config ids are still recorded
      expect(result.isEligible).toBe(true);
      expect(result.remediationDueBy).toBe('2025-06-02T00:00:00.000Z');
      expect(result.matchingConfigIds).toEqual(
        expect.arrayContaining(['aaaaaaaa-bbbb-cccc-dddd-000000000030', 'aaaaaaaa-bbbb-cccc-dddd-000000000010']),
      );
      expect(result.matchingConfigIds).toHaveLength(2);
    });
  });

  describe('resource filter delegation', () => {
    it('delegates to the resource filter evaluator in include mode with the config filter ids', async () => {
      // ARRANGE: config with a passing resource filter (covers OU/tag/ARN evaluation)
      passingFilterIds.add('rf-ou-and-tags');
      findByType.mockResolvedValue([createConfig({ resourceFilterIds: ['rf-ou-and-tags'] })]);
      const finding = createFinding();

      // ACT
      const result = (await evaluator.evaluateFindingConfigs(finding, 'S3.1')).enforcement;

      // ASSERT: matched, and the full-fidelity evaluator was invoked correctly
      expect(result.isEligible).toBe(true);
      expect(evaluateFilters).toHaveBeenCalledWith(finding, ['rf-ou-and-tags'], 'include');
    });

    it('treats an empty resource filter list as a match', async () => {
      // ARRANGE: config with no resource filters
      findByType.mockResolvedValue([createConfig({ resourceFilterIds: [] })]);

      // ACT
      const result = (await evaluator.evaluateFindingConfigs(createFinding(), 'S3.1')).enforcement;

      // ASSERT
      expect(result.isEligible).toBe(true);
      expect(evaluateFilters).toHaveBeenCalledWith(expect.anything(), [], 'include');
    });
  });

  describe('config selection', () => {
    it('excludes disabled, non-finding, and incompletely-configured enforcement configs', async () => {
      // ARRANGE: a set of configs that should all be ignored
      findByType.mockResolvedValue([
        createConfig({ configId: asConfigId('aaaaaaaa-0000-0000-0000-000000000001'), enabled: false }),
        createConfig({ configId: asConfigId('aaaaaaaa-0000-0000-0000-000000000002'), notificationType: 'remediation' }),
        createConfig({
          configId: asConfigId('aaaaaaaa-0000-0000-0000-000000000003'),
          contentOptions: {
            includeManualRemediationLink: false,
            includeRemediationDeadline: true,
            remediationDeadlineDays: 10,
            enforceDeadline: false,
            includeIaCSnippet: false,
            includeEnableAutomationLink: false,
          },
        }),
        createConfig({
          configId: asConfigId('aaaaaaaa-0000-0000-0000-000000000004'),
          contentOptions: {
            includeManualRemediationLink: false,
            includeRemediationDeadline: false,
            enforceDeadline: true,
            includeIaCSnippet: false,
            includeEnableAutomationLink: false,
          },
        }),
        createConfig({
          configId: asConfigId('aaaaaaaa-0000-0000-0000-000000000005'),
          contentOptions: {
            includeManualRemediationLink: false,
            includeRemediationDeadline: true,
            remediationDeadlineDays: undefined,
            enforceDeadline: true,
            includeIaCSnippet: false,
            includeEnableAutomationLink: false,
          },
        }),
      ]);

      // ACT
      const result = (await evaluator.evaluateFindingConfigs(createFinding(), 'S3.1')).enforcement;

      // ASSERT
      expect(result.isEligible).toBe(false);
      expect(result.matchingConfigIds).toEqual([]);
    });

    it('matches all findings when controlIds is empty', async () => {
      // ARRANGE: empty controlIds should match any control
      findByType.mockResolvedValue([createConfig({ controlIds: [] })]);

      // ACT
      const result = (await evaluator.evaluateFindingConfigs(createFinding(), 'EC2.19')).enforcement;

      // ASSERT
      expect(result.isEligible).toBe(true);
      expect(result.matchingConfigIds).toEqual(['aaaaaaaa-bbbb-cccc-dddd-000000000001']);
    });

    it('returns ineligible when no enforcement configs exist', async () => {
      // ARRANGE
      findByType.mockResolvedValue([]);

      // ACT
      const result = (await evaluator.evaluateFindingConfigs(createFinding(), 'S3.1')).enforcement;

      // ASSERT
      expect(result.isEligible).toBe(false);
      expect(result.matchingConfigIds).toEqual([]);
    });
  });

  describe('severity normalization', () => {
    it('matches an uppercase ASFF severity against a title-case severity filter', async () => {
      // ARRANGE: filter uses title case, finding uses ASFF uppercase
      findByType.mockResolvedValue([createConfig({ severityFilter: ['Critical'] })]);

      // ACT
      const result = (await evaluator.evaluateFindingConfigs(createFinding({ severity: 'CRITICAL' }), 'S3.1'))
        .enforcement;

      // ASSERT
      expect(result.isEligible).toBe(true);
    });
  });

  describe('evaluateFindingConfigs: metric-enrichment flags', () => {
    it('sets both flags and enforcement eligibility when a finding config fully matches', async () => {
      // ARRANGE: a fully matching enforcement config (deadline included + enforced)
      findByType.mockResolvedValue([createConfig()]);

      // ACT
      const result = await evaluator.evaluateFindingConfigs(createFinding(), 'S3.1');

      // ASSERT: notifications + deadline flags true, and enforcement still eligible
      expect(result.hasNotificationsEnabled).toBe(true);
      expect(result.hasDeadlineConfigured).toBe(true);
      expect(result.enforcement.isEligible).toBe(true);
    });

    it('excludes the finding from the metric flags when the config account scope does not match, but preserves enforcement', async () => {
      // ARRANGE: config scoped to a different account than the finding (111111111111)
      findByType.mockResolvedValue([createConfig({ accountIds: ['999999999999'] })]);

      // ACT
      const result = await evaluator.evaluateFindingConfigs(createFinding(), 'S3.1');

      // ASSERT: account scope gates the metric flags, but enforcement intentionally ignores it
      expect(result.hasNotificationsEnabled).toBe(false);
      expect(result.hasDeadlineConfigured).toBe(false);
      expect(result.enforcement.isEligible).toBe(true);
    });

    it('reports hasNotificationsEnabled without hasDeadlineConfigured when the matching config has no remediation deadline', async () => {
      // ARRANGE: an enabled finding config that matches but does not configure a deadline
      findByType.mockResolvedValue([
        createConfig({
          contentOptions: {
            includeManualRemediationLink: false,
            includeRemediationDeadline: false,
            enforceDeadline: false,
            includeIaCSnippet: false,
            includeEnableAutomationLink: false,
          },
        }),
      ]);

      // ACT
      const result = await evaluator.evaluateFindingConfigs(createFinding(), 'S3.1');

      // ASSERT
      expect(result.hasNotificationsEnabled).toBe(true);
      expect(result.hasDeadlineConfigured).toBe(false);
      expect(result.enforcement.isEligible).toBe(false);
    });

    it('reports all flags false when no config matches the control filter', async () => {
      // ARRANGE: config restricted to a different control
      findByType.mockResolvedValue([createConfig({ controlIds: ['IAM.1'] })]);

      // ACT
      const result = await evaluator.evaluateFindingConfigs(createFinding(), 'S3.1');

      // ASSERT
      expect(result.hasNotificationsEnabled).toBe(false);
      expect(result.hasDeadlineConfigured).toBe(false);
      expect(result.enforcement.isEligible).toBe(false);
    });
  });

  describe('24-hour grace-period floor wired through the evaluator clock', () => {
    it('uses the deadline-based value for a brand-new finding whose deadline exceeds the floor', async () => {
      // ARRANGE: a finding created at the write time (fixedNow) with a 10-day deadline
      findByType.mockResolvedValue([createConfig()]);

      // ACT
      const result = (
        await evaluator.evaluateFindingConfigs(createFinding({ createdAt: '2025-06-01T00:00:00Z' }), 'S3.1')
      ).enforcement;

      // ASSERT: createdAt + 10 days (2025-06-11) is later than fixedNow + 24h, so it wins
      expect(result.isEligible).toBe(true);
      expect(result.remediationDueBy).toBe('2025-06-11T00:00:00.000Z');
    });

    it('clamps a backlog finding to the write time (clock.now) plus 24 hours', async () => {
      // ARRANGE: an old backlog finding whose creation-time deadline is already in the past
      findByType.mockResolvedValue([createConfig()]);

      // ACT
      const result = (
        await evaluator.evaluateFindingConfigs(createFinding({ createdAt: '2020-01-01T00:00:00Z' }), 'S3.1')
      ).enforcement;

      // ASSERT: clamped to fixedNow + 24h rather than becoming instantly overdue
      expect(result.isEligible).toBe(true);
      expect(result.remediationDueBy).toBe('2025-06-02T00:00:00.000Z');
    });
  });
});
