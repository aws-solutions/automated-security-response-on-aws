// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as fc from 'fast-check';
import { ContentOptionsSchema, CreateNotificationConfigurationRequestSchema } from '@asr/data-models';

/**
 * Property 1: ContentOptions validation correctness
 *
 * For any combination of `enforceDeadline`, `includeRemediationDeadline`,
 * `remediationDeadlineDays`, and `notificationType`, the validation SHALL
 * accept the configuration if and only if:
 *   (a) `enforceDeadline` is false/omitted, OR
 *   (b) `enforceDeadline` is true AND `includeRemediationDeadline` is true
 *       AND `remediationDeadlineDays` is an integer in [1, 90]
 *       AND `notificationType` is 'finding'
 *
 * **Validates: Requirements 1.1, 1.2, 1.3, 1.5**
 */
describe('Property 1: ContentOptions validation correctness', () => {
  const enforceDeadlineArbitrary = fc.option(fc.boolean(), { nil: undefined });

  const includeRemediationDeadlineArbitrary = fc.boolean();

  const validDaysArbitrary = fc.integer({ min: 1, max: 90 });
  const invalidDaysArbitrary = fc.oneof(fc.integer({ min: -100, max: 0 }), fc.integer({ min: 91, max: 500 }));
  const remediationDeadlineDaysArbitrary = fc.option(fc.oneof(validDaysArbitrary, invalidDaysArbitrary), {
    nil: undefined,
  });

  const notificationTypeArbitrary = fc.constantFrom('finding' as const, 'remediation' as const);

  const baseContentOptions = {
    includeManualRemediationLink: true,
    includeIaCSnippet: false,
    includeEnableAutomationLink: true,
  };

  const baseRequest = {
    name: 'TestConfig',
    enabled: true,
    controlIds: ['SC.EC2.1'],
    resourceFilterIds: [],
    deliveryChannels: [
      {
        type: 'email' as const,
        enabled: true,
        recipients: [{ recipientType: 'rootAccountEmail' as const }],
      },
    ],
    batchWindow: { enabled: false },
  };

  function isDaysInValidRange(days: number | undefined): boolean {
    return days !== undefined && Number.isInteger(days) && days >= 1 && days <= 90;
  }

  /**
   * Oracle that models the complete ContentOptionsSchema validation logic.
   * This covers both the new enforceDeadline rules AND pre-existing refinements
   * (base field range, includeRemediationDeadline→days dependency) because
   * fast-check generates inputs that may violate any constraint.
   */
  function contentOptionsExpectedToPass(
    enforceDeadline: boolean | undefined,
    includeRemediationDeadline: boolean,
    remediationDeadlineDays: number | undefined,
  ): boolean {
    // Base field constraint: remediationDeadlineDays, when provided, must be in [1,90]
    if (remediationDeadlineDays !== undefined && !isDaysInValidRange(remediationDeadlineDays)) {
      return false;
    }

    // Existing refinement: includeRemediationDeadline requires remediationDeadlineDays
    if (includeRemediationDeadline && remediationDeadlineDays === undefined) {
      return false;
    }

    const effectiveEnforceDeadline = enforceDeadline ?? false;
    if (!effectiveEnforceDeadline) {
      return true;
    }

    // enforceDeadline is true: all preconditions must be met
    if (!includeRemediationDeadline) return false;
    if (!isDaysInValidRange(remediationDeadlineDays)) return false;
    return true;
  }

  it('ContentOptionsSchema accepts iff enforceDeadline is false/omitted OR all preconditions met', () => {
    fc.assert(
      fc.property(
        enforceDeadlineArbitrary,
        includeRemediationDeadlineArbitrary,
        remediationDeadlineDaysArbitrary,
        (enforceDeadline, includeRemediationDeadline, remediationDeadlineDays) => {
          // ARRANGE
          const input = {
            ...baseContentOptions,
            includeRemediationDeadline,
            ...(remediationDeadlineDays !== undefined ? { remediationDeadlineDays } : {}),
            ...(enforceDeadline !== undefined ? { enforceDeadline } : {}),
          };

          // ACT
          const result = ContentOptionsSchema.safeParse(input);

          // ASSERT
          const expected = contentOptionsExpectedToPass(
            enforceDeadline,
            includeRemediationDeadline,
            remediationDeadlineDays,
          );
          expect(result.success).toBe(expected);
        },
      ),
      { numRuns: 100 },
    );
  });

  it('CreateNotificationConfigurationRequestSchema enforces notificationType constraint when enforceDeadline is true', () => {
    fc.assert(
      fc.property(
        notificationTypeArbitrary,
        includeRemediationDeadlineArbitrary,
        remediationDeadlineDaysArbitrary,
        (notificationType, includeRemediationDeadline, remediationDeadlineDays) => {
          // ARRANGE
          const contentOptions = {
            ...baseContentOptions,
            includeRemediationDeadline,
            enforceDeadline: true,
            ...(remediationDeadlineDays !== undefined ? { remediationDeadlineDays } : {}),
          };

          const input = {
            ...baseRequest,
            notificationType,
            contentOptions,
          };

          // ACT
          const result = CreateNotificationConfigurationRequestSchema.safeParse(input);

          // ASSERT
          const contentOptionsValid = contentOptionsExpectedToPass(
            true,
            includeRemediationDeadline,
            remediationDeadlineDays,
          );
          const notificationTypeValid = notificationType === 'finding';
          const expectedSuccess = contentOptionsValid && notificationTypeValid;

          expect(result.success).toBe(expectedSuccess);
        },
      ),
      { numRuns: 100 },
    );
  });

  it('CreateNotificationConfigurationRequestSchema always accepts enforceDeadline=false regardless of notificationType', () => {
    fc.assert(
      fc.property(
        notificationTypeArbitrary,
        includeRemediationDeadlineArbitrary,
        remediationDeadlineDaysArbitrary,
        (notificationType, includeRemediationDeadline, remediationDeadlineDays) => {
          // ARRANGE
          const contentOptions = {
            ...baseContentOptions,
            includeRemediationDeadline,
            enforceDeadline: false,
            ...(remediationDeadlineDays !== undefined ? { remediationDeadlineDays } : {}),
          };

          const input = {
            ...baseRequest,
            notificationType,
            contentOptions,
          };

          // ACT
          const result = CreateNotificationConfigurationRequestSchema.safeParse(input);

          // ASSERT
          const expectedSuccess = contentOptionsExpectedToPass(
            false,
            includeRemediationDeadline,
            remediationDeadlineDays,
          );
          expect(result.success).toBe(expectedSuccess);
        },
      ),
      { numRuns: 100 },
    );
  });
});
