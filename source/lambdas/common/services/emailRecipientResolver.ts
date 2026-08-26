// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { OrganizationsClient, DescribeAccountCommand } from '@aws-sdk/client-organizations';
import { AccountClient, GetAlternateContactCommand, AlternateContactType } from '@aws-sdk/client-account';
import { Logger } from '@aws-lambda-powertools/logger';
import { LambdaCache } from '../utils/lambdaCache';
import { RecipientType } from '@asr/data-models';

const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

/** Recipient types that can be resolved to email addresses (excludes 'custom'). */
export type ResolvableRecipientType = Exclude<RecipientType, 'custom'>;

/** Result of resolving recipient types. `hasFailure` is true if any individual type's
 *  underlying API call failed — callers can use this to skip destructive sync operations
 *  (e.g. unsubscribing emails) when the desired set may be incomplete. */
export interface ResolveAllResult {
  readonly emails: string[];
  readonly hasFailure: boolean;
}

export interface EmailRecipientResolverDependencies {
  readonly organizationsClient: OrganizationsClient;
  readonly accountClient: AccountClient;
  readonly fetchAccountOperatorEmails: () => Promise<string[]>;
  readonly accountId: string;
  readonly logger: Logger;
}

/**
 * Resolves recipient type labels to actual email addresses using AWS APIs.
 * Uses LambdaCache to avoid repeated API calls within a single invocation.
 */
export class EmailRecipientResolver {
  private readonly cache: LambdaCache<string[], ResolvableRecipientType>;
  private readonly deps: EmailRecipientResolverDependencies;

  constructor(deps: EmailRecipientResolverDependencies) {
    this.deps = deps;
    this.cache = new LambdaCache<string[], ResolvableRecipientType>({
      ttlMs: CACHE_TTL_MS,
      fetchFn: (key) => this.fetchEmails(key),
    });
  }

  /**
   * Resolve recipient types to email addresses, returning per-call failure status.
   * `hasFailure` is true if any underlying API call failed — callers should treat the
   * resolved set as incomplete and avoid destructive sync (e.g. unsubscribing).
   * Genuine "no data configured" responses (e.g. no alternate contact, no operator
   * mappings) are NOT failures.
   */
  async resolveAll(recipientTypes: ResolvableRecipientType[]): Promise<ResolveAllResult> {
    if (recipientTypes.length === 0) return { emails: [], hasFailure: false };

    const unique = [...new Set(recipientTypes)];
    const perType = await Promise.all(
      unique.map(async (type) => {
        try {
          const emails = await this.cache.get(type);
          return { emails: emails ?? [], failed: false };
        } catch (error) {
          this.deps.logger.warn('Failed to resolve recipient type', { type, error });
          return { emails: [] as string[], failed: true };
        }
      }),
    );

    const allEmails = perType.flatMap((r) => r.emails);
    return {
      emails: [...new Set(allEmails)],
      hasFailure: perType.some((r) => r.failed),
    };
  }

  private async fetchEmails(recipientType: ResolvableRecipientType): Promise<string[]> {
    switch (recipientType) {
      case 'rootAccountEmail':
        return this.fetchRootAccountEmail();
      case 'securityContact':
        return this.fetchAlternateContact(AlternateContactType.SECURITY);
      case 'operationsContact':
        return this.fetchAlternateContact(AlternateContactType.OPERATIONS);
      case 'accountOperators':
        return this.fetchAccountOperatorEmails();
    }
  }

  private async fetchRootAccountEmail(): Promise<string[]> {
    try {
      const response = await this.deps.organizationsClient.send(
        new DescribeAccountCommand({ AccountId: this.deps.accountId }),
      );
      const email = response.Account?.Email;
      return email ? [email] : [];
    } catch (error: unknown) {
      // Account not in an org is a permanent "no data" state, not a transient failure.
      if (error instanceof Error && error.name === 'AWSOrganizationsNotInUseException') {
        this.deps.logger.info('Account is not part of an AWS Organization');
        return [];
      }
      throw error;
    }
  }

  private async fetchAlternateContact(contactType: AlternateContactType): Promise<string[]> {
    try {
      const response = await this.deps.accountClient.send(
        new GetAlternateContactCommand({ AlternateContactType: contactType }),
      );
      const email = response.AlternateContact?.EmailAddress;
      return email ? [email] : [];
    } catch (error: unknown) {
      // ResourceNotFoundException is a successful "no contact configured" response,
      // not an API failure — surface as empty list, not as a resolve failure.
      if (error instanceof Error && error.name === 'ResourceNotFoundException') {
        this.deps.logger.info('No alternate contact configured', { contactType });
        return [];
      }
      throw error;
    }
  }

  private async fetchAccountOperatorEmails(): Promise<string[]> {
    return this.deps.fetchAccountOperatorEmails();
  }
}
