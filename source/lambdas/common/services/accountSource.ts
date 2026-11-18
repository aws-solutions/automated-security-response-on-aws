// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { ListMembersCommand, SecurityHubClient } from '@aws-sdk/client-securityhub';
import { getLogger } from '../utils/logger';

/**
 * Enumerates the AWS account ids a synchronization sweep should walk. Kept behind an interface so the
 * enumeration source (and the IAM permission it needs) is a single, swappable dependency.
 */
export interface AccountSource {
  listAccountIds(): Promise<string[]>;
}

/**
 * Enumerates the Security Hub administrator account and its member accounts. The solution runs in the
 * Security Hub administrator account, so these are exactly the accounts whose findings this run can pull.
 *
 * `ListMembers` returns members only, never the administrator itself. The administrator account is
 * listed first so its own findings are synced too, including in a single-account deployment that has no
 * members at all.
 *
 * Requires the `securityhub:ListMembers` permission.
 */
export class SecurityHubAccountSource implements AccountSource {
  private readonly logger = getLogger('SecurityHubAccountSource');

  constructor(
    private readonly client: SecurityHubClient,
    private readonly administratorAccountId: string,
  ) {}

  async listAccountIds(): Promise<string[]> {
    const accountIds = new Set<string>([this.administratorAccountId]);
    let nextToken: string | undefined;

    do {
      const response = await this.client.send(new ListMembersCommand({ NextToken: nextToken }));
      for (const member of response.Members ?? []) {
        if (member.AccountId) {
          accountIds.add(member.AccountId);
        }
      }
      nextToken = response.NextToken;
    } while (nextToken);

    this.logger.info('Enumerated Security Hub administrator and member accounts', {
      accountCount: accountIds.size,
    });
    return [...accountIds];
  }
}
