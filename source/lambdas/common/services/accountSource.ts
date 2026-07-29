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
 * Enumerates member accounts via Security Hub `ListMembers`. Because the solution runs in the Security
 * Hub aggregation account, the member set is exactly the accounts whose findings this run can pull.
 *
 * Requires the `securityhub:ListMembers` permission.
 */
export class SecurityHubMemberAccountSource implements AccountSource {
  private readonly logger = getLogger('SecurityHubMemberAccountSource');

  constructor(private readonly client: SecurityHubClient) {}

  async listAccountIds(): Promise<string[]> {
    const accountIds: string[] = [];
    let nextToken: string | undefined;

    do {
      const response = await this.client.send(new ListMembersCommand({ NextToken: nextToken }));
      for (const member of response.Members ?? []) {
        if (member.AccountId) {
          accountIds.push(member.AccountId);
        }
      }
      nextToken = response.NextToken;
    } while (nextToken);

    this.logger.info('Enumerated Security Hub member accounts', { accountCount: accountIds.length });
    return accountIds;
  }
}
