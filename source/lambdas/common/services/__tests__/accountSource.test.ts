// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Unit tests for the Security Hub account enumeration source. Security Hub is a true system boundary,
// so it is mocked with aws-sdk-client-mock; the pagination and administrator-account logic is the code
// under test.

import { ListMembersCommand, SecurityHubClient } from '@aws-sdk/client-securityhub';
import { mockClient } from 'aws-sdk-client-mock';
import { SecurityHubAccountSource } from '../accountSource';

const securityHubMock = mockClient(SecurityHubClient);
const ADMINISTRATOR_ACCOUNT_ID = '999999999999';

function listAccountIds(): Promise<string[]> {
  return new SecurityHubAccountSource(new SecurityHubClient({}), ADMINISTRATOR_ACCOUNT_ID).listAccountIds();
}

describe('SecurityHubAccountSource', () => {
  beforeEach(() => securityHubMock.reset());

  it('returns the administrator account first, then every member account across paginated responses', async () => {
    // GIVEN ListMembers returns two pages of members
    securityHubMock
      .on(ListMembersCommand)
      .resolvesOnce({ Members: [{ AccountId: '111111111111' }, { AccountId: '222222222222' }], NextToken: 'p2' })
      .resolvesOnce({ Members: [{ AccountId: '333333333333' }] });

    // WHEN the accounts are enumerated
    const accountIds = await listAccountIds();

    // THEN the administrator leads and both member pages follow in order, the second call carrying the NextToken
    expect(accountIds).toEqual([ADMINISTRATOR_ACCOUNT_ID, '111111111111', '222222222222', '333333333333']);
    expect(securityHubMock.commandCalls(ListMembersCommand)[1].args[0].input.NextToken).toBe('p2');
  });

  it('returns only the administrator account when Security Hub has no members', async () => {
    // A single-account deployment: without the administrator account the sweep would sync nothing.
    securityHubMock.on(ListMembersCommand).resolves({ Members: [] });

    expect(await listAccountIds()).toEqual([ADMINISTRATOR_ACCOUNT_ID]);
  });

  it('lists the administrator account once when ListMembers also returns it', async () => {
    securityHubMock
      .on(ListMembersCommand)
      .resolves({ Members: [{ AccountId: ADMINISTRATOR_ACCOUNT_ID }, { AccountId: '111111111111' }] });

    expect(await listAccountIds()).toEqual([ADMINISTRATOR_ACCOUNT_ID, '111111111111']);
  });

  it('skips members missing an account id', async () => {
    securityHubMock.on(ListMembersCommand).resolves({ Members: [{ AccountId: '111111111111' }, { Email: 'x@y.z' }] });

    expect(await listAccountIds()).toEqual([ADMINISTRATOR_ACCOUNT_ID, '111111111111']);
  });
});
