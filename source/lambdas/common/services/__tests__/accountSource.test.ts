// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Unit tests for the Security Hub member-account enumeration source. Security Hub is a true system
// boundary, so it is mocked with aws-sdk-client-mock; the pagination logic is the code under test.

import { ListMembersCommand, SecurityHubClient } from '@aws-sdk/client-securityhub';
import { mockClient } from 'aws-sdk-client-mock';
import { SecurityHubMemberAccountSource } from '../accountSource';

const securityHubMock = mockClient(SecurityHubClient);

describe('SecurityHubMemberAccountSource', () => {
  beforeEach(() => securityHubMock.reset());

  it('returns every member account id across paginated responses', async () => {
    // GIVEN ListMembers returns two pages of members
    securityHubMock
      .on(ListMembersCommand)
      .resolvesOnce({ Members: [{ AccountId: '111111111111' }, { AccountId: '222222222222' }], NextToken: 'p2' })
      .resolvesOnce({ Members: [{ AccountId: '333333333333' }] });

    // WHEN the accounts are enumerated
    const accountIds = await new SecurityHubMemberAccountSource(new SecurityHubClient({})).listAccountIds();

    // THEN both pages are flattened in order and the second call carried the NextToken
    expect(accountIds).toEqual(['111111111111', '222222222222', '333333333333']);
    expect(securityHubMock.commandCalls(ListMembersCommand)[1].args[0].input.NextToken).toBe('p2');
  });

  it('returns an empty list when the organization has no members', async () => {
    securityHubMock.on(ListMembersCommand).resolves({ Members: [] });

    expect(await new SecurityHubMemberAccountSource(new SecurityHubClient({})).listAccountIds()).toEqual([]);
  });

  it('skips members missing an account id', async () => {
    securityHubMock.on(ListMembersCommand).resolves({ Members: [{ AccountId: '111111111111' }, { Email: 'x@y.z' }] });

    expect(await new SecurityHubMemberAccountSource(new SecurityHubClient({})).listAccountIds()).toEqual([
      '111111111111',
    ]);
  });
});
