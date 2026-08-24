// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { mockClient } from 'aws-sdk-client-mock';
import 'aws-sdk-client-mock-jest';
import { OrganizationsClient, DescribeAccountCommand } from '@aws-sdk/client-organizations';
import { AccountClient, GetAlternateContactCommand } from '@aws-sdk/client-account';
import { Logger } from '@aws-lambda-powertools/logger';
import { EmailRecipientResolver } from '../../services/emailRecipientResolver';

const orgMock = mockClient(OrganizationsClient);
const accountMock = mockClient(AccountClient);
const logger = new Logger({ logLevel: 'SILENT' });

describe('EmailRecipientResolver', () => {
  let resolver: EmailRecipientResolver;
  let fetchAccountOperatorEmails: jest.Mock;

  beforeEach(() => {
    orgMock.reset();
    accountMock.reset();
    fetchAccountOperatorEmails = jest.fn().mockResolvedValue([]);

    resolver = new EmailRecipientResolver({
      organizationsClient: new OrganizationsClient({}),
      accountClient: new AccountClient({}),
      fetchAccountOperatorEmails,
      accountId: '123456789012',
      logger,
    });
  });

  describe('rootAccountEmail', () => {
    it('should resolve root account email via Organizations DescribeAccount', async () => {
      orgMock.on(DescribeAccountCommand).resolves({
        Account: { Email: 'root@example.com', Id: '123456789012', Name: 'Test' },
      });

      const result = await resolver.resolveAll(['rootAccountEmail']);
      expect(result).toEqual({ emails: ['root@example.com'], hasFailure: false });
      expect(orgMock).toHaveReceivedCommandWith(DescribeAccountCommand, { AccountId: '123456789012' });
    });

    it('should mark as failure when DescribeAccount fails', async () => {
      orgMock.on(DescribeAccountCommand).rejects(new Error('Access denied'));

      const result = await resolver.resolveAll(['rootAccountEmail']);
      expect(result).toEqual({ emails: [], hasFailure: true });
    });

    it('should treat AWSOrganizationsNotInUseException as success with no email (not a failure)', async () => {
      const error = Object.assign(new Error('Your account is not a member of an organization.'), {
        name: 'AWSOrganizationsNotInUseException',
        $metadata: { httpStatusCode: 400 },
      });
      orgMock.on(DescribeAccountCommand).rejects(error);

      const result = await resolver.resolveAll(['rootAccountEmail']);
      expect(result).toEqual({ emails: [], hasFailure: false });
    });
  });

  describe('securityContact', () => {
    it('should resolve security alternate contact', async () => {
      accountMock.on(GetAlternateContactCommand).resolves({
        AlternateContact: { EmailAddress: 'security@example.com' },
      });

      const result = await resolver.resolveAll(['securityContact']);
      expect(result).toEqual({ emails: ['security@example.com'], hasFailure: false });
      expect(accountMock).toHaveReceivedCommandWith(GetAlternateContactCommand, {
        AlternateContactType: 'SECURITY',
      });
    });

    it('should treat ResourceNotFoundException as success with no email (not a failure)', async () => {
      const error = Object.assign(new Error('No contact'), { name: 'ResourceNotFoundException' });
      accountMock.on(GetAlternateContactCommand).rejects(error);

      const result = await resolver.resolveAll(['securityContact']);
      expect(result).toEqual({ emails: [], hasFailure: false });
    });

    it('should mark as failure on unexpected error', async () => {
      accountMock.on(GetAlternateContactCommand).rejects(new Error('Throttled'));

      const result = await resolver.resolveAll(['securityContact']);
      expect(result).toEqual({ emails: [], hasFailure: true });
    });
  });

  describe('operationsContact', () => {
    it('should resolve operations alternate contact', async () => {
      accountMock.on(GetAlternateContactCommand).resolves({
        AlternateContact: { EmailAddress: 'ops@example.com' },
      });

      const result = await resolver.resolveAll(['operationsContact']);
      expect(result).toEqual({ emails: ['ops@example.com'], hasFailure: false });
      expect(accountMock).toHaveReceivedCommandWith(GetAlternateContactCommand, {
        AlternateContactType: 'OPERATIONS',
      });
    });
  });

  describe('accountOperators', () => {
    it('should resolve all user emails via injected function', async () => {
      fetchAccountOperatorEmails.mockResolvedValue(['op1@example.com', 'op2@example.com']);

      const result = await resolver.resolveAll(['accountOperators']);
      expect(result).toEqual({ emails: ['op1@example.com', 'op2@example.com'], hasFailure: false });
      expect(fetchAccountOperatorEmails).toHaveBeenCalled();
    });

    it('should mark as failure on injected-function error', async () => {
      fetchAccountOperatorEmails.mockRejectedValue(new Error('DDB error'));

      const result = await resolver.resolveAll(['accountOperators']);
      expect(result).toEqual({ emails: [], hasFailure: true });
    });
  });

  describe('resolveAll', () => {
    it('should resolve multiple recipient types and deduplicate', async () => {
      orgMock.on(DescribeAccountCommand).resolves({
        Account: { Email: 'root@example.com', Id: '123456789012', Name: 'Test' },
      });
      accountMock.on(GetAlternateContactCommand).resolves({
        AlternateContact: { EmailAddress: 'root@example.com' }, // same as root
      });
      fetchAccountOperatorEmails.mockResolvedValue(['op@example.com']);

      const result = await resolver.resolveAll(['rootAccountEmail', 'securityContact', 'accountOperators']);
      expect(result.hasFailure).toBe(false);
      expect(result.emails).toContain('root@example.com');
      expect(result.emails).toContain('op@example.com');
      // Deduplicated
      expect(result.emails.filter((e) => e === 'root@example.com')).toHaveLength(1);
    });

    it('should return empty result for empty input', async () => {
      const result = await resolver.resolveAll([]);
      expect(result).toEqual({ emails: [], hasFailure: false });
    });

    it('should report hasFailure=true when ANY type fails, while still returning emails from successful types', async () => {
      orgMock.on(DescribeAccountCommand).resolves({
        Account: { Email: 'root@example.com', Id: '123456789012', Name: 'Test' },
      });
      fetchAccountOperatorEmails.mockRejectedValue(new Error('DDB error'));

      const result = await resolver.resolveAll(['rootAccountEmail', 'accountOperators']);
      expect(result.hasFailure).toBe(true);
      expect(result.emails).toEqual(['root@example.com']);
    });
  });
});
