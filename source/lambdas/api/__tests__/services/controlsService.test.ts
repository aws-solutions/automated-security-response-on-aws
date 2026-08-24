// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { DynamoDBDocumentClient, PutCommand } from '@aws-sdk/lib-dynamodb';
import { ControlsService } from '../../services/controlsService';
import { DynamoDBTestSetup } from '../../../common/__tests__/dynamodbSetup';
import { remediationConfigTableName } from '../../../common/__tests__/envSetup';

describe('ControlsService', () => {
  let controlsService: ControlsService;
  let logger: Logger;
  let dynamoDBDocumentClient: DynamoDBDocumentClient;

  beforeAll(async () => {
    dynamoDBDocumentClient = DynamoDBTestSetup.getDocClient();
    await DynamoDBTestSetup.createConfigTable(remediationConfigTableName);
  });

  afterAll(async () => {
    await DynamoDBTestSetup.deleteTable(remediationConfigTableName);
  });

  beforeEach(async () => {
    await DynamoDBTestSetup.clearTable(remediationConfigTableName, 'config');

    logger = new Logger({ serviceName: 'test' });
    controlsService = new ControlsService(logger);
  });

  describe('getAllControls', () => {
    it('should retrieve all controls successfully', async () => {
      // ARRANGE
      const controlItems = [
        {
          controlId: 'S3.1',
          description: 'S3 bucket should have server-side encryption enabled',
          automatedRemediationEnabled: true,
          filters: new Set(['filter-1', 'filter-2']),
          filterMode: 'include',
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'admin-user',
        },
        {
          controlId: 'EC2.6',
          description: 'VPC flow logging should be enabled',
          automatedRemediationEnabled: false,
          filterMode: 'exclude',
          version: 2,
          lastModified: '2024-01-02T00:00:00Z',
          modifiedBy: 'admin-user',
        },
        {
          controlId: 'CloudTrail.4',
          description: 'CloudTrail log file validation should be enabled',
          automatedRemediationEnabled: true,
          filters: new Set(['filter-3']),
          filterMode: 'include',
          version: 1,
          lastModified: '2024-01-03T00:00:00Z',
          modifiedBy: 'system',
        },
      ];

      await Promise.all(
        controlItems.map((item) =>
          dynamoDBDocumentClient.send(
            new PutCommand({
              TableName: remediationConfigTableName,
              Item: item,
            }),
          ),
        ),
      );

      // ACT
      const result = await controlsService.getAllControls();

      // ASSERT
      expect(result.controls).toHaveLength(3);
      const controlIds = result.controls.map((c) => c.controlId);
      expect(controlIds).toContain('S3.1');
      expect(controlIds).toContain('EC2.6');
      expect(controlIds).toContain('CloudTrail.4');
    });

    it('should return empty array when no controls exist', async () => {
      // ACT
      const result = await controlsService.getAllControls();

      // ASSERT
      expect(result.controls).toEqual([]);
      expect(result.controls).toHaveLength(0);
    });

    it('should return controls with all expected properties', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 bucket should have server-side encryption enabled',
        automatedRemediationEnabled: true,
        filters: new Set(['filter-1', 'filter-2']),
        filterMode: 'include',
        version: 1,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'admin-user',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      // ACT
      const result = await controlsService.getAllControls();

      // ASSERT
      const control = result.controls[0];
      expect(control).toHaveProperty('controlId', 'S3.1');
      expect(control).toHaveProperty('description', 'S3 bucket should have server-side encryption enabled');
      expect(control).toHaveProperty('automatedRemediationEnabled', true);
      expect(control.filters).toContain('filter-1');
      expect(control.filters).toContain('filter-2');
      expect(control).toHaveProperty('filterMode', 'include');
      expect(control).toHaveProperty('version', 1);
      expect(control).toHaveProperty('lastModified', '2024-01-01T00:00:00Z');
      expect(control).toHaveProperty('modifiedBy', 'admin-user');
    });

    it('should transform filters from Set to Array', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'CloudTrail.4',
        description: 'CloudTrail log file validation should be enabled',
        automatedRemediationEnabled: true,
        filters: new Set(['filter-a', 'filter-b', 'filter-c']),
        filterMode: 'include',
        version: 3,
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      // ACT
      const result = await controlsService.getAllControls();

      // ASSERT
      expect(result.controls).toHaveLength(1);
      expect(Array.isArray(result.controls[0].filters)).toBe(true);
      expect(result.controls[0].filters).toContain('filter-a');
      expect(result.controls[0].filters).toContain('filter-b');
      expect(result.controls[0].filters).toContain('filter-c');
    });

    it('should handle controls with undefined filters', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'RDS.1',
        description: 'RDS snapshots should be private',
        automatedRemediationEnabled: true,
        filterMode: 'include',
        version: 1,
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      // ACT
      const result = await controlsService.getAllControls();

      // ASSERT
      expect(result.controls).toHaveLength(1);
      expect(result.controls[0].filters).toEqual([]);
    });

    it('should default filterMode to include when not specified', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'Lambda.1',
        description: 'Lambda functions should prohibit public access',
        automatedRemediationEnabled: true,
        version: 1,
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      // ACT
      const result = await controlsService.getAllControls();

      // ASSERT
      expect(result.controls).toHaveLength(1);
      expect(result.controls[0].filterMode).toBe('include');
    });
  });

  describe('bulkUpdateControls', () => {
    it('should update controls successfully and return success count', async () => {
      // ARRANGE
      const existingControl = {
        controlId: 'S3.1',
        description: 'S3 bucket should have server-side encryption enabled',
        automatedRemediationEnabled: false,
        filterMode: 'include',
        version: 1,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'original-user',
      };
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: existingControl,
        }),
      );

      const controlsToUpdate = [
        {
          controlId: 'S3.1',
          description: 'S3 bucket should have server-side encryption enabled',
          automatedRemediationEnabled: true,
          filters: ['account-123'],
          filterMode: 'include' as const,
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'original-user',
        },
      ];

      // ACT
      const result = await controlsService.bulkUpdateControls(controlsToUpdate, 'test-user');

      // ASSERT
      expect(result.successCount).toBe(1);
      expect(result.failedControlIds).toHaveLength(0);
    });

    it('should return failed control IDs when version conflict occurs', async () => {
      // ARRANGE
      const existingControl = {
        controlId: 'EC2.6',
        description: 'VPC flow logging should be enabled',
        automatedRemediationEnabled: false,
        filterMode: 'include',
        version: 5,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'original-user',
      };
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: existingControl,
        }),
      );

      const controlsToUpdate = [
        {
          controlId: 'EC2.6',
          description: 'VPC flow logging should be enabled',
          automatedRemediationEnabled: true,
          filters: [],
          filterMode: 'include' as const,
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'original-user',
        },
      ];

      // ACT
      const result = await controlsService.bulkUpdateControls(controlsToUpdate, 'test-user');

      // ASSERT
      expect(result.successCount).toBe(0);
      expect(result.failedControlIds).toContain('EC2.6');
    });

    it('should update modifiedBy and lastModified fields', async () => {
      // ARRANGE
      const existingControl = {
        controlId: 'CloudTrail.4',
        description: 'CloudTrail log file validation should be enabled',
        automatedRemediationEnabled: false,
        filterMode: 'include',
        version: 1,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'original-user',
      };
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: existingControl,
        }),
      );

      const controlsToUpdate = [
        {
          controlId: 'CloudTrail.4',
          description: 'CloudTrail log file validation should be enabled',
          automatedRemediationEnabled: true,
          filters: [],
          filterMode: 'include' as const,
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'original-user',
        },
      ];

      // ACT
      await controlsService.bulkUpdateControls(controlsToUpdate, 'new-admin');
      const updatedControls = await controlsService.getAllControls();

      // ASSERT
      const updatedControl = updatedControls.controls.find((c) => c.controlId === 'CloudTrail.4');
      expect(updatedControl?.modifiedBy).toBe('new-admin');
      expect(updatedControl?.lastModified).toBeDefined();
      expect(updatedControl?.version).toBe(2);
    });
  });
});
