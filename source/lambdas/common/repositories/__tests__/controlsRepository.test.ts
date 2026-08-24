// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { DynamoDBDocumentClient, PutCommand, GetCommand } from '@aws-sdk/lib-dynamodb';
import { ControlsRepository } from '../controlsRepository';
import { DynamoDBTestSetup } from '../../__tests__/dynamodbSetup';
import { remediationConfigTableName } from '../../__tests__/envSetup';

describe('ControlsRepository', () => {
  let repository: ControlsRepository;
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
    repository = new ControlsRepository(remediationConfigTableName, dynamoDBDocumentClient);
  });

  describe('findAll', () => {
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
          filters: new Set(['filter-3']),
          filterMode: 'exclude',
          version: 2,
          lastModified: '2024-01-02T00:00:00Z',
          modifiedBy: 'admin-user',
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
      const result = await repository.findAll();

      // ASSERT
      expect(result).toHaveLength(2);
      const controlIds = result.map((c) => c.controlId);
      expect(controlIds).toContain('S3.1');
      expect(controlIds).toContain('EC2.6');
    });

    it('should return empty array when table is empty', async () => {
      // ACT
      const result = await repository.findAll();

      // ASSERT
      expect(result).toEqual([]);
      expect(result).toHaveLength(0);
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
        lastModified: '2024-01-03T00:00:00Z',
        modifiedBy: 'system',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      // ACT
      const result = await repository.findAll();

      // ASSERT
      expect(result).toHaveLength(1);
      expect(Array.isArray(result[0].filters)).toBe(true);
      expect(result[0].filters).toContain('filter-a');
      expect(result[0].filters).toContain('filter-b');
      expect(result[0].filters).toContain('filter-c');
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
      const result = await repository.findAll();

      // ASSERT
      expect(result).toHaveLength(1);
      expect(result[0].filters).toEqual([]);
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
      const result = await repository.findAll();

      // ASSERT
      expect(result).toHaveLength(1);
      expect(result[0].filterMode).toBe('include');
    });

    it('should handle controls with empty lastModified and modifiedBy', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'KMS.1',
        description: 'KMS keys should not be publicly accessible',
        automatedRemediationEnabled: false,
        version: 1,
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      // ACT
      const result = await repository.findAll();

      // ASSERT
      expect(result).toHaveLength(1);
      expect(result[0].lastModified).toBe('');
      expect(result[0].modifiedBy).toBe('');
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
      const result = await repository.findAll();

      // ASSERT
      const control = result[0];
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
  });

  describe('bulkUpdateControls', () => {
    it('should update a single control successfully', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 bucket should have server-side encryption enabled',
        automatedRemediationEnabled: false,
        filterMode: 'include',
        version: 1,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      const controlsToUpdate = [
        {
          controlId: 'S3.1',
          description: 'S3 bucket should have server-side encryption enabled',
          automatedRemediationEnabled: true,
          filters: ['filter-1'],
          filterMode: 'include' as const,
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        },
      ];

      // ACT
      const result = await repository.bulkUpdateControls(controlsToUpdate, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(1);
      expect(result.failedControlIds).toHaveLength(0);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(updatedItem.Item?.automatedRemediationEnabled).toBe(true);
      expect(updatedItem.Item?.version).toBe(2);
      expect(updatedItem.Item?.modifiedBy).toBe('admin-user');
      expect(updatedItem.Item?.lastModified).toBe('2024-01-15T10:00:00Z');
    });

    it('should update multiple controls in a single batch', async () => {
      // ARRANGE
      const controlItems = [
        {
          controlId: 'S3.1',
          description: 'S3 control',
          automatedRemediationEnabled: false,
          filterMode: 'include',
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        },
        {
          controlId: 'EC2.1',
          description: 'EC2 control',
          automatedRemediationEnabled: false,
          filterMode: 'include',
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
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

      const controlsToUpdate = [
        {
          controlId: 'S3.1',
          description: 'S3 control',
          automatedRemediationEnabled: true,
          filters: [],
          filterMode: 'include' as const,
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        },
        {
          controlId: 'EC2.1',
          description: 'EC2 control',
          automatedRemediationEnabled: true,
          filters: [],
          filterMode: 'exclude' as const,
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        },
      ];

      // ACT
      const result = await repository.bulkUpdateControls(controlsToUpdate, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(2);
      expect(result.failedControlIds).toHaveLength(0);
    });

    it('should fail immediately on version conflict without retries', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'S3.1',
        description: 'Original description',
        automatedRemediationEnabled: true,
        filters: new Set(['original-filter']),
        filterMode: 'exclude',
        version: 5,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'original-user',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      const controlsToUpdate = [
        {
          controlId: 'S3.1',
          description: 'New description',
          automatedRemediationEnabled: false,
          filters: ['new-filter'],
          filterMode: 'include' as const,
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        },
      ];

      // ACT
      const result = await repository.bulkUpdateControls(controlsToUpdate, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(0);
      expect(result.failedControlIds).toEqual(['S3.1']);

      const unchangedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(unchangedItem.Item?.version).toBe(5);
      expect(unchangedItem.Item?.description).toBe('Original description');
      expect(unchangedItem.Item?.automatedRemediationEnabled).toBe(true);
      expect(unchangedItem.Item?.filterMode).toBe('exclude');
      expect(unchangedItem.Item?.modifiedBy).toBe('original-user');
    });

    it('should fail when control does not exist', async () => {
      // ARRANGE
      const controlsToUpdate = [
        {
          controlId: 'NONEXISTENT.1',
          description: 'Non-existent control',
          automatedRemediationEnabled: true,
          filters: [],
          filterMode: 'include' as const,
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        },
      ];

      // ACT
      const result = await repository.bulkUpdateControls(controlsToUpdate, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(0);
      expect(result.failedControlIds).toEqual(['NONEXISTENT.1']);
    });

    it('should store filters as String Set in DynamoDB', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 control',
        automatedRemediationEnabled: false,
        filterMode: 'include',
        version: 1,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      const controlsToUpdate = [
        {
          controlId: 'S3.1',
          description: 'S3 control',
          automatedRemediationEnabled: true,
          filters: ['filter-a', 'filter-b'],
          filterMode: 'exclude' as const,
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        },
      ];

      // ACT
      const result = await repository.bulkUpdateControls(controlsToUpdate, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(1);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );

      const filters = updatedItem.Item?.filters;
      if (filters instanceof Set) {
        expect(Array.from(filters).sort()).toEqual(['filter-a', 'filter-b']);
      } else if (Array.isArray(filters)) {
        expect(filters.sort()).toEqual(['filter-a', 'filter-b']);
      } else {
        fail('Expected filters to be Set or Array');
      }
    });

    it('should remove filters attribute when empty array is provided', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 control',
        automatedRemediationEnabled: false,
        filters: new Set(['existing-filter']),
        filterMode: 'include',
        version: 1,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      const controlsToUpdate = [
        {
          controlId: 'S3.1',
          description: 'S3 control',
          automatedRemediationEnabled: true,
          filters: [],
          filterMode: 'include' as const,
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        },
      ];

      // ACT
      const result = await repository.bulkUpdateControls(controlsToUpdate, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(1);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(updatedItem.Item?.filters).toBeUndefined();
    });

    it('should update all control attributes correctly', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'S3.1',
        description: 'Original description',
        automatedRemediationEnabled: false,
        filters: new Set(['old-filter']),
        filterMode: 'include',
        version: 1,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'original-user',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      const controlsToUpdate = [
        {
          controlId: 'S3.1',
          description: 'Updated description',
          automatedRemediationEnabled: true,
          filters: ['new-filter-1', 'new-filter-2'],
          filterMode: 'exclude' as const,
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'original-user',
        },
      ];

      // ACT
      const result = await repository.bulkUpdateControls(controlsToUpdate, 'new-admin', '2024-02-01T12:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(1);
      expect(result.failedControlIds).toHaveLength(0);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );

      expect(updatedItem.Item?.description).toBe('Updated description');
      expect(updatedItem.Item?.automatedRemediationEnabled).toBe(true);
      expect(updatedItem.Item?.filterMode).toBe('exclude');
      expect(updatedItem.Item?.version).toBe(2);
      expect(updatedItem.Item?.lastModified).toBe('2024-02-01T12:00:00Z');
      expect(updatedItem.Item?.modifiedBy).toBe('new-admin');
    });

    it('should handle partial batch failure when some controls have version conflicts', async () => {
      // ARRANGE
      const controlItems = [
        {
          controlId: 'S3.1',
          description: 'S3 control',
          automatedRemediationEnabled: false,
          filterMode: 'include',
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        },
        {
          controlId: 'EC2.1',
          description: 'EC2 control',
          automatedRemediationEnabled: false,
          filterMode: 'include',
          version: 5,
          lastModified: '2024-01-01T00:00:00Z',
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

      const controlsToUpdate = [
        {
          controlId: 'S3.1',
          description: 'S3 control',
          automatedRemediationEnabled: true,
          filters: [],
          filterMode: 'include' as const,
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        },
        {
          controlId: 'EC2.1',
          description: 'EC2 control',
          automatedRemediationEnabled: true,
          filters: [],
          filterMode: 'include' as const,
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        },
      ];

      // ACT
      const result = await repository.bulkUpdateControls(controlsToUpdate, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      // Both controls are in the same transaction batch, so if one fails, the entire batch fails
      expect(result.successCount).toBe(0);
      expect(result.failedControlIds).toContain('S3.1');
      expect(result.failedControlIds).toContain('EC2.1');
    });
  });

  describe('applyFilterToAllControls', () => {
    it('should apply filter to all controls successfully', async () => {
      // ARRANGE
      const controlItems = [
        {
          controlId: 'S3.1',
          description: 'S3 control',
          automatedRemediationEnabled: false,
          filterMode: 'include',
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        },
        {
          controlId: 'EC2.1',
          description: 'EC2 control',
          automatedRemediationEnabled: true,
          filterMode: 'exclude',
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
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

      const filterId = '550e8400-e29b-41d4-a716-446655440000';

      // ACT
      const result = await repository.applyFilterToAllControls(filterId, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(2);
      expect(result.failedControlIds).toHaveLength(0);

      const s3Control = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(s3Control.Item?.filters).toBeInstanceOf(Set);
      expect(Array.from(s3Control.Item?.filters as Set<string>)).toContain(filterId);
      expect(s3Control.Item?.version).toBe(2);
      expect(s3Control.Item?.modifiedBy).toBe('admin-user');

      const ec2Control = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'EC2.1' },
        }),
      );
      expect(ec2Control.Item?.filters).toBeInstanceOf(Set);
      expect(Array.from(ec2Control.Item?.filters as Set<string>)).toContain(filterId);
      expect(ec2Control.Item?.version).toBe(2);
    });

    it('should return zero updates when no controls exist', async () => {
      // ARRANGE - empty table
      const filterId = '550e8400-e29b-41d4-a716-446655440000';

      // ACT
      const result = await repository.applyFilterToAllControls(filterId, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(0);
      expect(result.failedControlIds).toHaveLength(0);
    });

    it('should add filter to controls that already have existing filters', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 control',
        automatedRemediationEnabled: true,
        filters: new Set(['existing-filter-1', 'existing-filter-2']),
        filterMode: 'include',
        version: 1,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      const newFilterId = '550e8400-e29b-41d4-a716-446655440000';

      // ACT
      const result = await repository.applyFilterToAllControls(newFilterId, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(1);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      const filters = Array.from(updatedItem.Item?.filters as Set<string>).sort();
      expect(filters).toEqual(['550e8400-e29b-41d4-a716-446655440000', 'existing-filter-1', 'existing-filter-2']);
    });

    it('should be idempotent when applying the same filter twice', async () => {
      // ARRANGE
      const filterId = '550e8400-e29b-41d4-a716-446655440000';
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 control',
        automatedRemediationEnabled: true,
        filters: new Set([filterId]),
        filterMode: 'include',
        version: 1,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      // ACT
      const result = await repository.applyFilterToAllControls(filterId, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(1);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      const filters = Array.from(updatedItem.Item?.filters as Set<string>);
      expect(filters).toEqual([filterId]);
      expect(updatedItem.Item?.version).toBe(2);
    });

    it('should preserve other control attributes when applying filter', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 Block Public Access',
        automatedRemediationEnabled: true,
        filterMode: 'exclude',
        version: 3,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'previous-user',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      const filterId = '550e8400-e29b-41d4-a716-446655440000';

      // ACT
      const result = await repository.applyFilterToAllControls(filterId, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(1);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(updatedItem.Item?.description).toBe('S3 Block Public Access');
      expect(updatedItem.Item?.automatedRemediationEnabled).toBe(true);
      expect(updatedItem.Item?.filterMode).toBe('exclude');
      expect(updatedItem.Item?.version).toBe(4);
      expect(updatedItem.Item?.modifiedBy).toBe('admin-user');
      expect(updatedItem.Item?.lastModified).toBe('2024-01-15T10:00:00Z');
    });

    it('should handle controls with higher version numbers', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 control',
        automatedRemediationEnabled: false,
        filterMode: 'include',
        version: 10,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      const filterId = '550e8400-e29b-41d4-a716-446655440000';

      // ACT
      const result = await repository.applyFilterToAllControls(filterId, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(1);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(updatedItem.Item?.version).toBe(11);
    });

    it('should handle batch splitting when updating more than 100 controls', async () => {
      // ARRANGE
      const controlCount = 150;

      for (let i = 1; i <= controlCount; i++) {
        const controlItem = {
          controlId: `CTRL.${i}`,
          description: `Control ${i}`,
          automatedRemediationEnabled: false,
          filterMode: 'include',
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        };
        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: remediationConfigTableName,
            Item: controlItem,
          }),
        );
      }

      const filterId = '550e8400-e29b-41d4-a716-446655440000';

      // ACT
      const result = await repository.applyFilterToAllControls(filterId, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(controlCount);
      expect(result.failedControlIds).toHaveLength(0);

      const firstControl = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'CTRL.1' },
        }),
      );
      expect(firstControl.Item?.filters).toBeInstanceOf(Set);
      expect(Array.from(firstControl.Item?.filters as Set<string>)).toContain(filterId);

      const lastControl = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: `CTRL.${controlCount}` },
        }),
      );
      expect(lastControl.Item?.filters).toBeInstanceOf(Set);
      expect(Array.from(lastControl.Item?.filters as Set<string>)).toContain(filterId);
    });

    it('should handle controls with undefined version by defaulting to 1', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 control',
        automatedRemediationEnabled: false,
        filterMode: 'include',
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      const filterId = '550e8400-e29b-41d4-a716-446655440000';

      // ACT
      const result = await repository.applyFilterToAllControls(filterId, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(1);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(updatedItem.Item?.version).toBe(2);
    });

    it('should handle mixed controls with and without version attribute', async () => {
      // ARRANGE
      const controlWithVersion = {
        controlId: 'S3.1',
        description: 'S3 control with version',
        automatedRemediationEnabled: false,
        filterMode: 'include',
        version: 3,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      const controlWithoutVersion = {
        controlId: 'EC2.1',
        description: 'EC2 control without version',
        automatedRemediationEnabled: true,
        filterMode: 'exclude',
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await Promise.all([
        dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: remediationConfigTableName,
            Item: controlWithVersion,
          }),
        ),
        dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: remediationConfigTableName,
            Item: controlWithoutVersion,
          }),
        ),
      ]);

      const filterId = '550e8400-e29b-41d4-a716-446655440000';

      // ACT
      const result = await repository.applyFilterToAllControls(filterId, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(2);
      expect(result.failedControlIds).toHaveLength(0);

      const s3Control = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(s3Control.Item?.version).toBe(4);
      expect(Array.from(s3Control.Item?.filters as Set<string>)).toContain(filterId);

      const ec2Control = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'EC2.1' },
        }),
      );
      expect(ec2Control.Item?.version).toBe(2);
      expect(Array.from(ec2Control.Item?.filters as Set<string>)).toContain(filterId);
    });

    it('should add filter to control without version and preserve existing filters', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 control',
        automatedRemediationEnabled: false,
        filters: new Set(['existing-filter']),
        filterMode: 'include',
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      const newFilterId = '550e8400-e29b-41d4-a716-446655440000';

      // ACT
      const result = await repository.applyFilterToAllControls(newFilterId, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(1);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      const filters = Array.from(updatedItem.Item?.filters as Set<string>).sort();
      expect(filters).toEqual(['550e8400-e29b-41d4-a716-446655440000', 'existing-filter']);
      expect(updatedItem.Item?.version).toBe(2);
    });

    it('should not allow version mismatch even when attribute_not_exists condition is present', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 control',
        automatedRemediationEnabled: false,
        filterMode: 'include',
        version: 5,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      // Simulate concurrent modification by updating the control after scan but before transaction
      const filterId = '550e8400-e29b-41d4-a716-446655440000';

      // First apply succeeds
      const result1 = await repository.applyFilterToAllControls(filterId, 'admin-user', '2024-01-15T10:00:00Z');
      expect(result1.successCount).toBe(1);

      // Second apply with same filter should still succeed (idempotent ADD operation)
      // but version will increment
      const result2 = await repository.applyFilterToAllControls(filterId, 'admin-user', '2024-01-15T11:00:00Z');
      expect(result2.successCount).toBe(1);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(updatedItem.Item?.version).toBe(7);
    });
  });

  describe('removeFilterFromAllControls', () => {
    it('should remove filter from all controls successfully', async () => {
      // ARRANGE
      const filterId = '550e8400-e29b-41d4-a716-446655440000';
      const controlItems = [
        {
          controlId: 'S3.1',
          description: 'S3 control',
          automatedRemediationEnabled: false,
          filters: new Set([filterId, 'other-filter']),
          filterMode: 'include',
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        },
        {
          controlId: 'EC2.1',
          description: 'EC2 control',
          automatedRemediationEnabled: true,
          filters: new Set([filterId]),
          filterMode: 'exclude',
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
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
      const result = await repository.removeFilterFromAllControls(filterId, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(2);
      expect(result.failedControlIds).toHaveLength(0);

      const s3Control = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(Array.from(s3Control.Item?.filters as Set<string>)).not.toContain(filterId);
      expect(Array.from(s3Control.Item?.filters as Set<string>)).toContain('other-filter');
      expect(s3Control.Item?.version).toBe(2);
      expect(s3Control.Item?.modifiedBy).toBe('admin-user');

      const ec2Control = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'EC2.1' },
        }),
      );
      // When all filters are removed, the filters attribute may be empty or undefined
      const ec2Filters = ec2Control.Item?.filters;
      if (ec2Filters) {
        expect(Array.from(ec2Filters as Set<string>)).not.toContain(filterId);
      }
      expect(ec2Control.Item?.version).toBe(2);
    });

    it('should return zero updates when no controls exist', async () => {
      // ARRANGE - empty table
      const filterId = '550e8400-e29b-41d4-a716-446655440000';

      // ACT
      const result = await repository.removeFilterFromAllControls(filterId, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(0);
      expect(result.failedControlIds).toHaveLength(0);
    });

    it('should be idempotent when removing a filter that does not exist on controls', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 control',
        automatedRemediationEnabled: true,
        filters: new Set(['existing-filter']),
        filterMode: 'include',
        version: 1,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      const nonExistentFilterId = 'non-existent-filter-uuid';

      // ACT
      const result = await repository.removeFilterFromAllControls(
        nonExistentFilterId,
        'admin-user',
        '2024-01-15T10:00:00Z',
      );

      // ASSERT
      expect(result.successCount).toBe(1);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      const filters = Array.from(updatedItem.Item?.filters as Set<string>);
      expect(filters).toEqual(['existing-filter']);
      expect(updatedItem.Item?.version).toBe(2);
    });

    it('should preserve other control attributes when removing filter', async () => {
      // ARRANGE
      const filterId = '550e8400-e29b-41d4-a716-446655440000';
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 Block Public Access',
        automatedRemediationEnabled: true,
        filters: new Set([filterId, 'other-filter']),
        filterMode: 'exclude',
        version: 3,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'previous-user',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      // ACT
      const result = await repository.removeFilterFromAllControls(filterId, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(1);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(updatedItem.Item?.description).toBe('S3 Block Public Access');
      expect(updatedItem.Item?.automatedRemediationEnabled).toBe(true);
      expect(updatedItem.Item?.filterMode).toBe('exclude');
      expect(updatedItem.Item?.version).toBe(4);
      expect(updatedItem.Item?.modifiedBy).toBe('admin-user');
      expect(updatedItem.Item?.lastModified).toBe('2024-01-15T10:00:00Z');
    });

    it('should handle controls without any filters attribute', async () => {
      // ARRANGE
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 control',
        automatedRemediationEnabled: false,
        filterMode: 'include',
        version: 1,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      const filterId = '550e8400-e29b-41d4-a716-446655440000';

      // ACT
      const result = await repository.removeFilterFromAllControls(filterId, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(1);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(updatedItem.Item?.version).toBe(2);
    });

    it('should handle batch splitting when removing filter from more than 100 controls', async () => {
      // ARRANGE
      const controlCount = 150;
      const filterId = '550e8400-e29b-41d4-a716-446655440000';

      for (let i = 1; i <= controlCount; i++) {
        const controlItem = {
          controlId: `CTRL.${i}`,
          description: `Control ${i}`,
          automatedRemediationEnabled: false,
          filters: new Set([filterId, 'other-filter']),
          filterMode: 'include',
          version: 1,
          lastModified: '2024-01-01T00:00:00Z',
          modifiedBy: 'system',
        };
        await dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: remediationConfigTableName,
            Item: controlItem,
          }),
        );
      }

      // ACT
      const result = await repository.removeFilterFromAllControls(filterId, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(controlCount);
      expect(result.failedControlIds).toHaveLength(0);

      const firstControl = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'CTRL.1' },
        }),
      );
      expect(Array.from(firstControl.Item?.filters as Set<string>)).not.toContain(filterId);
      expect(Array.from(firstControl.Item?.filters as Set<string>)).toContain('other-filter');

      const lastControl = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: `CTRL.${controlCount}` },
        }),
      );
      expect(Array.from(lastControl.Item?.filters as Set<string>)).not.toContain(filterId);
      expect(Array.from(lastControl.Item?.filters as Set<string>)).toContain('other-filter');
    });

    it('should handle controls with undefined version by defaulting to 1', async () => {
      // ARRANGE
      const filterId = '550e8400-e29b-41d4-a716-446655440000';
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 control',
        automatedRemediationEnabled: false,
        filters: new Set([filterId]),
        filterMode: 'include',
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      // ACT
      const result = await repository.removeFilterFromAllControls(filterId, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(1);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(updatedItem.Item?.version).toBe(2);
    });

    it('should handle mixed controls with and without version attribute', async () => {
      // ARRANGE
      const filterId = '550e8400-e29b-41d4-a716-446655440000';
      const controlWithVersion = {
        controlId: 'S3.1',
        description: 'S3 control with version',
        automatedRemediationEnabled: false,
        filters: new Set([filterId]),
        filterMode: 'include',
        version: 3,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      const controlWithoutVersion = {
        controlId: 'EC2.1',
        description: 'EC2 control without version',
        automatedRemediationEnabled: true,
        filters: new Set([filterId, 'other-filter']),
        filterMode: 'exclude',
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await Promise.all([
        dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: remediationConfigTableName,
            Item: controlWithVersion,
          }),
        ),
        dynamoDBDocumentClient.send(
          new PutCommand({
            TableName: remediationConfigTableName,
            Item: controlWithoutVersion,
          }),
        ),
      ]);

      // ACT
      const result = await repository.removeFilterFromAllControls(filterId, 'admin-user', '2024-01-15T10:00:00Z');

      // ASSERT
      expect(result.successCount).toBe(2);
      expect(result.failedControlIds).toHaveLength(0);

      const s3Control = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(s3Control.Item?.version).toBe(4);

      const ec2Control = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'EC2.1' },
        }),
      );
      expect(ec2Control.Item?.version).toBe(2);
      expect(Array.from(ec2Control.Item?.filters as Set<string>)).toContain('other-filter');
      expect(Array.from(ec2Control.Item?.filters as Set<string>)).not.toContain(filterId);
    });

    it('should be idempotent when removing the same filter twice', async () => {
      // ARRANGE
      const filterId = '550e8400-e29b-41d4-a716-446655440000';
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 control',
        automatedRemediationEnabled: true,
        filters: new Set([filterId, 'other-filter']),
        filterMode: 'include',
        version: 1,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'system',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      // ACT - First removal
      const result1 = await repository.removeFilterFromAllControls(filterId, 'admin-user', '2024-01-15T10:00:00Z');
      expect(result1.successCount).toBe(1);

      // ACT - Second removal (filter already removed)
      const result2 = await repository.removeFilterFromAllControls(filterId, 'admin-user', '2024-01-15T11:00:00Z');
      expect(result2.successCount).toBe(1);

      // ASSERT
      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(updatedItem.Item?.version).toBe(3);
      expect(Array.from(updatedItem.Item?.filters as Set<string>)).toEqual(['other-filter']);
    });

    it('should update lastModified and modifiedBy correctly', async () => {
      // ARRANGE
      const filterId = '550e8400-e29b-41d4-a716-446655440000';
      const controlItem = {
        controlId: 'S3.1',
        description: 'S3 control',
        automatedRemediationEnabled: true,
        filters: new Set([filterId]),
        filterMode: 'include',
        version: 1,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'original-user',
      };

      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: controlItem,
        }),
      );

      // ACT
      const result = await repository.removeFilterFromAllControls(filterId, 'new-admin', '2024-02-15T15:30:00Z');

      // ASSERT
      expect(result.successCount).toBe(1);

      const updatedItem = await dynamoDBDocumentClient.send(
        new GetCommand({
          TableName: remediationConfigTableName,
          Key: { controlId: 'S3.1' },
        }),
      );
      expect(updatedItem.Item?.lastModified).toBe('2024-02-15T15:30:00Z');
      expect(updatedItem.Item?.modifiedBy).toBe('new-admin');
    });
  });

  describe('batchFindByIds', () => {
    const insertControl = async (controlId: string) =>
      dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: {
            controlId,
            description: `Description for ${controlId}`,
            automatedRemediationEnabled: false,
            filters: new Set(['none']),
            filterMode: 'include',
            version: 1,
            lastModified: '2024-01-01T00:00:00Z',
            modifiedBy: 'admin',
          },
        }),
      );

    it('should return empty result when input list is empty', async () => {
      const result = await repository.batchFindByIds([]);
      expect(result).toEqual({ foundControlIds: [], isComplete: true });
    });

    it('should return only controlIds that exist in the table', async () => {
      await insertControl('S3.1');
      await insertControl('EC2.6');

      const result = await repository.batchFindByIds(['S3.1', 'EC2.6', 'MISSING.1']);

      expect(result.isComplete).toBe(true);
      expect(result.foundControlIds.sort()).toEqual(['EC2.6', 'S3.1']);
    });

    it('should deduplicate input controlIds before querying DynamoDB', async () => {
      await insertControl('S3.1');

      const result = await repository.batchFindByIds(['S3.1', 'S3.1', 'S3.1']);

      expect(result.foundControlIds).toEqual(['S3.1']);
    });

    it('should return an empty foundControlIds list when none of the inputs exist', async () => {
      const result = await repository.batchFindByIds(['MISSING.1', 'MISSING.2']);

      expect(result).toEqual({ foundControlIds: [], isComplete: true });
    });
  });

  describe('findRemediationStateByControlIds', () => {
    const insertControl = async (controlId: string, automatedRemediationEnabled: boolean) =>
      dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: {
            controlId,
            description: `Description for ${controlId}`,
            automatedRemediationEnabled,
            filters: new Set(['none']),
            filterMode: 'include',
            version: 1,
            lastModified: '2024-01-01T00:00:00Z',
            modifiedBy: 'admin',
          },
        }),
      );

    it('returns an empty map when input list is empty', async () => {
      // ARRANGE / ACT
      const result = await repository.findRemediationStateByControlIds([]);

      // ASSERT
      expect(result.size).toBe(0);
    });

    it('maps each requested control to its current remediation state', async () => {
      // ARRANGE
      await insertControl('S3.1', true);
      await insertControl('EC2.6', false);

      // ACT
      const result = await repository.findRemediationStateByControlIds(['S3.1', 'EC2.6']);

      // ASSERT
      expect(result.get('S3.1')).toBe(true);
      expect(result.get('EC2.6')).toBe(false);
    });

    it('omits controls that do not exist and deduplicates input ids', async () => {
      // ARRANGE
      await insertControl('S3.1', true);

      // ACT
      const result = await repository.findRemediationStateByControlIds(['S3.1', 'S3.1', 'MISSING.1']);

      // ASSERT
      expect(result.size).toBe(1);
      expect(result.get('S3.1')).toBe(true);
      expect(result.has('MISSING.1')).toBe(false);
    });
  });
});
