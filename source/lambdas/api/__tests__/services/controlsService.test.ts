// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Logger } from '@aws-lambda-powertools/logger';
import { DynamoDBDocumentClient, PutCommand } from '@aws-sdk/lib-dynamodb';
import { ControlsService } from '../../services/controlsService';
import { DynamoDBTestSetup } from '../../../common/__tests__/dynamodbSetup';
import { remediationConfigTableName } from '../../../common/__tests__/envSetup';

import * as metricsUtils from '../../../common/utils/metricsUtils';
import { AdminActivityNotifier } from '../../services/adminActivityNotifier';

jest.spyOn(metricsUtils, 'sendMetrics').mockResolvedValue(undefined);

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

  describe('processBulkEdit rollback toggle', () => {
    const actor = { actorEmail: 'admin@example.com', actorGroups: ['AdminGroup'] };

    function existing(controlId: string, rollbackEnabled: boolean | undefined) {
      return {
        controlId,
        description: `Description for ${controlId}`,
        automatedRemediationEnabled: true,
        ...(rollbackEnabled === undefined ? {} : { rollbackEnabled }),
        filterMode: 'include',
        version: 1,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'admin',
      };
    }

    function edit(controlId: string, rollbackEnabled: boolean) {
      return {
        controlId,
        description: `Description for ${controlId}`,
        automatedRemediationEnabled: true,
        rollbackEnabled,
        filters: [],
        filterMode: 'include' as const,
        version: 1,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'admin',
      };
    }

    async function seed(item: ReturnType<typeof existing>) {
      await dynamoDBDocumentClient.send(new PutCommand({ TableName: remediationConfigTableName, Item: item }));
    }

    it('notifies with CONTROL_ROLLBACK_SET when a control rollback is disabled', async () => {
      // ARRANGE
      await seed(existing('S3.6', true));
      const notify = jest.fn().mockResolvedValue(undefined);
      const service = new ControlsService(logger, undefined, { notify } as unknown as AdminActivityNotifier);

      // ACT
      await service.processBulkEdit({ operation: 'update', data: [edit('S3.6', false)] }, actor);

      // ASSERT
      expect(notify).toHaveBeenCalledWith(
        expect.objectContaining({ action: 'CONTROL_ROLLBACK_SET', affectedControlCount: 1 }),
      );
      expect(metricsUtils.sendMetrics).toHaveBeenCalledWith(
        expect.objectContaining({
          control_configuration_changes: expect.arrayContaining([expect.objectContaining({ rollback_enabled: false })]),
        }),
      );
    });

    it('notifies with CONTROL_ROLLBACK_ENABLED when a control rollback is enabled', async () => {
      await seed(existing('S3.6', false));
      const notify = jest.fn().mockResolvedValue(undefined);
      const service = new ControlsService(logger, undefined, { notify } as unknown as AdminActivityNotifier);

      await service.processBulkEdit({ operation: 'update', data: [edit('S3.6', true)] }, actor);

      expect(notify).toHaveBeenCalledWith(
        expect.objectContaining({ action: 'CONTROL_ROLLBACK_ENABLED', affectedControlCount: 1 }),
      );
    });

    it('does not send a rollback notification when the edit leaves rollback unchanged (absent stays enabled)', async () => {
      // A control stored without rollbackEnabled (enabled) edited to explicit true is not a change.
      await seed(existing('S3.6', undefined));
      const notify = jest.fn().mockResolvedValue(undefined);
      const service = new ControlsService(logger, undefined, { notify } as unknown as AdminActivityNotifier);

      await service.processBulkEdit({ operation: 'update', data: [edit('S3.6', true)] }, actor);

      const rollbackCalls = notify.mock.calls.filter((c) => String(c[0]?.action).startsWith('CONTROL_ROLLBACK'));
      expect(rollbackCalls).toHaveLength(0);
    });
  });

  // Custom runbooks run only on a manual trigger: resolve_ssm_doc_for_finding checks the
  // event type BEFORE it looks up the custom-runbook table, so a stored
  // automatedRemediationEnabled=true is honoured by the pre-processor (it triggers an
  // execution) and then ignored by the resolver (NOTFOUND). The console would read
  // "Enabled" while nothing is ever remediated, which is why the write is refused here
  // rather than only hidden in the Web UI — the MCP `update_controls` tool posts to this
  // same route.
  describe('processBulkEdit automated-remediation guard for custom runbooks', () => {
    const actor = { actorEmail: 'admin@example.com', actorGroups: ['AdminGroup'] };

    async function seedControl(
      controlId: string,
      source: 'builtin' | 'custom',
      automatedRemediationEnabled: boolean,
    ): Promise<void> {
      await dynamoDBDocumentClient.send(
        new PutCommand({
          TableName: remediationConfigTableName,
          Item: {
            controlId,
            description: `Description for ${controlId}`,
            automatedRemediationEnabled,
            filterMode: 'include',
            source,
            version: 1,
            lastModified: '2024-01-01T00:00:00Z',
            modifiedBy: 'admin',
          },
        }),
      );
    }

    function edit(controlId: string, automatedRemediationEnabled: boolean) {
      return {
        controlId,
        description: `Description for ${controlId}`,
        automatedRemediationEnabled,
        filters: [],
        filterMode: 'include' as const,
        version: 1,
        lastModified: '2024-01-01T00:00:00Z',
        modifiedBy: 'admin',
      };
    }

    const storedRemediationState = async (controlId: string): Promise<boolean | undefined> =>
      (await controlsService.getRemediationStateByControlIds([controlId])).get(controlId);

    it('refuses to enable automated remediation for a custom-runbook control', async () => {
      // ARRANGE
      await seedControl('MCPProbe.1', 'custom', false);

      // ACT
      const result = await controlsService.processBulkEdit(
        { operation: 'update', data: [edit('MCPProbe.1', true)] },
        actor,
      );

      // ASSERT — reported as rejected, and the stored flag is untouched. Asserting the
      // stored state matters: a result that says "rejected" while the row flipped anyway
      // would be the same defect wearing a different hat.
      expect(result.rejectedControlIds).toEqual(['MCPProbe.1']);
      expect(result.failedControlIds).toEqual(['MCPProbe.1']);
      expect(result.successCount).toBe(0);
      expect(await storedRemediationState('MCPProbe.1')).toBe(false);
    });

    it('still allows disabling automated remediation for a custom-runbook control', async () => {
      // A control switched on before this guard existed has to remain switchable off,
      // otherwise the guard traps it in the inconsistent state it was meant to prevent.
      await seedControl('MCPProbe.1', 'custom', true);

      const result = await controlsService.processBulkEdit(
        { operation: 'update', data: [edit('MCPProbe.1', false)] },
        actor,
      );

      expect(result.rejectedControlIds).toBeUndefined();
      expect(result.successCount).toBe(1);
      expect(await storedRemediationState('MCPProbe.1')).toBe(false);
    });

    it('allows editing an already-enabled custom control that resends automatedRemediationEnabled: true', async () => {
      // The UI resends the whole SecurityControl on save, so editing only the filters of a
      // custom control enabled before this guard existed still carries
      // automatedRemediationEnabled: true. That is not a false→true transition, so it must
      // not be rejected — otherwise the control is permanently uneditable.
      await seedControl('MCPProbe.1', 'custom', true);

      const result = await controlsService.processBulkEdit(
        {
          operation: 'update',
          data: [{ ...edit('MCPProbe.1', true), filters: ['some-filter-id'] }],
        },
        actor,
      );

      expect(result.rejectedControlIds).toBeUndefined();
      expect(result.failedControlIds).toEqual([]);
      expect(result.successCount).toBe(1);
      expect(await storedRemediationState('MCPProbe.1')).toBe(true);
    });

    it('still allows enabling automated remediation for a built-in control', async () => {
      await seedControl('S3.9', 'builtin', false);

      const result = await controlsService.processBulkEdit({ operation: 'update', data: [edit('S3.9', true)] }, actor);

      expect(result.rejectedControlIds).toBeUndefined();
      expect(result.successCount).toBe(1);
      expect(await storedRemediationState('S3.9')).toBe(true);
    });

    it('applies the built-in entries of a mixed batch and rejects only the custom one', async () => {
      // One custom control must not block a bulk edit over built-ins — the route already
      // reports per-control outcomes, so the refusal rides that contract.
      await seedControl('MCPProbe.1', 'custom', false);
      await seedControl('S3.9', 'builtin', false);

      const result = await controlsService.processBulkEdit(
        { operation: 'update', data: [edit('MCPProbe.1', true), edit('S3.9', true)] },
        actor,
      );

      expect(result.rejectedControlIds).toEqual(['MCPProbe.1']);
      expect(result.successCount).toBe(1);
      expect(await storedRemediationState('S3.9')).toBe(true);
      expect(await storedRemediationState('MCPProbe.1')).toBe(false);
    });
  });
});
