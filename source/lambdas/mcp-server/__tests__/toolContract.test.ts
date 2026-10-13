// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  matchesToolPattern,
  isToolAllowedForGroups,
  resolveUserToolAccess,
  tierForGroups,
  ACCOUNT_OPERATOR_TOOLS,
  AUTHOR_TOOLS,
  ADMIN_TOOLS,
  TOOL_CONTRACTS,
  TestRunbookYamlSchema,
  UpdateControlsToolSchema,
  categoryForTool,
  toBulkEditApiBody,
} from '../contract/toolContract';
import { ValidationError } from '../backends/common/errors';

describe('matchesToolPattern', () => {
  test('a bare "*" matches every tool name', () => {
    expect(matchesToolPattern('list_runbooks', '*')).toBe(true);
    expect(matchesToolPattern('execute_runbook', '*')).toBe(true);
  });

  test('a trailing "*" matches by prefix', () => {
    expect(matchesToolPattern('list_runbooks', 'list_*')).toBe(true);
    expect(matchesToolPattern('list_findings_without_runbook', 'list_*')).toBe(true);
    expect(matchesToolPattern('get_runbook', 'list_*')).toBe(false);
  });

  test('a "*" anywhere other than the end is a literal character, not a wildcard', () => {
    // Per the documented contract: "A `*` anywhere other than the end is
    // treated as a literal character (no mid/leading wildcard support)".
    expect(matchesToolPattern('list_runbooks', '*_runbooks')).toBe(false);
    expect(matchesToolPattern('list_runbooks', 'list_*_extra')).toBe(false);
  });

  test('no wildcard requires an exact match', () => {
    expect(matchesToolPattern('list_runbooks', 'list_runbooks')).toBe(true);
    expect(matchesToolPattern('list_runbooks', 'list_runbook')).toBe(false);
    expect(matchesToolPattern('list_runbooks', 'LIST_RUNBOOKS')).toBe(false);
  });

  test('empty pattern matches nothing but an empty tool name', () => {
    expect(matchesToolPattern('list_runbooks', '')).toBe(false);
    expect(matchesToolPattern('', '')).toBe(true);
  });
});

describe('tierForGroups', () => {
  test('resolves the highest tier across multiple groups', () => {
    expect(tierForGroups(['AccountOperatorGroup', 'AdminGroup'])).toBe('Admin');
  });

  test('an unmapped or empty group set has no access tier', () => {
    expect(tierForGroups([])).toBeUndefined();
    expect(tierForGroups(['SomeUnknownGroup'])).toBeUndefined();
    expect(tierForGroups(['SecurityEngineerGroup'])).toBeUndefined();
  });

  test('maps each shipped group to its distinct authorization tier', () => {
    expect(tierForGroups(['AdminGroup'])).toBe('Admin');
    expect(tierForGroups(['DelegatedAdminGroup'])).toBe('DelegatedAdmin');
    expect(tierForGroups(['AccountOperatorGroup'])).toBe('AccountOperator');
  });
});

describe('isToolAllowedForGroups', () => {
  test('AccountOperator tier cannot call delegated administration tools', () => {
    expect(isToolAllowedForGroups('deploy_runbook', ['AccountOperatorGroup'])).toBe(false);
    expect(isToolAllowedForGroups('execute_runbook', ['AccountOperatorGroup'])).toBe(false);
    expect(isToolAllowedForGroups('update_controls', ['AccountOperatorGroup'])).toBe(false);
  });

  test('AccountOperator tier includes account-scoped UI actions', () => {
    expect(isToolAllowedForGroups('list_runbooks', ['AccountOperatorGroup'])).toBe(true);
    expect(isToolAllowedForGroups('execute_finding_action', ['AccountOperatorGroup'])).toBe(true);
    expect(isToolAllowedForGroups('create_notification', ['AccountOperatorGroup'])).toBe(true);
  });

  test('DelegatedAdmin and Admin tiers have the full capability ceiling', () => {
    expect(isToolAllowedForGroups('deploy_runbook', ['DelegatedAdminGroup'])).toBe(true);
    expect(isToolAllowedForGroups('execute_runbook', ['DelegatedAdminGroup'])).toBe(true);
    expect(isToolAllowedForGroups('update_controls', ['DelegatedAdminGroup'])).toBe(true);
    expect(isToolAllowedForGroups('deploy_runbook', ['AdminGroup'])).toBe(true);
  });

  test('unrecognized groups receive no capability floor', () => {
    expect(isToolAllowedForGroups('deploy_runbook', ['SecurityEngineerGroup'])).toBe(false);
    expect(isToolAllowedForGroups('list_runbooks', ['SecurityEngineerGroup'])).toBe(false);
    expect(isToolAllowedForGroups('list_runbooks', [])).toBe(false);
  });

  test('a declared but unadvertised tool is denied to every tier, including Admin', () => {
    // execute_rollback is defined in TOOL_CONTRACTS but absent from
    // toolSchema.json, so the gateway never exposes it and no tier grants it.
    // Admin being denied here is the point: an unreachable tool must not carry a
    // standing grant that a later change could silently activate.
    expect(isToolAllowedForGroups('execute_rollback', ['AdminGroup'])).toBe(false);
    expect(isToolAllowedForGroups('execute_rollback', ['AccountOperatorGroup'])).toBe(false);

    // preview_policy_change / apply_policy_change are the intent-based policy
    // placeholders: declared in TOOL_CONTRACTS for a future release, but absent
    // from toolSchema.json, routeless, and tierless. Pin them as denied to every
    // tier so the "placeholder, not dispatchable" contract is enforced, not just
    // documented — if a later change advertises one without adding a reviewed
    // tier, this fails.
    for (const placeholder of ['preview_policy_change', 'apply_policy_change']) {
      expect(isToolAllowedForGroups(placeholder, ['AdminGroup'])).toBe(false);
      expect(isToolAllowedForGroups(placeholder, ['DelegatedAdminGroup'])).toBe(false);
      expect(isToolAllowedForGroups(placeholder, ['AccountOperatorGroup'])).toBe(false);
    }
  });
});

describe('resolveUserToolAccess', () => {
  test('Admin receives every tier-allowed tool automatically', () => {
    expect(resolveUserToolAccess('execute_runbook', ['AdminGroup'], undefined)).toBe(true);
    expect(resolveUserToolAccess('execute_runbook', ['AdminGroup'], [])).toBe(true);
  });

  test('Delegated Admin requires an explicit per-user grant', () => {
    expect(resolveUserToolAccess('execute_runbook', ['DelegatedAdminGroup'], undefined)).toBe(false);
    expect(resolveUserToolAccess('execute_runbook', ['DelegatedAdminGroup'], [])).toBe(false);
    expect(resolveUserToolAccess('execute_runbook', ['DelegatedAdminGroup'], ['execute_runbook'])).toBe(true);
    expect(resolveUserToolAccess('execute_runbook', ['DelegatedAdminGroup'], ['execute_*'])).toBe(true);
  });

  test('Account Operator requires a grant that cannot widen its role ceiling', () => {
    expect(resolveUserToolAccess('list_runbooks', ['AccountOperatorGroup'], undefined)).toBe(false);
    expect(resolveUserToolAccess('list_runbooks', ['AccountOperatorGroup'], ['list_runbooks'])).toBe(true);
    expect(resolveUserToolAccess('execute_runbook', ['AccountOperatorGroup'], ['*'])).toBe(false);
  });
});

describe('tier lists are cumulative', () => {
  test('every ACCOUNT_OPERATOR_TOOLS entry is present in AUTHOR_TOOLS and ADMIN_TOOLS', () => {
    for (const toolName of ACCOUNT_OPERATOR_TOOLS) {
      expect(AUTHOR_TOOLS).toContain(toolName);
      expect(ADMIN_TOOLS).toContain(toolName);
    }
  });

  test('every AUTHOR_TOOLS entry is present in ADMIN_TOOLS', () => {
    for (const toolName of AUTHOR_TOOLS) {
      expect(ADMIN_TOOLS).toContain(toolName);
    }
  });
});

describe('tool categories', () => {
  test('every grantable tool has a real category, never the Other fallback', () => {
    // The Web UI groups the grant list by category, so a tiered tool with no mapping
    // would land in the catch-all group. Categories are derived from the declared tool
    // groups; a tool that is tiered but declared only as a proxy route has to be named
    // in TOOLS_BY_CATEGORY explicitly, and this is what catches that omission.
    for (const toolName of ADMIN_TOOLS) {
      expect(categoryForTool(toolName)).not.toBe('Other');
    }
  });

  test('categorizes a tool by the declared group it belongs to', () => {
    expect(categoryForTool('findings')).toBe('Discovery');
    expect(categoryForTool('remediations')).toBe('Reporting');
    expect(categoryForTool('test_notification')).toBe('Notifications');
    expect(categoryForTool('deploy_runbook')).toBe('Infrastructure');
    expect(categoryForTool('update_controls')).toBe('Policy');
  });

  test('categorizes the two proxy-only tools that TOOL_CONTRACTS does not declare', () => {
    expect(TOOL_CONTRACTS).not.toHaveProperty('execute_finding_action');
    expect(TOOL_CONTRACTS).not.toHaveProperty('drift_detection');
    expect(categoryForTool('execute_finding_action')).toBe('Remediation');
    expect(categoryForTool('drift_detection')).toBe('Remediation');
  });

  test('falls back to Other for an unknown tool rather than throwing', () => {
    expect(categoryForTool('not_a_tool')).toBe('Other');
  });
});

describe('TOOL_CONTRACTS', () => {
  test('every contract has a schema and a description', () => {
    for (const [name, contract] of Object.entries(TOOL_CONTRACTS)) {
      expect(contract.name).toBe(name);
      expect(contract.description.length).toBeGreaterThan(0);
      expect(contract.schema).toBeDefined();
    }
  });
});

describe('TestRunbookYamlSchema', () => {
  const runbookYaml = 'schemaVersion: "0.3"\nmainSteps: []';

  test('requires runbook_id, version, and required_iam_actions as one recorded-test tuple', () => {
    const incomplete = TestRunbookYamlSchema.safeParse({
      runbook_yaml: runbookYaml,
      runbook_id: 'rb-1',
      version: 1,
    });

    expect(incomplete.success).toBe(false);
    if (!incomplete.success) {
      expect(incomplete.error.issues.map((issue) => issue.message).join(' ')).toMatch(/must be supplied together/);
    }
  });

  test('validates every requested IAM action before a role can be provisioned', () => {
    const unsafe = TestRunbookYamlSchema.safeParse({
      runbook_yaml: runbookYaml,
      runbook_id: 'rb-1',
      version: 1,
      required_iam_actions: ['iam:CreateRole'],
    });

    expect(unsafe.success).toBe(false);
    if (!unsafe.success) {
      expect(unsafe.error.issues).toEqual(
        expect.arrayContaining([expect.objectContaining({ path: ['required_iam_actions', 0] })]),
      );
    }
  });

  test('accepts a complete registered-version test and a tuple-free throwaway test', () => {
    expect(
      TestRunbookYamlSchema.safeParse({
        runbook_yaml: runbookYaml,
        runbook_id: '2d85d752-b86d-47bf-83cc-09c4b11408eb',
        version: 1,
        required_iam_actions: ['s3:PutBucketLogging'],
      }).success,
    ).toBe(true);
    expect(TestRunbookYamlSchema.safeParse({ runbook_yaml: runbookYaml }).success).toBe(true);
  });

  test('rejects a runbook_id that is not a UUID, which deploy_runbook could never accept', () => {
    // deploy_runbook validates runbook_id with RunbookIdSchema (z.uuid()). While this tool
    // took any string, a caller could earn a recorded PASSED test — provisioning a bounded
    // test role and running a real automation — for an id the deploy would then reject as
    // malformed. The two tools have to agree on what an id is.
    const result = TestRunbookYamlSchema.safeParse({
      runbook_yaml: runbookYaml,
      runbook_id: 'rb-1',
      version: 1,
      required_iam_actions: ['s3:PutBucketLogging'],
    });

    expect(result.success).toBe(false);
  });
});

describe('access tiers match the advertised tool surface', () => {
  // toolSchema.json is what the AgentCore Gateway advertises, so it is the set of
  // tools that can actually be invoked. Read it from disk rather than importing
  // it, so the test needs no resolveJsonModule and reads exactly the file the
  // build zips into the Lambda.
  const advertisedToolNames: readonly string[] = (() => {
    const raw = readFileSync(join(__dirname, '..', 'toolSchema.json'), 'utf8');
    const parsed: unknown = JSON.parse(raw);
    const entries = Array.isArray(parsed) ? parsed : ((parsed as { tools?: unknown[] }).tools ?? []);
    return entries.map((entry) => (entry as { name: string }).name);
  })();

  // ADMIN_TOOLS is the widest tier, so it is the union of everything grantable.
  test('every advertised tool has an access tier, so none is denied to all callers', () => {
    const untiered = advertisedToolNames.filter((name) => !ADMIN_TOOLS.includes(name));
    expect(untiered).toEqual([]);
  });

  // The direction that regressed: a tier entry for a tool the gateway does not
  // advertise is a standing grant on something unreachable. Harmless today, but it
  // means advertising that tool later activates the grant with no review of the
  // access decision. Fail here instead, and force the tier into the same change.
  test('every tiered tool is advertised, so no tier grants access to an unreachable tool', () => {
    const advertised = new Set(advertisedToolNames);
    const phantomGrants = ADMIN_TOOLS.filter((name) => !advertised.has(name));
    expect(phantomGrants).toEqual([]);
  });
});

// Name parity alone let the advertised bounds drift from what the Lambda enforces. A
// caller writes a request that satisfies the advertised schema and gets a validation
// error anyway — the schema is the contract, so a disagreement is the schema's bug.
// These pin the specific numbers and defaults that had drifted, against the Zod
// definitions that actually run.
describe('advertised parameter bounds match what the Lambda enforces', () => {
  const advertised = (() => {
    const raw = readFileSync(join(__dirname, '..', 'toolSchema.json'), 'utf8');
    const parsed: unknown = JSON.parse(raw);
    const entries = Array.isArray(parsed) ? parsed : ((parsed as { tools?: unknown[] }).tools ?? []);
    return entries as Array<{
      name: string;
      description?: string;
      inputSchema?: { properties?: Record<string, { description?: string }>; required?: string[] };
    }>;
  })();

  /** The advertised tool-level description — curated in toolSchema.json, not generated from Zod. */
  const describeTool = (toolName: string): string => {
    const tool = advertised.find((entry) => entry.name === toolName);
    expect(tool?.description).toBeDefined();
    return tool?.description ?? '';
  };

  const describeParam = (toolName: string, paramName: string): string => {
    const tool = advertised.find((entry) => entry.name === toolName);
    expect(tool).toBeDefined();
    const description = tool?.inputSchema?.properties?.[paramName]?.description;
    expect(description).toBeDefined();
    return description ?? '';
  };

  /** Every numeric bound a Zod schema enforces, so a test cannot assert a stale number. */
  const zodBound = (schemaName: string, method: 'min' | 'max'): number => {
    const contract = readFileSync(join(__dirname, '..', 'contract', 'toolContract.ts'), 'utf8');
    const start = contract.indexOf(`export const ${schemaName}`);
    expect(start).toBeGreaterThan(-1);
    const body = contract.slice(start, start + 4000);
    const match = body.match(new RegExp(`\\.${method}\\((\\d+)\\)`));
    expect(match).not.toBeNull();
    return Number(match?.[1]);
  };

  test('test_runbook_yaml advertises the runbook_yaml ceiling the Zod schema enforces', () => {
    // Advertised 200000 against a Zod .max(65536) — SSM's CreateDocument content
    // quota. A 70KB runbook passed the advertised schema and was then rejected.
    const enforcedMax = zodBound('TestRunbookYamlSchema', 'max');
    expect(enforcedMax).toBe(65536);
    expect(describeParam('test_runbook_yaml', 'runbook_yaml')).toContain(String(enforcedMax));
    expect(describeParam('test_runbook_yaml', 'runbook_yaml')).not.toContain('200000');
  });

  test('check_runbook_drift advertises the mutual exclusion its Zod refine enforces', () => {
    // `required` cannot express "exactly one of", so the refine is invisible to a
    // caller reading the schema: document_name alone satisfies it and still fails.
    for (const param of ['runbook_yaml', 'runbook_path']) {
      expect(describeParam('check_runbook_drift', param)).toMatch(/exactly one/i);
    }
  });

  test('check_deploy_readiness does not advertise a default its schema does not apply', () => {
    // Advertised "Default: as501" — a value nothing sets. Omitting namespace outside
    // the deployed server produced a confusing failure instead of the documented default.
    const description = describeParam('check_deploy_readiness', 'namespace');
    expect(description).not.toMatch(/as501/i);
    expect(description).toMatch(/no default/i);
  });

  test('automation_assume_role advertises the PassRole prefix and no phantom env fallback', () => {
    // The env var is deliberately unset on the deployed Lambda, so advertising it as a fallback gave
    // a remote caller advice they cannot act on — the same defect as the namespace default above.
    // The prefix constraint was undiscoverable, and violating it produced a raw IAM PassRole denial
    // reported inside an HTTP 200.
    const description = describeParam('test_remediation_script', 'automation_assume_role');
    expect(description).not.toMatch(/ASR_TEST_ASSUME_ROLE/);
    expect(description).toMatch(/no default/i);
    expect(description).toContain('SO0111-Remediate-Custom-Test-');
  });

  test('test_notification says a successful test does not evaluate the configuration filters', () => {
    // The synthetic event is delivered regardless of severityFilter/accountIds, so an operator whose
    // filters match nothing still sees a success in a real inbox and concludes it works.
    const description = describeTool('test_notification');
    expect(description).toMatch(/severityFilter/);
    expect(description).toMatch(/does not mean any real finding will match/i);
  });

  test('update_controls describes per-entry application, not batch atomicity', () => {
    // The repository re-drives the entries that were not at fault after a stale one is rejected,
    // so a caller can get a 207 after partial application. Promising "atomic per batch" told
    // them the opposite: that a 409 or 207 meant nothing had been written.
    const description = describeTool('update_controls');
    expect(description).toMatch(/version/i);
    expect(description).toMatch(/applied independently/i);
    expect(description).not.toMatch(/atomic/i);
    expect(description).toMatch(/failedControlIds/);
    expect(description).toMatch(/409 means none were/);
  });

  test('test_remediation_script advertises the optional document_name its schema accepts', () => {
    // Absent from the advertised schema, so a caller could not discover it.
    expect(describeParam('test_remediation_script', 'document_name')).toBeTruthy();
  });

  test('test_runbook_yaml advertises the IAM action set bound to its recorded pass', () => {
    const description = describeParam('test_runbook_yaml', 'required_iam_actions');
    expect(description).toMatch(/exact IAM actions/i);
    expect(description).toMatch(/deploy_runbook.*same set/i);
  });
});

describe('toBulkEditApiBody', () => {
  const filterId = '11111111-1111-4111-8111-111111111111';

  test('maps update to the controls array', () => {
    const args = UpdateControlsToolSchema.parse({
      operation: 'update',
      data: [
        {
          controlId: 'S3.1',
          description: 'S3 control',
          automatedRemediationEnabled: true,
          filters: [],
          filterMode: 'include',
          version: 1,
          lastModified: '2026-01-01T00:00:00Z',
          modifiedBy: 'admin',
        },
      ],
    });

    expect(toBulkEditApiBody(args)).toEqual({ operation: 'update', data: args.data });
  });

  test('maps the filter operations to the bare filter id the API expects', () => {
    const args = UpdateControlsToolSchema.parse({ operation: 'applyFilterToAll', filterId });

    expect(toBulkEditApiBody(args)).toEqual({ operation: 'applyFilterToAll', data: filterId });
  });

  test('the schema rejects the wrong-branch field instead of letting the mapper drop it', () => {
    // A caller who confuses the two payloads must hear about it; the mapper forwards only the
    // field its branch uses, so without this the supplied value would be ignored without a word.
    const withFilterOnUpdate = UpdateControlsToolSchema.safeParse({ operation: 'update', data: [], filterId });
    expect(withFilterOnUpdate.success).toBe(false);
    expect(withFilterOnUpdate.error?.issues.map((issue) => issue.message)).toContainEqual(
      expect.stringContaining('filterId is not valid for operation "update"'),
    );

    const withDataOnFilterOp = UpdateControlsToolSchema.safeParse({
      operation: 'removeFilterFromAll',
      filterId,
      data: [],
    });
    expect(withDataOnFilterOp.success).toBe(false);
    expect(withDataOnFilterOp.error?.issues.map((issue) => issue.message)).toContainEqual(
      expect.stringContaining('data is not valid for operation "removeFilterFromAll"'),
    );
  });

  test('the schema rejects a branch missing its field, and the mapper refuses it the same way', () => {
    // Parsed input can never reach the mapper without its field; the mapper's own guard is for a
    // caller that bypasses the schema, and it names the same requirement.
    expect(UpdateControlsToolSchema.safeParse({ operation: 'update' }).success).toBe(false);
    expect(UpdateControlsToolSchema.safeParse({ operation: 'removeFilterFromAll' }).success).toBe(false);
    expect(() => toBulkEditApiBody({ operation: 'update' })).toThrow(ValidationError);
    expect(() => toBulkEditApiBody({ operation: 'removeFilterFromAll' })).toThrow(
      'filterId is required for operation "removeFilterFromAll"',
    );
  });
});
