// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';
import { ROLLBACK_ELIGIBLE_FINDING_TYPES } from '@asr/data-models';

interface BranchChoice {
  NextStep: string;
  Variable: string;
  StringEquals?: string;
}

interface DocumentStep {
  name: string;
  action: string;
  isEnd?: boolean;
  onFailure?: string;
  inputs?: {
    Choices?: BranchChoice[];
    Default?: string;
    RuntimeParameters?: Record<string, unknown>;
    DocumentName?: string;
    InputPayload?: Record<string, unknown>;
  };
  outputs?: { Name: string }[];
}

function isStepList(value: unknown): value is DocumentStep[] {
  return (
    Array.isArray(value) &&
    value.every((step) => typeof step === 'object' && step !== null && 'name' in step && 'action' in step)
  );
}

function loadSteps(documentRelPath: string): DocumentStep[] {
  const document = path.join(__dirname, '..', 'playbooks', documentRelPath);
  const parsed: unknown = yaml.load(fs.readFileSync(document, 'utf8'));
  if (typeof parsed !== 'object' || parsed === null || !('mainSteps' in parsed)) {
    throw new Error(`${document}: expected an SSM document object with mainSteps`);
  }
  const { mainSteps } = parsed;
  if (!isStepList(mainSteps)) {
    throw new Error(`${document}: mainSteps is not a list of steps`);
  }
  return mainSteps;
}

const PLAYBOOKS_DIR = path.join(__dirname, '..', 'playbooks');
const afsbpSsmdocsDir = path.join(PLAYBOOKS_DIR, 'AFSBP', 'ssmdocs');
const afsbpRollbackControls = [...ROLLBACK_ELIGIBLE_FINDING_TYPES]
  .filter((control) => fs.existsSync(path.join(afsbpSsmdocsDir, `AFSBP_${control}.yaml`)))
  .sort();

const REMEDIATION_TO_CONTROL: Record<string, string> = {
  'ASR-EnableKeyRotation': 'KMS.4',
};

/**
 * Discovers rollback-capable SSM playbooks within a given security standard
 * and returns metadata (label, document path, control ID) for each. A playbook
 * is rollback-capable when its Remediation step forwards the Rollback parameter.
 */
function findRollbackCapablePlaybooks(standard: string): { label: string; document: string; control: string }[] {
  const ssmdocsDir = path.join(PLAYBOOKS_DIR, standard, 'ssmdocs');
  if (!fs.existsSync(ssmdocsDir)) return [];

  const results: { label: string; document: string; control: string }[] = [];
  for (const file of fs.readdirSync(ssmdocsDir)) {
    if (!file.endsWith('.yaml')) continue;

    const document = `${standard}/ssmdocs/${file}`;
    const remediation = loadSteps(document).find((step) => step.name === 'Remediation');
    // Gate: only playbooks that forward Rollback to a rollback-capable remediation runbook.
    if (remediation?.inputs?.RuntimeParameters?.Rollback !== '{{Rollback}}') continue;

    const documentName = remediation.inputs?.DocumentName ?? '';
    const control = REMEDIATION_TO_CONTROL[documentName] ?? '';
    if (!control) {
      console.warn(
        `static-playbook rollback scan: no REMEDIATION_TO_CONTROL mapping for '${documentName}' (${document})`,
      );
    }

    results.push({
      label: `${standard}_${file.replace(/\.yaml$/, '')} (${control})`,
      document,
      control,
    });
  }

  return results.sort((a, b) => a.document.localeCompare(b.document));
}

const NON_AFSBP_STATIC_STANDARDS = fs
  .readdirSync(PLAYBOOKS_DIR, { withFileTypes: true })
  .filter((entry) => entry.isDirectory() && entry.name !== 'AFSBP')
  .map((entry) => entry.name)
  .sort();

const STATIC_ROLLBACK_PLAYBOOKS: { label: string; document: string; control: string }[] = [
  ...afsbpRollbackControls.map((control) => ({
    label: `AFSBP_${control}`,
    document: `AFSBP/ssmdocs/AFSBP_${control}.yaml`,
    control,
  })),
  ...NON_AFSBP_STATIC_STANDARDS.flatMap(findRollbackCapablePlaybooks),
];

describe('rollback eligibility guards', () => {
  const ROLLBACK_CONTROLS_WITHOUT_STATIC_PLAYBOOK = new Set(['GuardDuty.IAMUser']);
  it('represents every snapshot-rollback-eligible control in a static playbook entry', () => {
    const coveredControls = new Set(STATIC_ROLLBACK_PLAYBOOKS.map((p) => p.control));
    for (const control of ROLLBACK_ELIGIBLE_FINDING_TYPES) {
      if (ROLLBACK_CONTROLS_WITHOUT_STATIC_PLAYBOOK.has(control)) continue;
      expect(coveredControls.has(control)).toBe(true);
    }
  });

  const EXPECTED_ROLLBACK_ELIGIBLE_CONTROLS = [
    'GuardDuty.IAMUser',
    'KMS.4',
    'SNS.1',
    'RDS.6',
    'RDS.7',
    'RDS.8',
    'RDS.13',
    'RDS.16',
    'ElastiCache.1',
    'ElastiCache.2',
    'DynamoDB.6',
    'SSM.7',
    'S3.6',
    'SecretsManager.3',
  ].sort();
  it('ROLLBACK_ELIGIBLE_FINDING_TYPES matches the expected set (catches an accidental add/remove)', () => {
    expect([...ROLLBACK_ELIGIBLE_FINDING_TYPES].sort()).toEqual(EXPECTED_ROLLBACK_ELIGIBLE_CONTROLS);
  });

  it('resolves a known control for every discovered static playbook', () => {
    const unmapped = STATIC_ROLLBACK_PLAYBOOKS.filter((p) => !p.control).map((p) => p.document);
    expect(unmapped).toEqual([]);
  });
});

describe.each(STATIC_ROLLBACK_PLAYBOOKS)('$label rollback path', ({ document }) => {
  it('routes the rollback path away from UpdateFinding to a terminating step', () => {
    const steps = loadSteps(document);
    const branch = steps.find((s) => s.name === 'CheckRollback');
    expect(branch).toBeDefined();
    expect(branch?.action).toStrictEqual('aws:branch');

    const choice = branch?.inputs?.Choices?.find((c) => c.StringEquals === 'ROLLBACK');
    expect(choice).toBeDefined();
    expect(choice?.Variable).toStrictEqual('{{Rollback}}');
    expect(branch?.inputs?.Default).toStrictEqual('UpdateFinding');
    expect(choice?.NextStep).toStrictEqual('GetRemediationDetails');

    // The branch target must exist and terminate, or SSM would fall through into UpdateFinding anyway.
    const target = steps.find((s) => s.name === choice?.NextStep);
    expect(target).toBeDefined();
    expect(target?.isEnd).toStrictEqual(true);
  });

  it('forwards every rollback parameter the Orchestrator sends to the remediation runbook', () => {
    const remediation = loadSteps(document).find((s) => s.name === 'Remediation');
    expect(remediation?.inputs?.RuntimeParameters).toMatchObject({
      Rollback: '{{Rollback}}',
      ExecutionId: '{{ExecutionId}}',
      RemediationConfigBucket: '{{RemediationConfigBucket}}',
      SnapshotVersionId: '{{SnapshotVersionId}}',
      ControlExecutionId: '{{automation:EXECUTION_ID}}',
    });
  });

  it('runs the branch after Remediation and before UpdateFinding', () => {
    const names = loadSteps(document).map((s) => s.name);
    expect(names.indexOf('CheckRollback')).toBeGreaterThan(names.indexOf('Remediation'));
    expect(names.indexOf('CheckRollback')).toBeLessThan(names.indexOf('UpdateFinding'));
  });

  it('falls the remediation path through UpdateFinding to the terminal GetRemediationDetails step', () => {
    const steps = loadSteps(document);
    expect(steps.find((s) => s.name === 'UpdateFinding')?.isEnd).not.toStrictEqual(true);
    expect(steps.find((s) => s.name === 'RollbackComplete')).toBeUndefined();
    const last = steps[steps.length - 1];
    expect(last.name).toStrictEqual('GetRemediationDetails');
    expect(last.isEnd).toStrictEqual(true);
  });

  it('surfaces the child execution snapshot details via GetRemediationDetails', () => {
    const steps = loadSteps(document);
    const grd = steps.find((s) => s.name === 'GetRemediationDetails');
    expect(grd?.action).toStrictEqual('aws:executeScript');
    expect(grd?.inputs?.InputPayload?.execution_id).toStrictEqual('{{Remediation.ExecutionId}}');
    const outputNames = (grd?.outputs ?? []).map((o) => o.Name);
    expect(outputNames).toEqual(expect.arrayContaining(['Output', 'FailureMessage']));

    const remediation = steps.find((s) => s.name === 'Remediation');
    expect(remediation?.onFailure).toStrictEqual('step:GetRemediationDetails');
  });
});
