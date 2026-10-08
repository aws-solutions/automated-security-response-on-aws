// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import { App, DefaultStackSynthesizer, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import {
  SecurityControlsPlaybookMemberStack,
  SecurityControlsPlaybookPrimaryStack,
} from '../lib/security_controls_playbook-construct';
import { omitWaitResourceHash } from '../../../test/utils';
import { SC_REMEDIATIONS } from '../lib/sc_remediations';

function getPrimaryStack(): Stack {
  const app = new App();
  const stack = new SecurityControlsPlaybookPrimaryStack(app, 'stack', {
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    description: 'test;',
    solutionId: 'SO0111',
    resourceNamePrefix: 'SO0111',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'sharrbukkit',
    solutionDistName: 'automated-security-response-on-aws',
    remediations: [
      { control: 'Example.3', versionAdded: '2.1.0' },
      { control: 'Example.5', versionAdded: '2.2.0' },
      { control: 'Example.1', versionAdded: '2.2.1' },
    ],
    securityStandard: 'SC',
    securityStandardLongName: 'security-control',
    securityStandardVersion: '2.0.0',
  });
  return stack;
}

test('admin stack', () => {
  const stack = getPrimaryStack();
  const template = Template.fromStack(stack);

  const templateJSON = template.toJSON();
  omitWaitResourceHash(template, templateJSON);
  expect(templateJSON).toMatchSnapshot();
});

function getMemberStack(): Stack {
  const app = new App();
  const stack = new SecurityControlsPlaybookMemberStack(app, 'memberStack', {
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    description: 'test;',
    solutionId: 'SO0111',
    resourceNamePrefix: 'SO0111',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'sharrbukkit',
    ssmdocs: 'playbooks/NEWPLAYBOOK/ssmdocs',
    remediations: [
      { control: 'AutoScaling.1', versionAdded: '2.1.0' },
      { control: 'CloudTrail.5', versionAdded: '2.2.0' },
      { control: 'Config.1', versionAdded: '2.1.1' },
    ],
    securityStandard: 'PCI',
    securityStandardLongName: 'pci-dss',
    securityStandardVersion: '3.2.1',
    commonScripts: 'playbooks/common',
  });
  return stack;
}

test('member stack', () => {
  const stack = getMemberStack();
  const template = Template.fromStack(stack);

  const templateJSON = template.toJSON();
  omitWaitResourceHash(template, templateJSON);
  expect(templateJSON).toMatchSnapshot();
});

// Regression guard for the rollback-param gating: the control runbook must forward the rollback
// parameters ONLY for rollback-enabled controls. Forwarding them to a control whose remediation
// runbook does not declare them makes SSM reject StartAutomationExecution with "Undefined execution
// inputs" (all non-migrated controls broke on remediate before the gate was added).
function getGatingMemberStack(): Stack {
  const app = new App();
  return new SecurityControlsPlaybookMemberStack(app, 'gatingMemberStack', {
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    description: 'test;',
    solutionId: 'SO0111',
    resourceNamePrefix: 'SO0111',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'sharrbukkit',
    ssmdocs: 'playbooks/NEWPLAYBOOK/ssmdocs',
    remediations: [
      { control: 'RDS.16', versionAdded: '2.1.0' }, // rollback-enabled -> params forwarded
      { control: 'Config.1', versionAdded: '2.1.1' }, // not rollback-enabled -> no rollback params
    ],
    securityStandard: 'SC',
    securityStandardLongName: 'security-control',
    securityStandardVersion: '2.0.0',
    commonScripts: 'playbooks/common',
  });
}

// Every control the real member stack deploys, so the undeclared-parameter guard below sees the same
// document set SSM would validate at deploy time.
function getAllControlsMemberStack(): Stack {
  const app = new App();
  return new SecurityControlsPlaybookMemberStack(app, 'allControlsMemberStack', {
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    description: 'test;',
    solutionId: 'SO0111',
    resourceNamePrefix: 'SO0111',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'sharrbukkit',
    ssmdocs: 'playbooks/SC/ssmdocs',
    remediations: SC_REMEDIATIONS,
    securityStandard: 'SC',
    securityStandardLongName: 'security-control',
    securityStandardVersion: '2.0.0',
    commonScripts: 'playbooks/common',
  });
}

test('rollback params are gated on isRollbackEnabled per control', () => {
  const template = Template.fromStack(getGatingMemberStack());
  const docs = template.findResources('AWS::SSM::Document');
  const contentOf = (controlId: string): any => {
    const doc = Object.values(docs).find((r) => (r.Properties?.Name as string | undefined)?.endsWith(`_${controlId}`));
    if (!doc) throw new Error(`Control runbook for ${controlId} not found`);
    return doc.Properties.Content;
  };
  const remediationParams = (content: any): Record<string, unknown> =>
    content.mainSteps.find((s: any) => s.name === 'Remediation').inputs.RuntimeParameters;

  // Rollback-enabled control: rollback inputs are declared AND forwarded to the remediation step.
  const enabled = contentOf('RDS.16');
  expect(enabled.parameters).toHaveProperty('Rollback');
  expect(enabled.parameters).toHaveProperty('SnapshotVersionId');
  expect(enabled.parameters).toHaveProperty('ExecutionId');
  expect(enabled.parameters).toHaveProperty('RemediationConfigBucket');
  // ControlExecutionId is forwarded (automation:EXECUTION_ID) but is not a declared control-runbook input.
  expect(enabled.parameters).not.toHaveProperty('ControlExecutionId');
  const enabledForwarded = remediationParams(enabled);
  expect(enabledForwarded).toHaveProperty('Rollback');
  expect(enabledForwarded).toHaveProperty('ExecutionId');
  expect(enabledForwarded).toHaveProperty('RemediationConfigBucket');
  expect(enabledForwarded).toHaveProperty('ControlExecutionId');
  expect(enabledForwarded).toHaveProperty('SnapshotVersionId');

  // Non-rollback control: no rollback inputs declared and none forwarded.
  const nonRollback = contentOf('Config.1');
  expect(nonRollback.parameters).not.toHaveProperty('Rollback');
  expect(nonRollback.parameters).not.toHaveProperty('SnapshotVersionId');
  expect(nonRollback.parameters).not.toHaveProperty('ExecutionId');
  expect(nonRollback.parameters).not.toHaveProperty('RemediationConfigBucket');
  const nonRollbackForwarded = remediationParams(nonRollback);
  expect(nonRollbackForwarded).not.toHaveProperty('Rollback');
  expect(nonRollbackForwarded).not.toHaveProperty('ExecutionId');
  expect(nonRollbackForwarded).not.toHaveProperty('RemediationConfigBucket');
  expect(nonRollbackForwarded).not.toHaveProperty('ControlExecutionId');
  expect(nonRollbackForwarded).not.toHaveProperty('SnapshotVersionId');

  // CheckRollback reads {{Rollback}}, so it exists only where the parameter is declared. Without this,
  // SSM rejects the document at deploy time with 'Parameter "Rollback" is not declared'.
  const stepNames = (content: { mainSteps: { name: string }[] }): string[] => content.mainSteps.map((s) => s.name);
  expect(stepNames(enabled)).toContain('CheckRollback');
  expect(stepNames(nonRollback)).not.toContain('CheckRollback');
});

test('no control runbook references an undeclared Rollback parameter', () => {
  // Built from SC_REMEDIATIONS, the same list the real member stack uses, so this covers every control
  // rather than the two sampled above. SSM validates parameter references at document creation, so one
  // offender fails the whole member stack update — that is how CloudFront.1, AutoScaling.1 and IAM.3
  // broke when CheckRollback was added unconditionally while the Rollback declaration stayed gated.
  const template = Template.fromStack(getAllControlsMemberStack());
  const docs = template.findResources('AWS::SSM::Document');
  expect(Object.keys(docs).length).toBeGreaterThan(50); // guard against silently testing an empty set
  const offenders: string[] = [];

  for (const doc of Object.values(docs)) {
    const content = doc.Properties?.Content as { parameters?: Record<string, unknown> } | undefined;
    if (!content) continue;
    const referencesRollback = /\{\{\s*Rollback\s*\}\}/.test(JSON.stringify(content));
    const declaresRollback = Object.prototype.hasOwnProperty.call(content.parameters ?? {}, 'Rollback');
    if (referencesRollback && !declaresRollback) {
      offenders.push(typeof doc.Properties?.Name === 'string' ? doc.Properties.Name : 'unknown');
    }
  }

  expect(offenders).toEqual([]);
});
