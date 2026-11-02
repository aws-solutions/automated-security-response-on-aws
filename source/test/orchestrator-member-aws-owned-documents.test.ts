// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
import * as path from 'path';
import { App, DefaultStackSynthesizer, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { z } from 'zod';
import { SECURITY_CONTROL_STANDARD_VERSION } from '@asr/data-models';
import { PlaybookMemberStack } from '../lib/playbook-construct';
import { MemberRolesStack } from '../lib/member-roles-stack';
import { splitMemberStack, SplitStackProps } from '../playbooks/split_member_stacks';
import { SecurityControlsPlaybookMemberStack } from '../playbooks/SC/lib/security_controls_playbook-construct';
import { SC_REMEDIATIONS } from '../playbooks/SC/lib/sc_remediations';
import { AFSBP_REMEDIATIONS } from '../playbooks/AFSBP/lib/afsbp_remediations';
import { CIS120_REMEDIATIONS } from '../playbooks/CIS120/lib/cis120_remediations';
import { CIS140PlaybookMemberStack } from '../playbooks/CIS140/lib/cis140_playbook-construct';
import { CIS140_REMEDIATIONS } from '../playbooks/CIS140/lib/cis140_remediations';
import { CIS300PlaybookMemberStack } from '../playbooks/CIS300/lib/cis300_playbook-construct';
import { CIS300_remediations } from '../playbooks/CIS300/lib/cis300_remediations';
import { NIST80053PlaybookMemberStack } from '../playbooks/NIST80053/lib/NIST80053_playbook-construct';
import { NIST80053_REMEDIATIONS } from '../playbooks/NIST80053/lib/nist80053_remediations';
import { PCI321_REMEDIATIONS } from '../playbooks/PCI321/lib/pci321_remediations';

/** splitMemberStack's arguments, minus the ones the test supplies, plus the folder to synthesize from. */
interface PlaybookDefinition extends Omit<SplitStackProps, 'scope' | 'stackLimit'> {
  /** Playbook folder under playbooks/; its build reads ./ssmdocs relative to this folder. */
  readonly directory: string;
}

const PLAYBOOKS: PlaybookDefinition[] = [
  {
    stackClass: SecurityControlsPlaybookMemberStack,
    remediations: SC_REMEDIATIONS,
    directory: 'SC',
    baseStackName: 'SCMemberStack',
    standardShortName: 'SC',
    standardVersion: SECURITY_CONTROL_STANDARD_VERSION,
    standardLongName: 'security-control',
  },
  {
    stackClass: PlaybookMemberStack,
    remediations: AFSBP_REMEDIATIONS,
    directory: 'AFSBP',
    baseStackName: 'AFSBPMemberStack',
    standardShortName: 'AFSBP',
    standardVersion: '1.0.0',
    standardLongName: 'aws-foundational-security-best-practices',
  },
  {
    stackClass: PlaybookMemberStack,
    remediations: CIS120_REMEDIATIONS,
    directory: 'CIS120',
    baseStackName: 'CIS120MemberStack',
    standardShortName: 'CIS',
    standardVersion: '1.2.0',
    standardLongName: 'cis-aws-foundations-benchmark',
  },
  {
    stackClass: CIS140PlaybookMemberStack,
    remediations: CIS140_REMEDIATIONS,
    directory: 'CIS140',
    baseStackName: 'CIS140MemberStack',
    standardShortName: 'CIS',
    standardVersion: '1.4.0',
    standardLongName: 'cis-aws-foundations-benchmark',
  },
  {
    stackClass: CIS300PlaybookMemberStack,
    remediations: CIS300_remediations,
    directory: 'CIS300',
    baseStackName: 'CIS300MemberStack',
    standardShortName: 'CIS',
    standardVersion: '3.0.0',
    standardLongName: 'cis-aws-foundations-benchmark',
  },
  {
    stackClass: NIST80053PlaybookMemberStack,
    remediations: NIST80053_REMEDIATIONS,
    directory: 'NIST80053',
    baseStackName: 'NIST80053MemberStack',
    standardShortName: 'NIST80053R5',
    standardVersion: '5.0.0',
    standardLongName: 'nist-800-53',
  },
  {
    stackClass: PlaybookMemberStack,
    remediations: PCI321_REMEDIATIONS,
    directory: 'PCI321',
    baseStackName: 'PCI321MemberStack',
    standardShortName: 'PCI',
    standardVersion: '3.2.1',
    standardLongName: 'pci-dss',
  },
];

/** A CloudFormation string value as CDK synthesizes it: a literal, a Ref, or an Fn::Join of those. */
type CfnString = string | { readonly Ref: string } | { readonly 'Fn::Join': readonly [string, readonly CfnString[]] };

const cfnStringSchema: z.ZodType<CfnString> = z.lazy(() =>
  z.union([
    z.string(),
    z.object({ Ref: z.string() }),
    z.object({ 'Fn::Join': z.tuple([z.string(), z.array(cfnStringSchema)]) }),
  ]),
);

const automationStepSchema = z.object({
  action: z.string(),
  inputs: z.object({ DocumentName: cfnStringSchema.optional(), Script: z.string().optional() }).optional(),
});

const documentContentSchema = z.object({ mainSteps: z.array(automationStepSchema) });

const ssmDocumentSchema = z.object({
  Properties: z.object({
    Name: cfnStringSchema,
    Content: z.union([
      z.string().transform((json) => documentContentSchema.parse(JSON.parse(json))),
      documentContentSchema,
    ]),
  }),
});

const policyStatementSchema = z.object({
  Action: z.union([z.string(), z.array(z.string())]),
  Resource: z.union([cfnStringSchema, z.array(cfnStringSchema)]).optional(),
});

const roleSchema = z.object({
  Properties: z.object({
    Policies: z.array(z.object({ PolicyDocument: z.object({ Statement: z.array(policyStatementSchema) }) })),
  }),
});

/** The argument text of a call, from just after its opening parenthesis up to the matching closing one. */
function callArguments(textAfterOpenParenthesis: string): string {
  let depth = 0;
  for (let index = 0; index < textAfterOpenParenthesis.length; index++) {
    const character = textAfterOpenParenthesis[index];
    if (character === '(') depth++;
    if (character === ')') {
      if (depth === 0) return textAfterOpenParenthesis.slice(0, index);
      depth--;
    }
  }
  return textAfterOpenParenthesis;
}

/**
 * Documents a playbook script starts with ssm.start_automation_execution. Scripts run as the
 * playbook's own role, so these need the grant too. A call whose DocumentName isn't a string
 * literal is reported by name so the comparison fails instead of silently missing it.
 */
function documentsStartedByScript(script: string, documentName: string): string[] {
  const calls = script.split('start_automation_execution(').slice(1);
  return calls.map((call) => {
    const literal = /DocumentName\s*=\s*["']([^"']+)["']/.exec(callArguments(call));
    return literal ? literal[1] : `<non-literal DocumentName in ${documentName}>`;
  });
}

/** Flattens the Fn::Join form CDK emits for ARNs so they can be compared as strings. */
function flattenArn(value: CfnString): string {
  if (typeof value === 'string') return value;
  if ('Ref' in value) return `\${${value.Ref}}`;
  return value['Fn::Join'][1].map(flattenArn).join(value['Fn::Join'][0]);
}

function awsOwnedDocumentsStartedByPlaybooks(): Set<string> {
  const documentNames = new Set<string>();
  for (const playbook of PLAYBOOKS) {
    const originalDirectory = process.cwd();
    process.chdir(path.join(__dirname, '..', 'playbooks', playbook.directory));
    let stacks: Stack[];
    try {
      stacks = splitMemberStack({ scope: new App(), stackLimit: Infinity, ...playbook });
    } finally {
      process.chdir(originalDirectory);
    }
    for (const stack of stacks) {
      const documents = Template.fromStack(stack).findResources('AWS::SSM::Document');
      for (const document of Object.values(documents).map((resource) => ssmDocumentSchema.parse(resource))) {
        for (const step of document.Properties.Content.mainSteps) {
          const documentName = step.inputs?.DocumentName;
          if (
            step.action === 'aws:executeAutomation' &&
            typeof documentName === 'string' &&
            documentName.startsWith('AWS')
          ) {
            documentNames.add(documentName);
          }
          const script = step.inputs?.Script;
          if (step.action === 'aws:executeScript' && script !== undefined) {
            documentsStartedByScript(script, flattenArn(document.Properties.Name))
              .filter((name) => !name.startsWith('ASR-'))
              .forEach((name) => documentNames.add(name));
          }
        }
      }
    }
  }
  return documentNames;
}

function orchestratorMemberStartAutomationResources(): string[] {
  const roleStack = new MemberRolesStack(new App(), 'roles', {
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    description: 'test;',
    solutionId: 'SO0111',
    solutionVersion: 'v1.1.1',
    solutionDistBucket: 'sharrbukkit',
  });
  const roles = Template.fromStack(roleStack).findResources('AWS::IAM::Role', {
    Properties: { RoleName: 'SO0111-ASR-Orchestrator-Member' },
  });
  const statements = Object.values(roles)
    .map((resource) => roleSchema.parse(resource))
    .flatMap((role) => role.Properties.Policies.flatMap((policy) => policy.PolicyDocument.Statement));
  return statements
    .filter((statement) => [statement.Action].flat().includes('ssm:StartAutomationExecution'))
    .flatMap((statement) => [statement.Resource ?? []].flat().map(flattenArn));
}

describe('Orchestrator-Member AWS-owned SSM document grant', () => {
  const resources = orchestratorMemberStartAutomationResources();
  const awsOwnedDocumentGrants = resources.filter((resource) => resource.includes(':ssm:*::document/'));

  test('does not grant every AWS-owned document', () => {
    expect(awsOwnedDocumentGrants).not.toContainEqual(expect.stringMatching(/::document\/\*$/));
  });

  test('names exactly the AWS-owned documents the playbooks start, as nested automations or from scripts', () => {
    const grantedDocumentNames = awsOwnedDocumentGrants.map((resource) => resource.split('::document/')[1]).sort();

    expect(grantedDocumentNames).toEqual([...awsOwnedDocumentsStartedByPlaybooks()].sort());
  });
});
