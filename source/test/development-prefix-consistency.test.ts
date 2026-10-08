// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Guards the pre-prod (`build-s3-dist.sh -t`) build, where SOLUTION_ID is DEV-SO0111.
//
// Physical names, SSM parameter paths and IAM resource ARNs must resolve to the stripped
// SO0111 form, because many readers are literals in Python and YAML that always spell the
// production id. A handful of names intentionally keep the raw build id; those are listed
// in SELF_CONSISTENT_RAW_RESOURCE_NAMES and are asserted to have no stripped counterpart.
import { App, DefaultStackSynthesizer } from 'aws-cdk-lib';
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import { AdministratorStack } from '../lib/administrator-stack';
import { MemberStack } from '../lib/member-stack';
import { MemberRolesStack } from '../lib/member-roles-stack';
import { RemediationRunbookStack } from '../lib/remediation-runbook-stack';
import { SecurityControlsPlaybookMemberStack } from '../playbooks/SC/lib/security_controls_playbook-construct';
import { SC_REMEDIATIONS } from '../playbooks/SC/lib/sc_remediations';
import { stripDevelopmentPrefix } from '../lib/config/cdk-config';
import { buildOrchestratorLogGroupName, buildStatusTopicName } from '../lib/cdk-helper/solution-resource-names';

const DEVELOPMENT_SOLUTION_ID = 'DEV-SO0111';
const RESOURCE_NAME_PREFIX = stripDevelopmentPrefix(DEVELOPMENT_SOLUTION_ID);

// Names deliberately built from the raw build id. Each is produced and consumed by the same
// component, so no reader spells the stripped form. Adding an entry here is a design decision.
// Every entry must be reachable in the stacks synthesized below, otherwise it asserts nothing;
// the API Lambda name is equally self-consistent but lives in the WebUI nested stack, which is
// outside this suite's scope.
const SELF_CONSISTENT_RAW_RESOURCE_NAMES = [
  `${DEVELOPMENT_SOLUTION_ID}-ASR-PreProcessor`,
  `${DEVELOPMENT_SOLUTION_ID}_automated-security-response-on-aws_AutoTrigger`,
];

// Keyed by the suffix after the prefix, so an entry asserts that this identifier appears ONLY in
// its raw form. If a consumer starts spelling the stripped form, the suffix carries both and the
// agreement assertion fails, which is what stops the allowlist from hiding a real mismatch.
const SELF_CONSISTENT_RAW_SUFFIXES = new Set(
  SELF_CONSISTENT_RAW_RESOURCE_NAMES.map((name) => name.slice(`${DEVELOPMENT_SOLUTION_ID}`.length).toLowerCase()),
);

// The raw id legitimately appears as a bare value: the Solutions:SolutionID tag and the
// SOLUTION_ID Lambda environment variable both report build identity, not a resource name.
const BARE_SOLUTION_ID_PATTERN = new RegExp(`^(?:DEV-)?${RESOURCE_NAME_PREFIX}$`);

function synthesizeTemplates(): Record<string, unknown>[] {
  const app = new App();

  const administratorStack = new AdministratorStack(app, 'SolutionDeployStack', {
    analyticsReporting: false,
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    description: 'test',
    solutionId: DEVELOPMENT_SOLUTION_ID,
    solutionVersion: 'v0.0.0',
    solutionDistBucket: 'test-bucket',
    solutionTMN: 'automated-security-response-on-aws',
    solutionName: 'Automated Security Response on AWS',
    runtimePython: Runtime.PYTHON_3_11,
    orchestratorLogGroup: buildOrchestratorLogGroupName(RESOURCE_NAME_PREFIX),
    SNSTopicName: buildStatusTopicName(RESOURCE_NAME_PREFIX),
    cloudTrailLogGroupName: '/aws/lambda/SO0111-ASR-CloudTrailEvents',
  });

  const memberStack = new MemberStack(app, 'MemberStack', {
    analyticsReporting: false,
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    description: 'test',
    solutionId: DEVELOPMENT_SOLUTION_ID,
    resourceNamePrefix: RESOURCE_NAME_PREFIX,
    solutionTradeMarkName: 'automated-security-response-on-aws',
    solutionDistBucket: 'test-bucket',
    solutionVersion: 'v0.0.0',
    runtimePython: Runtime.PYTHON_3_11,
    SNSTopicName: buildStatusTopicName(RESOURCE_NAME_PREFIX),
    cloudTrailLogGroupName: '/aws/lambda/SO0111-ASR-CloudTrailEvents',
  });

  // Control runbook documents embed role, instance profile, topic and bucket names in their
  // content, so a playbook member stack is the only place those mismatches are observable.
  const securityControlsMemberStack = new SecurityControlsPlaybookMemberStack(app, 'SCMemberStack', {
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    description: 'test',
    solutionId: DEVELOPMENT_SOLUTION_ID,
    resourceNamePrefix: RESOURCE_NAME_PREFIX,
    solutionVersion: 'v0.0.0',
    solutionDistBucket: 'test-bucket',
    // Driven from the real control set, not a hand-maintained subset, so a runbook added later
    // that embeds a DEV- prefixed name cannot escape this check.
    remediations: SC_REMEDIATIONS,
    securityStandard: 'SC',
    securityStandardLongName: 'security-control',
    securityStandardVersion: '2.0.0',
  });

  // Control runbooks reference remediation roles and instance profiles by name, and those
  // resources are created here, so synthesis covers both the producer and the consumer.
  const rolesStack = new MemberRolesStack(app, 'MemberRolesStack', {
    analyticsReporting: false,
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    description: 'test',
    solutionId: DEVELOPMENT_SOLUTION_ID,
    solutionVersion: 'v0.0.0',
    solutionDistBucket: 'test-bucket',
  });

  const runbookStack = new RemediationRunbookStack(app, 'RunbookStack', {
    analyticsReporting: false,
    synthesizer: new DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
    description: 'test',
    solutionId: DEVELOPMENT_SOLUTION_ID,
    solutionVersion: 'v0.0.0',
    solutionDistBucket: 'test-bucket',
    roleStack: rolesStack,
    ssmdocs: 'remediation_runbooks',
    parameters: { Namespace: rolesStack.getNamespace() },
  });

  const assembly = app.synth();
  return [administratorStack, memberStack, securityControlsMemberStack, rolesStack, runbookStack].map(
    (stack) => assembly.getStackByName(stack.stackName).template as Record<string, unknown>,
  );
}

/**
 * Collects every identifier that begins with the solution id, in either prefix form, and
 * returns it keyed by the suffix that follows the prefix.
 *
 * The map is built across ALL stacks, never per stack: a writer and its reader routinely live
 * in different templates (a remediation role is created in the roles stack and referenced from
 * a control runbook document in a playbook stack), so a per-stack map cannot see a disagreement.
 *
 * Matching is case-insensitive because some names are lowercased for services with
 * lowercase-only naming rules (S3 buckets), which would otherwise hide a mismatch.
 */
interface TemplateResource {
  Type: string;
  Properties?: Record<string, unknown>;
}

/** Reads a synthesized template's Resources map, narrowing it once instead of at each use site. */
function getResources(template: Record<string, unknown>): TemplateResource[] {
  const resources = template.Resources;
  if (typeof resources !== 'object' || resources === null) return [];
  return Object.values(resources).filter(
    (resource): resource is TemplateResource =>
      typeof resource === 'object' && resource !== null && typeof (resource as TemplateResource).Type === 'string',
  );
}

function collectIdentifiersBySuffix(templates: Record<string, unknown>[]): Map<string, Set<string>> {
  const pattern = new RegExp(`(DEV-)?${RESOURCE_NAME_PREFIX}([A-Za-z0-9._/:*-]*)`, 'gi');
  const bySuffix = new Map<string, Set<string>>();

  for (const template of templates) {
    for (const match of JSON.stringify(template).matchAll(pattern)) {
      const [identifier, devPrefix, suffix] = match;
      if (BARE_SOLUTION_ID_PATTERN.test(identifier)) continue;

      const key = suffix.toLowerCase();
      const forms = bySuffix.get(key) ?? new Set<string>();
      forms.add(devPrefix ? 'development' : 'stripped');
      bySuffix.set(key, forms);
    }
  }

  return bySuffix;
}

describe('pre-prod DEV- build', function () {
  const templates = synthesizeTemplates();

  it('resolves every shared identifier to its single expected prefix form', function () {
    // ACT
    // An allowlisted suffix must appear only raw; everything else must appear only stripped.
    const violations = [...collectIdentifiersBySuffix(templates)]
      .filter(([suffix, forms]) => {
        const expected = SELF_CONSISTENT_RAW_SUFFIXES.has(suffix) ? 'development' : 'stripped';
        return forms.size > 1 || !forms.has(expected);
      })
      .map(([suffix, forms]) => `${suffix} -> ${[...forms].sort().join('+')}`);

    // ASSERT
    expect(violations).toEqual([]);
  });

  it('keeps the DEV- prefix out of SSM parameter names and their IAM scopes', function () {
    // ACT
    const offenders = templates.flatMap((template) => {
      const resources = getResources(template);
      const parameterNames = resources
        .filter((resource) => resource.Type === 'AWS::SSM::Parameter')
        .map((resource) => resource.Properties?.Name)
        .filter((name): name is string => typeof name === 'string');

      const policyArns = resources
        .filter((resource) => resource.Type === 'AWS::IAM::Policy' || resource.Type === 'AWS::IAM::Role')
        .flatMap((resource) => JSON.stringify(resource.Properties ?? {}).match(/parameter\/Solutions\/[^"']+/g) ?? []);

      return [...parameterNames, ...policyArns].filter((value) => value.includes(`/${DEVELOPMENT_SOLUTION_ID}/`));
    });

    // ASSERT
    expect(offenders).toEqual([]);
  });

  it('never embeds a DEV- prefixed resource name in SSM document content', function () {
    // Every resource an automation document names by string is created by CloudFormation under
    // the stripped prefix, so a DEV- form inside document content is always a dangling
    // reference. This is the only check that catches a concrete name whose IAM counterpart is
    // a wildcard (the CloudTrail.7 access-logging bucket against `s3:::so0111-*`), and it is
    // case-insensitive because that bucket name is lowercased for S3 naming rules.
    // ARRANGE
    const developmentPrefixedName = new RegExp(`DEV-${RESOURCE_NAME_PREFIX}[A-Za-z0-9._/:*-]*`, 'gi');

    // ACT
    const offenders = templates.flatMap((template) => {
      return getResources(template)
        .filter((resource) => resource.Type === 'AWS::SSM::Document')
        .flatMap((resource) => JSON.stringify(resource.Properties ?? {}).match(developmentPrefixedName) ?? [])
        .filter((name) => !BARE_SOLUTION_ID_PATTERN.test(name) && !SELF_CONSISTENT_RAW_RESOURCE_NAMES.includes(name));
    });

    // ASSERT
    expect([...new Set(offenders)]).toEqual([]);
  });

  it('names the status topic and its publish grant identically', function () {
    // ARRANGE
    const administratorTemplate = templates[0];
    // ACT
    const statusTopicNames = getResources(administratorTemplate)
      .filter((resource) => resource.Type === 'AWS::SNS::Topic')
      .map((resource) => resource.Properties?.TopicName)
      .filter((name): name is string => typeof name === 'string' && name.endsWith('-ASR_Topic'));

    const publishScopes = JSON.stringify(administratorTemplate).match(/[A-Za-z0-9-]*-ASR_Topic/g) ?? [];

    // ASSERT
    expect(statusTopicNames).toEqual([buildStatusTopicName(RESOURCE_NAME_PREFIX)]);
    expect([...new Set(publishScopes)]).toEqual([buildStatusTopicName(RESOURCE_NAME_PREFIX)]);
  });
});
