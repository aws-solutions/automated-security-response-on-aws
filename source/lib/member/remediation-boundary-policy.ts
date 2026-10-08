// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { CfnManagedPolicy, Effect, ManagedPolicy, PolicyDocument, PolicyStatement } from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';
import { FORBIDDEN_IAM_ACTION_NAMESPACES } from '@asr/data-models';
import { addCfnGuardSuppression } from '../cdk-helper/add-cfn-guard-suppression';
import { stripDevelopmentPrefix } from '../config/cdk-config';

// Derived from the request-time validator's namespace list, but the two are NOT the same
// set: that list says what a caller may REQUEST, this says what the role may ever DO. `iam`
// is excluded here because it needs the narrower conditional Deny below. Adding a namespace
// to the validator therefore changes every deployed remediation role's ceiling as well.
const WHOLESALE_DENY_ACTIONS = [...FORBIDDEN_IAM_ACTION_NAMESPACES]
  .filter((namespace) => namespace !== 'iam')
  .map((namespace) => `${namespace}:*`);
const PASS_ROLE_TARGET_SERVICE = 'ssm.amazonaws.com';

export interface RemediationBoundaryPolicyProps {
  readonly solutionId: string;
  /**
   * Overrides the managed-policy name. Defaults to `${prefix}-ASR-Remediation-Boundary`,
   * the fixed name the member-account consumers (CrossAccountRoleService) reconstruct by
   * convention. The admin-account copy created for MCP recorded-testing passes a DISTINCT
   * name so it cannot collide with the member-roles-stack boundary when the member-roles
   * template is also deployed into the admin account (managed-policy names are unique per
   * account); that copy is consumed by ARN, not by the fixed name, so a different name is
   * safe.
   */
  readonly managedPolicyName?: string;
}

export class RemediationBoundaryPolicy extends Construct {
  public readonly managedPolicy: ManagedPolicy;

  constructor(scope: Construct, id: string, props: RemediationBoundaryPolicyProps) {
    super(scope, id);

    // Strip DEV- so a dev build names the boundary exactly as a production one does. The
    // consumers attach it by a reconstructed ARN built from a hardcoded SO0111 prefix
    // (CrossAccountRoleService), so a DEV-SO0111-prefixed policy would never be found and no
    // custom-runbook role could be created at all. Matches every other resource name in the
    // solution, which strips the prefix the same way.
    const resourcePrefix = stripDevelopmentPrefix(props.solutionId);
    const boundaryPolicyName = props.managedPolicyName ?? `${resourcePrefix}-ASR-Remediation-Boundary`;

    this.managedPolicy = new ManagedPolicy(this, 'Policy', {
      managedPolicyName: boundaryPolicyName,
      description:
        'Permissions boundary for ASR custom-runbook remediation roles. Caps their effective ' +
        'permissions: allows service actions in general, denies the sts and organizations ' +
        'namespaces wholesale, and denies iam except passing a role to SSM Automation (so the ' +
        "role's own scoped PassRole survives), capping the escalation primitives available to a " +
        'custom remediation role.',
      document: new PolicyDocument({
        statements: [
          new PolicyStatement({
            sid: 'AllowServiceActions',
            effect: Effect.ALLOW,
            actions: ['*'], // NOSONAR
            resources: ['*'], // NOSONAR
          }),
          new PolicyStatement({
            sid: 'DenyEscalationNamespaces',
            effect: Effect.DENY,
            actions: WHOLESALE_DENY_ACTIONS,
            resources: ['*'],
          }),
          new PolicyStatement({
            sid: 'DenyIamExceptPassRoleToSsm',
            effect: Effect.DENY,
            actions: ['iam:*'],
            resources: ['*'],
            conditions: { StringNotEquals: { 'iam:PassedToService': PASS_ROLE_TARGET_SERVICE } },
          }),
        ],
      }),
    });

    addCfnGuardSuppression(this.managedPolicy, 'IAM_POLICYDOCUMENT_NO_WILDCARD_RESOURCE');
    addCfnGuardSuppression(this.managedPolicy, 'IAM_MANAGEDPOLICY_NO_STATEMENTS_WITH_FULL_ACCESS');
    addCfnGuardSuppression(this.managedPolicy, 'CFN_NO_EXPLICIT_RESOURCE_NAMES');

    const policyResource = this.managedPolicy.node.findChild('Resource') as CfnManagedPolicy;
    // Spread the existing metadata: addCfnGuardSuppression above writes guard.SuppressedRules onto
    // this same L1 resource, so a bare assignment would silently drop all three suppressions.
    policyResource.cfnOptions.metadata = {
      ...policyResource.cfnOptions.metadata,
      cfn_nag: {
        rules_to_suppress: [
          {
            id: 'F5',
            reason:
              'A permissions boundary grants nothing: it caps what an identity policy can grant. ' +
              'Action: * here is a ceiling, not a privilege, and the Deny statements are what constrain the role.',
          },
          {
            id: 'W12',
            reason:
              'A boundary that caps any remediation role cannot enumerate resources; the Deny statements bound it.',
          },
          {
            id: 'W28',
            reason: 'Static name chosen intentionally: the consumers attach this boundary by a fixed ARN.',
          },
        ],
      },
    };
  }
}
