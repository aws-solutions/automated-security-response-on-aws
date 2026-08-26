// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as cdk from 'aws-cdk-lib';
import { InspectorAutomationRole } from './inspector-automation-role';
import { OrchestratorMemberRole } from './orchestrator_roles-construct';
import AdminAccountParam from './parameters/admin-account-param';
import NamespaceParam from './parameters/namespace-param';

export interface MemberRolesStackProps extends cdk.StackProps {
  readonly solutionId: string;
  readonly solutionVersion: string;
  readonly solutionDistBucket: string;
}

export class MemberRolesStack extends cdk.Stack {
  private readonly orchestratorMemberRole: OrchestratorMemberRole;
  private readonly namespace: NamespaceParam;

  constructor(scope: cdk.App, id: string, props: MemberRolesStackProps) {
    super(scope, id, props);
    /********************
     ** Parameters
     ********************/
    const RESOURCE_PREFIX = props.solutionId.replace(/^DEV-/, ''); // prefix on every resource name
    const adminRoleName = `${RESOURCE_PREFIX}-ASR-Orchestrator-Admin`;
    const adminAccount = new AdminAccountParam(this, 'AdminAccountParameter');
    this.namespace = new NamespaceParam(this, 'Namespace');
    this.orchestratorMemberRole = new OrchestratorMemberRole(this, 'OrchestratorMemberRole', {
      solutionId: props.solutionId,
      adminAccountId: adminAccount.value,
      adminRoleName: adminRoleName,
    });

    // Dedicated, Inspector-scoped AutomationAssumeRole. Confines the
    // ssm:GetCommandInvocation wildcard needed by the Inspector runbook's native
    // waiter to a single-purpose role instead of the shared Orchestrator-Member
    // role. resolve_ssm_doc_for_finding.py resolves Inspector findings to this
    // role name; all other multi-service controls stay on Orchestrator-Member.
    new InspectorAutomationRole(this, 'InspectorAutomationRole', {
      solutionId: props.solutionId,
      adminAccountId: adminAccount.value,
      adminRoleName: adminRoleName,
      namespace: this.namespace.value,
    });
  }
  getOrchestratorMemberRole(): OrchestratorMemberRole {
    return this.orchestratorMemberRole;
  }

  getNamespace(): string {
    return this.namespace.value;
  }
}
