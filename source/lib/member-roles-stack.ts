// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as cdk from 'aws-cdk-lib';
import { InspectorAutomationRole } from './inspector-automation-role';
import { OrchestratorMemberRole } from './orchestrator_roles-construct';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { RemediationBoundaryPolicy } from './member/remediation-boundary-policy';
import { CustomRunbookRoleCleanup } from './member/custom-runbook-role-cleanup';
import AdminAccountParam from './parameters/admin-account-param';
import NamespaceParam from './parameters/namespace-param';
import { stripDevelopmentPrefix } from './config/cdk-config';

export interface MemberRolesStackProps extends cdk.StackProps {
  readonly solutionId: string;
  readonly solutionVersion: string;
  readonly solutionDistBucket: string;
  readonly solutionTradeMarkName: string;
  readonly runtimePython: lambda.Runtime;
}

export class MemberRolesStack extends cdk.Stack {
  private readonly orchestratorMemberRole: OrchestratorMemberRole;
  private readonly namespace: NamespaceParam;

  constructor(scope: cdk.App, id: string, props: MemberRolesStackProps) {
    super(scope, id, props);
    /********************
     ** Parameters
     ********************/
    const RESOURCE_PREFIX = stripDevelopmentPrefix(props.solutionId); // prefix on every resource name
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

    const remediationBoundaryPolicy = new RemediationBoundaryPolicy(this, 'RemediationBoundaryPolicy', {
      solutionId: props.solutionId,
    });

    // ASR creates the Custom Runbook remediation roles at runtime with this boundary, so they must be
    // deleted before the boundary policy can be. Name prefix matches CrossAccountRoleService.
    new CustomRunbookRoleCleanup(this, 'CustomRunbookRoleCleanup', {
      solutionTradeMarkName: props.solutionTradeMarkName,
      solutionVersion: props.solutionVersion,
      solutionDistBucket: props.solutionDistBucket,
      runtimePython: props.runtimePython,
      roleNamePrefix: `${RESOURCE_PREFIX}-Remediate-Custom-`,
      remediationBoundaryPolicy: remediationBoundaryPolicy.managedPolicy,
    });
  }
  getOrchestratorMemberRole(): OrchestratorMemberRole {
    return this.orchestratorMemberRole;
  }

  getNamespace(): string {
    return this.namespace.value;
  }
}
